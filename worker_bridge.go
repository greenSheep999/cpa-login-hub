// Package main — bridge between the Go plugin and the Python worker.
//
// Responsibilities:
//  1. Locate the plugin bundle directory (worker/ + worker/.venv/ live there).
//  2. Spawn the worker as a subprocess in its own process group so the
//     whole tree (Python + Playwright driver + Camoufox + Firefox) can be
//     SIGTERMed as a unit when the host cancels a login.
//  3. Frame the stdin spec + stream stdout events back to the caller.
//
// The stdin/stdout contract mirrors what muxhub's scripts/login-hub/server.py
// already does — the Python entry point “worker.runner“ is a thin wrapper
// around the same “helpers.run_worker.main“ we've been running for months.
package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// workerEvent is one JSON line emitted by the Python worker on stdout.
// kind values: info | step | url | error | done | _result | _error | ...
type workerEvent struct {
	Kind string          `json:"kind"`
	Msg  string          `json:"msg"`
	Data json.RawMessage `json:"data,omitempty"`
}

// workerJob is what we send to the worker on stdin. Mirrors
// muxhub scripts/login-hub/server.py::_run_job's spec dict.
type workerJob struct {
	Provider string         `json:"provider"`
	Label    string         `json:"label"`
	Proxy    string         `json:"proxy,omitempty"`
	OutDir   string         `json:"out_dir"`
	Timeout  int            `json:"timeout"`
	Extras   map[string]any `json:"extras"`
}

// workerResult is the parsed outcome of a completed worker run.
type workerResult struct {
	// FinalResult is the payload of the terminal ``_result`` event.
	// Contains at minimum ``out_path`` + ``identity`` + ``extra``.
	FinalResult json.RawMessage
	// ErrorMessage is set when the worker terminated with ``_error``.
	ErrorMessage string
	// ExitCode is the worker process exit code.
	ExitCode int
	// Events is the ordered list of non-terminal progress events.
	Events []workerEvent
}

// activeWorkers tracks running subprocesses so shutdown() can reap them.
var (
	activeWorkersMu sync.Mutex
	activeWorkers   = map[int]*exec.Cmd{}
)

// runWorker forks the Python worker, streams the spec into stdin, drains
// stdout line by line, and returns the parsed result. Callers should
// treat this as a blocking call.
//
// The subprocess is started in its own session (setsid) so the caller can
// kill the whole process tree via killpg. This is essential — Playwright
// spawns node driver, node driver spawns Firefox, Firefox spawns 5+
// content processes; leaving any of them behind means a phantom browser
// on the user's desktop after cancel.
func runWorker(job workerJob) (*workerResult, error) {
	bundle, err := pluginBundleDir()
	if err != nil {
		return nil, err
	}
	if err := ensureVenv(bundle); err != nil {
		return nil, fmt.Errorf("venv setup: %w", err)
	}

	pythonBin := filepath.Join(bundle, "worker", ".venv", "bin", "python")
	if _, statErr := os.Stat(pythonBin); statErr != nil {
		return nil, fmt.Errorf("worker venv missing python: %w", statErr)
	}

	specBytes, err := json.Marshal(job)
	if err != nil {
		return nil, fmt.Errorf("marshal job: %w", err)
	}

	cmd := exec.Command(pythonBin, "-m", "worker.runner")
	cmd.Dir = bundle
	cmd.Env = append(os.Environ(),
		"PYTHONUNBUFFERED=1",
		// worker.runner adds ``worker/`` to sys.path itself, but we hint
		// PYTHONPATH too so ``python -m worker.runner`` resolves cleanly
		// when the process is launched from an unrelated cwd (unlikely,
		// but harmless).
		"PYTHONPATH="+bundle,
	)
	stdinPipe, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout // fold stderr in so any unexpected traceback surfaces via the event stream

	// Detach into its own process group so cancel can killpg cleanly.
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true

	if err := cmd.Start(); err != nil {
		return nil, err
	}
	activeWorkersMu.Lock()
	activeWorkers[cmd.Process.Pid] = cmd
	activeWorkersMu.Unlock()
	defer func() {
		activeWorkersMu.Lock()
		delete(activeWorkers, cmd.Process.Pid)
		activeWorkersMu.Unlock()
	}()

	// Push the spec + close stdin so the worker knows it has the full
	// job and can exit cleanly after producing its result.
	if _, err := stdinPipe.Write(specBytes); err != nil && !errors.Is(err, io.ErrClosedPipe) {
		return nil, fmt.Errorf("write spec: %w", err)
	}
	_ = stdinPipe.Close()

	result := &workerResult{}
	scanner := bufio.NewScanner(stdoutPipe)
	scanner.Buffer(make([]byte, 64*1024), 4*1024*1024) // allow long log lines from playwright
	for scanner.Scan() {
		line := strings.TrimRight(scanner.Text(), "\r")
		if line == "" {
			continue
		}
		var ev workerEvent
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			// Non-JSON lines are treated as raw log noise (Camoufox spew,
			// etc.). Surface them as info events so troubleshooters have
			// something to grep.
			ev = workerEvent{Kind: "info", Msg: truncate(line, 400)}
		}
		switch ev.Kind {
		case "_result":
			result.FinalResult = ev.Data
		case "_error":
			result.ErrorMessage = ev.Msg
		default:
			result.Events = append(result.Events, ev)
		}
	}
	waitErr := cmd.Wait()
	if waitErr != nil {
		var exitErr *exec.ExitError
		if errors.As(waitErr, &exitErr) {
			result.ExitCode = exitErr.ExitCode()
		} else {
			return nil, waitErr
		}
	}
	if result.FinalResult == nil && result.ErrorMessage == "" {
		result.ErrorMessage = fmt.Sprintf("worker exited rc=%d without delivering a result", result.ExitCode)
	}
	return result, nil
}

// shutdownWorkers signals any lingering worker subprocesses to shut down.
// Called from cliproxyPluginShutdown when CPA unloads the plugin. We
// SIGTERM the whole group, wait briefly, then SIGKILL survivors — same
// pattern muxhub server.py uses for the cancel endpoint.
func shutdownWorkers() {
	activeWorkersMu.Lock()
	pids := make([]*exec.Cmd, 0, len(activeWorkers))
	for _, c := range activeWorkers {
		pids = append(pids, c)
	}
	activeWorkersMu.Unlock()

	for _, cmd := range pids {
		if cmd.Process == nil {
			continue
		}
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err != nil {
			pgid = cmd.Process.Pid
		}
		_ = syscall.Kill(-pgid, syscall.SIGTERM)
	}

	// 5s grace, then kill.
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
		activeWorkersMu.Lock()
		remaining := len(activeWorkers)
		activeWorkersMu.Unlock()
		if remaining == 0 {
			return
		}
	}
	activeWorkersMu.Lock()
	for _, cmd := range activeWorkers {
		if cmd.Process == nil {
			continue
		}
		pgid, err := syscall.Getpgid(cmd.Process.Pid)
		if err != nil {
			pgid = cmd.Process.Pid
		}
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}
	activeWorkersMu.Unlock()
}

// pluginBundleDir returns the directory the plugin .so was loaded from —
// this is where worker/ and worker/.venv/ live. We resolve it via the
// executable path of the *shared library*; Go doesn't expose that
// directly, so we fall back to the process cwd hint CPA passes in
// (typically “plugins-dir/<plugin-id>/“). Environment variables win
// when set — this makes local dev + testing straightforward.
func pluginBundleDir() (string, error) {
	if p := os.Getenv("CPA_LOGIN_HUB_DIR"); p != "" {
		return p, nil
	}
	// Some hosts pass CLIPROXY_PLUGIN_DIR when they load us; honour it.
	if p := os.Getenv("CLIPROXY_PLUGIN_DIR"); p != "" {
		return p, nil
	}
	// Final fallback: process CWD (works when CPA is launched from the
	// plugin's own directory during development).
	return os.Getwd()
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
