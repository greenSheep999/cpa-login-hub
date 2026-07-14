// Package main — Python venv autoprovisioning.
//
// On first invocation from any plugin capability that needs the worker,
// ensureVenv():
//  1. Checks worker/.setup_done sentinel — if the recorded fingerprint
//     matches the current worker/requirements.txt hash, skip.
//  2. Otherwise, acquires a file lock (worker/.setup.lock) so parallel
//     login flows don't race each other into a half-built venv.
//  3. Runs “python3 -m venv worker/.venv“, then
//     “pip install -r worker/requirements.txt“, then
//     “python -m camoufox fetch“ (Playwright ships Firefox binaries
//     via the camoufox fetch subcommand).
//  4. Writes the sentinel so future calls short-circuit.
//
// The whole thing is deliberately synchronous inside ensureVenv — the
// first login the user triggers is expected to take ~90 seconds while
// pip + camoufox fetch run. Subsequent calls are millisecond-cheap.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

// ensureVenv creates the Python virtualenv on demand.
// bundleDir is the plugin directory containing worker/.
func ensureVenv(bundleDir string) error {
	workerDir := filepath.Join(bundleDir, "worker")
	if _, err := os.Stat(workerDir); err != nil {
		return fmt.Errorf("worker dir missing at %s: %w", workerDir, err)
	}
	reqPath := filepath.Join(workerDir, "requirements.txt")
	reqHash, err := fileHash(reqPath)
	if err != nil {
		return fmt.Errorf("read requirements: %w", err)
	}

	sentinel := filepath.Join(workerDir, ".setup_done")
	if buf, err := os.ReadFile(sentinel); err == nil && string(buf) == reqHash {
		return nil // already set up + requirements unchanged
	}

	// Acquire a coarse file lock via O_CREATE|O_EXCL. If someone else is
	// already installing, block until they finish then re-check the
	// sentinel — no need to duplicate the work.
	lock := filepath.Join(workerDir, ".setup.lock")
	if err := acquireLock(lock); err != nil {
		// Someone else has it — wait for the sentinel to appear.
		if err := waitForSentinel(sentinel, reqHash, 5*time.Minute); err == nil {
			return nil
		}
		return err
	}
	defer os.Remove(lock)

	venvDir := filepath.Join(workerDir, ".venv")
	python := resolveHostPython()
	if python == "" {
		return fmt.Errorf("cpa-login-hub requires python3 on PATH — install it and retry")
	}

	// Fresh venv build. If a stale venv exists (e.g. broken half-install)
	// nuke it so we don't inherit bad state.
	if _, err := os.Stat(venvDir); err == nil {
		_ = os.RemoveAll(venvDir)
	}
	if err := run(python, "-m", "venv", venvDir); err != nil {
		return fmt.Errorf("python venv failed: %w", err)
	}

	pipBin := filepath.Join(venvDir, "bin", "pip")
	if err := run(pipBin, "install", "--upgrade", "pip"); err != nil {
		return fmt.Errorf("pip upgrade failed: %w", err)
	}
	if err := run(pipBin, "install", "-r", reqPath); err != nil {
		return fmt.Errorf("pip install requirements failed: %w", err)
	}

	// camoufox fetch downloads the Firefox binary Playwright will drive.
	// This is the biggest single step (~150MB) so surface progress if
	// available — but the CLIProxyAPI plugin logger isn't wired here so
	// we just run silently. The user sees an ``info`` progress event
	// only when the first login actually starts.
	venvPython := filepath.Join(venvDir, "bin", "python")
	if err := run(venvPython, "-m", "camoufox", "fetch"); err != nil {
		return fmt.Errorf("camoufox fetch failed: %w", err)
	}

	if err := os.WriteFile(sentinel, []byte(reqHash), 0o600); err != nil {
		return fmt.Errorf("write sentinel: %w", err)
	}
	return nil
}

// resolveHostPython returns the first usable Python 3 interpreter it can
// find on PATH. The venv module needs a system Python (venvs can't
// bootstrap venvs) so this must be a real interpreter, not our own venv.
func resolveHostPython() string {
	for _, candidate := range []string{"python3", "python3.13", "python3.12", "python3.11", "python"} {
		if p, err := exec.LookPath(candidate); err == nil {
			return p
		}
	}
	return ""
}

// run invokes an external command, folding stderr into stdout and
// returning an error containing the last chunk of output if it fails.
func run(name string, args ...string) error {
	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w — output: %s", name, args, err, truncate(string(out), 800))
	}
	return nil
}

// acquireLock tries to create the lock file exclusively. Returns nil on
// success. On any other error the caller should assume a peer is running
// the install and fall back to sentinel polling.
func acquireLock(path string) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	_ = f.Close()
	return nil
}

// waitForSentinel polls up to timeout for the sentinel file to appear with
// matching hash. Used when we lose the acquireLock race.
func waitForSentinel(sentinel, expected string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if buf, err := os.ReadFile(sentinel); err == nil && string(buf) == expected {
			return nil
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("timed out waiting for peer venv install")
}

// fileHash returns a hex sha256 of the file contents.
func fileHash(path string) (string, error) {
	buf, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(buf)
	return hex.EncodeToString(sum[:]), nil
}
