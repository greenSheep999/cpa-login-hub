// Package main — flow state bridging the panel and CPA's auth machinery.
//
// The plugin exposes two capabilities that both need to reason about a
// login attempt in progress:
//
//  1. ManagementAPI capability serves the HTML panel. The panel collects
//     the user's provider choice + credentials + proxy and posts them to
//     /prepare. This is the ONLY place the user's password enters the
//     plugin — CPA's AuthProvider.StartLogin request never carries them.
//
//  2. AuthProvider capability handles CPA-driven StartLogin / PollLogin.
//     StartLogin needs the parameters the panel captured; PollLogin needs
//     to know whether the background worker finished.
//
// flow_registry.go is the bridge. Two data structures:
//
//   - pendingSlot: single-element slot the panel writes, StartLogin reads.
//     Single-element because CPA management runs one admin at a time and
//     StartLogin needs to correlate its call with "the last thing the
//     panel prepared". A queue would race across providers.
//
//   - activeFlows: map[stateToken] → running goroutine's result channel.
//     StartLogin populates it right before returning; PollLogin drains it.
//     TTL cleaner reaps entries the caller never polled (browser closed
//     mid-flow, CPA panel navigated away, etc.).
package main

import (
	"sync"
	"time"
)

// pendingLogin is the payload the panel /submit-login sends: which
// provider the user picked and what they filled in. Passed as a
// value to panelSubmitLogin — not stored anywhere at package scope
// (the CPA-issued state token is the correlator now, not a slot).
type pendingLogin struct {
	Provider string            // "kiro" | "openai" | ...
	Label    string            // free-form user label
	Proxy    string            // proxy URL / "direct" / ""
	Timeout  int               // seconds
	Extras   map[string]string // provider-specific fields
}

// activeFlow tracks the lifecycle of one login attempt from CPA's
// StartLogin call to worker termination. Three phases:
//
//	1. Awaiting=true:   flow exists, waiting for user to submit the panel form
//	2. Awaiting=false, done open:  worker goroutine running
//	3. done closed:                worker terminated (Result / ErrorMessage set)
type activeFlow struct {
	// mu guards Provider + Awaiting (which mutate between phases 1→2);
	// Result / ErrorMessage / StartedAt only get set once via finish()
	// / creation and don't need the mutex.
	mu       sync.Mutex
	Provider string
	Awaiting bool

	StartedAt time.Time
	// done is closed by the worker goroutine once Result / ErrorMessage
	// is populated. PollLogin uses a non-blocking check on this channel.
	done chan struct{}
	// once ensures the worker goroutine calls close(done) at most once.
	once sync.Once

	// Result is populated on success. ErrorMessage on failure. Exactly
	// one of these ends up non-empty.
	Result       *workerResult
	ErrorMessage string
}

// finish records the worker's terminal state and unblocks PollLogin.
// Safe to call at most once per flow.
func (f *activeFlow) finish(result *workerResult, err error) {
	f.once.Do(func() {
		if err != nil {
			f.ErrorMessage = err.Error()
		} else if result != nil {
			f.Result = result
			if result.ErrorMessage != "" {
				f.ErrorMessage = result.ErrorMessage
			}
		}
		close(f.done)
	})
}

// isDone reports whether the worker goroutine finished. Non-blocking.
func (f *activeFlow) isDone() bool {
	select {
	case <-f.done:
		return true
	default:
		return false
	}
}

// --- registry (package-global; the plugin dylib has one process) --------

var (
	registryMu  sync.Mutex
	activeFlows = map[string]*activeFlow{} // stateToken → flow
)

const (
	// awaitingTTL — how long a flow can sit in Awaiting=true (user hasn't
	// submitted the panel form yet). CPA's own OAuth session expiry is
	// also ~15min so we match it.
	awaitingTTL = 15 * time.Minute
	// activeTTL is how long we keep a running/completed flow's result
	// around. CPA's poll cadence is 1-2s so 30 min is plenty.
	activeTTL = 30 * time.Minute
)

// registerActiveFlow inserts a new in-flight flow keyed by stateToken.
// Callers must construct the activeFlow themselves and populate
// StartedAt + Awaiting before calling.
func registerActiveFlow(stateToken string, flow *activeFlow) {
	if stateToken == "" || flow == nil {
		return
	}
	registryMu.Lock()
	activeFlows[stateToken] = flow
	registryMu.Unlock()
}

// lookupActiveFlow returns the flow for stateToken, or nil.
// PollLogin uses this on every poll.
func lookupActiveFlow(stateToken string) *activeFlow {
	registryMu.Lock()
	defer registryMu.Unlock()
	return activeFlows[stateToken]
}

// consumeActiveFlow removes and returns the flow. PollLogin calls this
// only after a successful terminal read so CPA can retry on transient
// errors without losing the result.
func consumeActiveFlow(stateToken string) *activeFlow {
	registryMu.Lock()
	defer registryMu.Unlock()
	flow, ok := activeFlows[stateToken]
	if !ok {
		return nil
	}
	delete(activeFlows, stateToken)
	return flow
}

// startFlowJanitor launches the background reaper that trims expired
// activeFlows entries. Called from init() so it runs for the lifetime
// of the dylib. Runs at low frequency — we're just guarding against
// long-lived abandoned entries, not aiming for precise cleanup timing.
func startFlowJanitor() {
	go func() {
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			reapExpiredFlows()
		}
	}()
}

func reapExpiredFlows() {
	now := time.Now()
	registryMu.Lock()
	defer registryMu.Unlock()
	for token, flow := range activeFlows {
		flow.mu.Lock()
		awaiting := flow.Awaiting
		flow.mu.Unlock()
		age := now.Sub(flow.StartedAt)
		if awaiting && age > awaitingTTL {
			delete(activeFlows, token)
			continue
		}
		if age > activeTTL {
			delete(activeFlows, token)
		}
	}
}

func init() {
	startFlowJanitor()
}
