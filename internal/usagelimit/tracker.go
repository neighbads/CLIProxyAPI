// Package usagelimit accounts the tokens each client API key consumes so per-key allowances
// can be enforced. Only keys published through SetTrackedKeys are accounted, so a deployment
// without usage limits keeps no state. Counters are kept per local calendar day and month,
// indexed by API key fingerprint, and persisted so a restart does not reset a key's
// consumption.
package usagelimit

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
	log "github.com/sirupsen/logrus"
)

const (
	stateFileName = "api-key-usage.json"
	stateVersion  = 1
	flushInterval = 10 * time.Second
)

// windowUsage holds one client key's counters together with the windows they belong to.
// Storing the window identifiers instead of a reset timestamp keeps the rollover derivable
// from the file alone, so a counter loaded after a restart still expires on schedule.
type windowUsage struct {
	Day         string `json:"day"`
	DayTokens   int64  `json:"day_tokens"`
	Month       string `json:"month"`
	MonthTokens int64  `json:"month_tokens"`
}

type stateFile struct {
	Version int                    `json:"version"`
	Entries map[string]windowUsage `json:"entries"`
}

// Tracker accumulates per-client-key token usage in local calendar windows.
type Tracker struct {
	// path is the persistence target. An empty path keeps the counters in memory only.
	path string

	mu      sync.Mutex
	entries map[string]*windowUsage
	tracked map[string]struct{}
	dirty   bool

	flushOnce sync.Once
}

// SetTrackedKeys publishes the fingerprints of the client keys that carry a usage limit and
// takes ownership of the map. Tokens consumed by any other key are ignored, so accounting
// stays opt-in and the retained state stays bounded by the configured policies. Counters for
// keys that no longer carry a limit are dropped.
func (t *Tracker) SetTrackedKeys(fingerprints map[string]struct{}) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.tracked = fingerprints
	for key := range t.entries {
		if _, ok := fingerprints[key]; !ok {
			delete(t.entries, key)
			t.dirty = true
		}
	}
}

// New creates a tracker backed by path, loading any counters left by a previous run.
func New(path string) *Tracker {
	t := &Tracker{path: path, entries: make(map[string]*windowUsage)}
	t.load()
	return t
}

// Add records tokens consumed by the key identified by fingerprint. Keys that carry no usage
// limit are not tracked, so they cost neither an entry nor a write.
func (t *Tracker) Add(fingerprint string, tokens int64, now time.Time) {
	if t == nil || fingerprint == "" || tokens <= 0 {
		return
	}
	day, month := windowKeys(now)

	t.mu.Lock()
	if _, tracked := t.tracked[fingerprint]; !tracked {
		t.mu.Unlock()
		return
	}
	entry := t.entries[fingerprint]
	if entry == nil {
		entry = &windowUsage{}
		t.entries[fingerprint] = entry
	}
	rollLocked(entry, day, month)
	entry.DayTokens += tokens
	entry.MonthTokens += tokens
	t.dirty = true
	t.mu.Unlock()

	t.startFlusher()
}

// Snapshot returns the tokens the key has consumed in the current day and month windows.
// Counters that belong to an elapsed window read as zero.
func (t *Tracker) Snapshot(fingerprint string, now time.Time) (dayTokens, monthTokens int64) {
	if t == nil || fingerprint == "" {
		return 0, 0
	}
	day, month := windowKeys(now)

	t.mu.Lock()
	defer t.mu.Unlock()
	entry := t.entries[fingerprint]
	if entry == nil {
		return 0, 0
	}
	// Rolling here does not mark the tracker dirty: the persisted window identifiers already
	// imply the reset, so a crash before the next write replays the same rollover.
	rollLocked(entry, day, month)
	return entry.DayTokens, entry.MonthTokens
}

// HandleUsage consumes usage records emitted by the proxy runtime.
func (t *Tracker) HandleUsage(_ context.Context, record coreusage.Record) {
	tokens := recordTokens(record)
	if tokens <= 0 {
		return
	}
	t.Add(misc.APIKeyFingerprint(record.APIKey), tokens, time.Now())
}

// Flush writes the counters to disk when they changed since the last write.
func (t *Tracker) Flush() {
	if t == nil || t.path == "" {
		return
	}
	t.mu.Lock()
	if !t.dirty {
		t.mu.Unlock()
		return
	}
	snapshot := stateFile{Version: stateVersion, Entries: make(map[string]windowUsage, len(t.entries))}
	for key, entry := range t.entries {
		snapshot.Entries[key] = *entry
	}
	t.dirty = false
	t.mu.Unlock()

	if err := writeState(t.path, snapshot); err != nil {
		log.Warnf("usage limit: failed to persist counters to %s: %v", t.path, err)
		t.mu.Lock()
		t.dirty = true
		t.mu.Unlock()
	}
}

// startFlusher launches the periodic writer on first use so a tracker that never records
// anything does not hold a goroutine.
func (t *Tracker) startFlusher() {
	if t.path == "" {
		return
	}
	t.flushOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(flushInterval)
			defer ticker.Stop()
			for range ticker.C {
				t.Flush()
			}
		}()
	})
}

func (t *Tracker) load() {
	if t.path == "" {
		return
	}
	data, err := os.ReadFile(t.path)
	if err != nil {
		return
	}
	var state stateFile
	if errUnmarshal := json.Unmarshal(data, &state); errUnmarshal != nil {
		log.Warnf("usage limit: ignoring unreadable state file %s: %v", t.path, errUnmarshal)
		return
	}
	if state.Version != stateVersion {
		return
	}
	for key, entry := range state.Entries {
		if key == "" {
			continue
		}
		stored := entry
		t.entries[key] = &stored
	}
}

func writeState(path string, snapshot stateFile) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(snapshot)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err = os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

func rollLocked(entry *windowUsage, day, month string) {
	if entry.Day != day {
		entry.Day = day
		entry.DayTokens = 0
	}
	if entry.Month != month {
		entry.Month = month
		entry.MonthTokens = 0
	}
}

func windowKeys(now time.Time) (day, month string) {
	local := now.Local()
	return local.Format("2006-01-02"), local.Format("2006-01")
}

// recordTokens resolves the total tokens a record accounts for. The normalized breakdown is
// authoritative; the legacy total covers records published without one.
func recordTokens(record coreusage.Record) int64 {
	if total := record.Detail.TokenBreakdown.TotalTokens; total > 0 {
		return total
	}
	if record.Detail.TotalTokens > 0 {
		return record.Detail.TotalTokens
	}
	return 0
}

// ResolveStatePath returns the file the counters are persisted to. An empty result keeps the
// counters in memory, which is the behaviour when no writable location can be determined.
func ResolveStatePath() string {
	if writable := util.WritablePath(); writable != "" {
		return filepath.Join(writable, stateFileName)
	}
	if configDir, err := os.UserConfigDir(); err == nil && configDir != "" {
		return filepath.Join(configDir, "cpa", stateFileName)
	}
	if homeDir, err := os.UserHomeDir(); err == nil && homeDir != "" {
		return filepath.Join(homeDir, ".config", "cpa", stateFileName)
	}
	return ""
}

var defaultTracker = New(ResolveStatePath())

// Default returns the process-wide tracker fed by the usage pipeline.
func Default() *Tracker { return defaultTracker }

func init() {
	coreusage.RegisterPlugin(defaultTracker)
}
