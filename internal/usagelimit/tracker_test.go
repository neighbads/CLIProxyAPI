package usagelimit

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/misc"
	coreusage "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/usage"
)

func TestTrackerAccumulatesWithinWindow(t *testing.T) {
	t.Parallel()

	tracker := New("")
	tracker.SetTrackedKeys(map[string]struct{}{"fp": {}})
	now := time.Date(2026, 9, 18, 10, 0, 0, 0, time.Local)

	tracker.Add("fp", 1_000, now)
	tracker.Add("fp", 2_500, now.Add(3*time.Hour))

	day, month := tracker.Snapshot("fp", now.Add(5*time.Hour))
	if day != 3_500 || month != 3_500 {
		t.Fatalf("day = %d, month = %d, want 3500, 3500", day, month)
	}

	// An unknown key is unrestricted and reads as zero.
	if day, month = tracker.Snapshot("other", now); day != 0 || month != 0 {
		t.Fatalf("unknown key = (%d, %d), want (0, 0)", day, month)
	}
}

func TestTrackerIgnoresAndPrunesUntrackedKeys(t *testing.T) {
	t.Parallel()

	tracker := New("")
	now := time.Date(2026, 9, 18, 10, 0, 0, 0, time.Local)

	// A key that carries no usage limit is never accounted, so it costs no state.
	tracker.Add("unlimited", 5_000, now)
	if day, month := tracker.Snapshot("unlimited", now); day != 0 || month != 0 {
		t.Fatalf("untracked key = (%d, %d), want (0, 0)", day, month)
	}

	tracker.SetTrackedKeys(map[string]struct{}{"limited": {}})
	tracker.Add("limited", 3_000, now)
	if day, _ := tracker.Snapshot("limited", now); day != 3_000 {
		t.Fatalf("tracked key day = %d, want 3000", day)
	}

	// Removing the key's limit discards the counter it no longer needs.
	tracker.SetTrackedKeys(map[string]struct{}{})
	if day, _ := tracker.Snapshot("limited", now); day != 0 {
		t.Fatalf("pruned key day = %d, want 0", day)
	}
}

func TestTrackerRollsCalendarWindows(t *testing.T) {
	t.Parallel()

	tracker := New("")
	tracker.SetTrackedKeys(map[string]struct{}{"fp": {}})
	september := time.Date(2026, 9, 18, 23, 0, 0, 0, time.Local)
	tracker.Add("fp", 5_000, september)

	// The next local day resets the daily counter but keeps the month running.
	nextDay := time.Date(2026, 9, 19, 1, 0, 0, 0, time.Local)
	if day, month := tracker.Snapshot("fp", nextDay); day != 0 || month != 5_000 {
		t.Fatalf("next day = (%d, %d), want (0, 5000)", day, month)
	}

	tracker.Add("fp", 700, nextDay)
	if day, month := tracker.Snapshot("fp", nextDay); day != 700 || month != 5_700 {
		t.Fatalf("after next-day add = (%d, %d), want (700, 5700)", day, month)
	}

	// The next local month resets both counters.
	nextMonth := time.Date(2026, 10, 1, 0, 30, 0, 0, time.Local)
	if day, month := tracker.Snapshot("fp", nextMonth); day != 0 || month != 0 {
		t.Fatalf("next month = (%d, %d), want (0, 0)", day, month)
	}
}

func TestTrackerPersistsAcrossRestart(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "api-key-usage.json")
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.Local)

	tracker := New(path)
	tracker.SetTrackedKeys(map[string]struct{}{"fp": {}})
	tracker.Add("fp", 4_200, now)
	tracker.Flush()

	restarted := New(path)
	if day, month := restarted.Snapshot("fp", now); day != 4_200 || month != 4_200 {
		t.Fatalf("restored = (%d, %d), want (4200, 4200)", day, month)
	}

	// A counter restored from an elapsed window still expires on schedule.
	nextMonth := time.Date(2026, 10, 2, 12, 0, 0, 0, time.Local)
	if day, month := restarted.Snapshot("fp", nextMonth); day != 0 || month != 0 {
		t.Fatalf("restored next month = (%d, %d), want (0, 0)", day, month)
	}
}

func TestHandleUsageAccountsRecordTokens(t *testing.T) {
	t.Parallel()

	tracker := New("")
	tracker.SetTrackedKeys(map[string]struct{}{misc.APIKeyFingerprint("sk-a"): {}})
	record := coreusage.Record{APIKey: "sk-a"}
	record.Detail.TotalTokens = 1_200
	tracker.HandleUsage(context.Background(), record)

	breakdown := coreusage.Record{APIKey: "sk-a"}
	breakdown.Detail.TokenBreakdown = coreusage.NewSubsetTokenBreakdown(600, 0, 0, 400, 0, 1_000)
	tracker.HandleUsage(context.Background(), breakdown)

	// A record without tokens must not create an entry.
	tracker.HandleUsage(context.Background(), coreusage.Record{APIKey: "sk-a"})

	day, _ := tracker.Snapshot(misc.APIKeyFingerprint("sk-a"), time.Now())
	if day != 2_200 {
		t.Fatalf("day = %d, want 2200", day)
	}

	// Records without a client key are not attributable and must be dropped.
	anonymous := coreusage.Record{}
	anonymous.Detail.TotalTokens = 900
	tracker.HandleUsage(context.Background(), anonymous)
	if day, _ = tracker.Snapshot("", time.Now()); day != 0 {
		t.Fatalf("anonymous day = %d, want 0", day)
	}
}
