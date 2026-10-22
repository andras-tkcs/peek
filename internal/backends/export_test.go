package backends

import (
	"testing"
	"time"
)

// Test hooks for manager_test.go, which is an external test package because it
// imports backendstest (which imports this package).

// SetReadinessForTest shortens the readiness probe for one test.
func SetReadinessForTest(t testing.TB, timeout, interval time.Duration) {
	t.Helper()
	oldTimeout, oldInterval := readinessTimeout, readinessInterval
	readinessTimeout, readinessInterval = timeout, interval
	t.Cleanup(func() { readinessTimeout, readinessInterval = oldTimeout, oldInterval })
}

// SetReapIntervalForTest shortens Run's ticker for one test.
func SetReapIntervalForTest(t testing.TB, d time.Duration) {
	t.Helper()
	old := reapInterval
	reapInterval = d
	t.Cleanup(func() { reapInterval = old })
}

// TrackedForTest reports whether the manager has an entry (started or
// starting) for a page version, and its image.
func (m *Manager) TrackedForTest(uploadID int64, version int) (bool, string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[key{uploadID, version}]
	if e == nil {
		return false, ""
	}
	return true, e.image
}
