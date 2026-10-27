package backends_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/privacyfence/peek/internal/backends"
	"github.com/privacyfence/peek/internal/backends/backendstest"
)

const (
	testInstance = "abcd1234"
	testNetwork  = "peek-test"
	testImage    = "ghcr.io/acme/app:1"
)

// backendPort starts an HTTP server standing in for the container and
// returns its port; the fake runtime reports every container at 127.0.0.1.
func backendPort(t *testing.T) int {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().(*net.TCPAddr).Port
}

type clock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

func newManager(t *testing.T, rt backends.Runtime, limits backends.Limits, now func() time.Time) *backends.Manager {
	t.Helper()
	m := backends.NewManager(backends.Config{
		Runtime:  rt,
		Network:  testNetwork,
		Instance: testInstance,
		Limits:   func(context.Context) backends.Limits { return limits },
		Now:      now,
	})
	if err := m.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = m.Close(context.Background()) })
	return m
}

func spec(uploadID int64, version, port int) backends.Spec {
	return backends.Spec{UploadID: uploadID, Version: version, Image: testImage, Port: port}
}

func ensure(t *testing.T, m *backends.Manager, s backends.Spec) backends.Endpoint {
	t.Helper()
	ep, err := m.Ensure(context.Background(), s)
	if err != nil {
		t.Fatalf("Ensure(u%d v%d): %v", s.UploadID, s.Version, err)
	}
	return ep
}

func snapshot(rt *backendstest.FakeRuntime, field func(*backendstest.FakeRuntime) []string) []string {
	rt.Lock()
	defer rt.Unlock()
	return slices.Clone(field(rt))
}

func stopped(rt *backendstest.FakeRuntime) []string {
	return snapshot(rt, func(f *backendstest.FakeRuntime) []string { return f.Stopped })
}

func createdCount(rt *backendstest.FakeRuntime) int {
	rt.Lock()
	defer rt.Unlock()
	return len(rt.Created)
}

// blockStarts makes the fake's StartContainer report each id on entered and
// wait for release (or the start context) before returning failFor[id].
func blockStarts(rt *backendstest.FakeRuntime, failFor map[string]error) (entered chan string, release chan struct{}) {
	entered, release = make(chan string, 16), make(chan struct{})
	rt.StartHook = func(ctx context.Context, id string) error {
		entered <- id
		select {
		case <-release:
		case <-ctx.Done():
			return ctx.Err()
		}
		return failFor[id]
	}
	return entered, release
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestContainerAndVolumeNames(t *testing.T) {
	if got := backends.ContainerName("abcd1234", 7, 3); got != "peek-abcd1234-u7-v3" {
		t.Errorf("ContainerName = %q", got)
	}
	if got := backends.VolumeName("abcd1234", 7); got != "peek-abcd1234-data-u7" {
		t.Errorf("VolumeName = %q", got)
	}
}

func TestManagerEnsureCreatesContainer(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	m := newManager(t, rt, backends.Limits{}, nil)
	port := backendPort(t)

	s := backends.Spec{
		UploadID: 7, Version: 2, Image: testImage, Port: port,
		Env:         map[string]string{"B": "2", "A": "1", "PORT": "1", "PEEK_X": "y"},
		MemoryBytes: 256 << 20, NanoCPUs: 500_000_000, RegistryAuth: "auth",
	}
	ep := ensure(t, m, s)

	rt.Lock()
	pulled, created, removed := slices.Clone(rt.Pulled), slices.Clone(rt.Created), slices.Clone(rt.Removed)
	rt.Unlock()
	if !slices.Equal(pulled, []string{testImage}) {
		t.Fatalf("Pulled = %v", pulled)
	}
	if len(created) != 1 {
		t.Fatalf("Created = %+v", created)
	}
	c := created[0]
	name := "peek-abcd1234-u7-v2"
	if c.Name != name || c.Image != testImage || c.Network != testNetwork || c.Volume != "peek-abcd1234-data-u7" {
		t.Errorf("spec = %+v", c)
	}
	if c.MemoryBytes != 256<<20 || c.NanoCPUs != 500_000_000 || len(c.Cmd) != 0 {
		t.Errorf("limits/cmd = %d %d %v", c.MemoryBytes, c.NanoCPUs, c.Cmd)
	}
	wantLabels := map[string]string{"peek.managed": "true", "peek.instance": testInstance, "peek.upload_id": "7", "peek.version": "2"}
	if len(c.Labels) != len(wantLabels) {
		t.Errorf("labels = %v", c.Labels)
	}
	for k, v := range wantLabels {
		if c.Labels[k] != v {
			t.Errorf("label %s = %q, want %q", k, c.Labels[k], v)
		}
	}
	if len(c.Env) != 6 {
		t.Fatalf("env = %v", c.Env)
	}
	token := strings.TrimPrefix(c.Env[3], "PEEK_BACKEND_TOKEN=")
	if !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(token) {
		t.Errorf("token = %q", token)
	}
	wantEnv := []string{"A=1", "B=2", "PORT=" + strconv.Itoa(port), "PEEK_BACKEND_TOKEN=" + token, "PEEK_UPLOAD_ID=7", "PEEK_VERSION=2"}
	if !slices.Equal(c.Env, wantEnv) {
		t.Errorf("env = %v, want %v", c.Env, wantEnv)
	}
	if ep.URL != "http://127.0.0.1:"+strconv.Itoa(port) || ep.Token != token {
		t.Errorf("endpoint = %+v", ep)
	}
	if !slices.Contains(removed, name) {
		t.Errorf("stale container %s not removed before create: %v", name, removed)
	}
	if !m.Running(7, 2) || m.Running(7, 1) {
		t.Error("Running mismatch")
	}

	if again := ensure(t, m, s); again != ep {
		t.Errorf("second Ensure = %+v, want %+v", again, ep)
	}
	if n := createdCount(rt); n != 1 {
		t.Errorf("second Ensure created a container: %d", n)
	}

	// The image is now present: another version starts without a pull.
	ensure(t, m, spec(7, 3, port))
	rt.Lock()
	defer rt.Unlock()
	if len(rt.Pulled) != 1 || len(rt.Created) != 2 {
		t.Errorf("Pulled = %v, Created = %d", rt.Pulled, len(rt.Created))
	}
	if rt.Created[0].Env[3] == rt.Created[1].Env[3] {
		t.Error("two starts share a token")
	}
}

func TestManagerEnsureConcurrentSameKey(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	m := newManager(t, rt, backends.Limits{MaxRunning: 5}, nil)
	port := backendPort(t)

	var wg sync.WaitGroup
	endpoints := make([]backends.Endpoint, 20)
	errs := make([]error, 20)
	for i := range endpoints {
		wg.Go(func() {
			endpoints[i], errs[i] = m.Ensure(context.Background(), spec(1, 1, port))
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("Ensure %d: %v", i, err)
		}
		if endpoints[i] != endpoints[0] {
			t.Errorf("endpoint %d = %+v, want %+v", i, endpoints[i], endpoints[0])
		}
	}
	if n := createdCount(rt); n != 1 {
		t.Errorf("created %d containers, want 1", n)
	}
}

func TestManagerEnsureConcurrentKeys(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	m := newManager(t, rt, backends.Limits{MaxRunning: 3}, nil)
	port := backendPort(t)

	var wg sync.WaitGroup
	for i := range 10 {
		wg.Go(func() {
			if _, err := m.Ensure(context.Background(), spec(int64(i%5), 1, port)); err != nil {
				t.Errorf("Ensure: %v", err)
			}
			m.Running(int64(i%5), 1)
			if i%3 == 0 {
				_ = m.StopUpload(context.Background(), int64(i%5))
			}
			m.ReapIdle(context.Background())
		})
	}
	wg.Wait()
	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if left := rt.Containers(); len(left) != 0 {
		t.Errorf("containers left after Close: %v", left)
	}
}

func TestManagerEnsureImageChangeReplaces(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	m := newManager(t, rt, backends.Limits{}, nil)
	port := backendPort(t)

	first := ensure(t, m, spec(1, 1, port))
	next := spec(1, 1, port)
	next.Image = "ghcr.io/acme/app:2"
	second := ensure(t, m, next)

	if first.Token == second.Token {
		t.Error("image change kept the old container")
	}
	if got := stopped(rt); !slices.Equal(got, []string{"c1"}) {
		t.Errorf("Stopped = %v", got)
	}
	if _, ok := rt.Container("c1"); ok {
		t.Error("old container not removed")
	}
	if tracked, image := m.TrackedForTest(1, 1); !tracked || image != next.Image {
		t.Errorf("tracked = %v %q", tracked, image)
	}
	if n := createdCount(rt); n != 2 {
		t.Errorf("Created = %d", n)
	}
}

func TestManagerEnsureConcurrentWaitsForInflightStart(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	entered, release := blockStarts(rt, nil)
	m := newManager(t, rt, backends.Limits{}, nil)
	port := backendPort(t)

	type result struct {
		ep  backends.Endpoint
		err error
	}
	results := make(chan result, 2)
	call := func() {
		ep, err := m.Ensure(context.Background(), spec(1, 1, port))
		results <- result{ep, err}
	}
	waiting := make(chan struct{}, 1)
	m.SetOnWaitForTest(func() { waiting <- struct{}{} })
	go call()
	<-entered
	if m.Running(1, 1) {
		t.Error("Running is true while starting")
	}
	go call()
	<-waiting
	close(release)

	a, b := <-results, <-results
	if a.err != nil || b.err != nil {
		t.Fatalf("errors: %v, %v", a.err, b.err)
	}
	if a.ep != b.ep {
		t.Errorf("endpoints differ: %+v vs %+v", a.ep, b.ep)
	}
	if n := createdCount(rt); n != 1 {
		t.Errorf("Created = %d", n)
	}
}

func TestManagerEnsureCanceledWhileAnotherStarts(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	entered, release := blockStarts(rt, nil)
	m := newManager(t, rt, backends.Limits{}, nil)
	port := backendPort(t)

	firstErr := make(chan error, 1)
	go func() {
		_, err := m.Ensure(context.Background(), spec(1, 1, port))
		firstErr <- err
	}()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	waitErr := make(chan error, 1)
	go func() {
		_, err := m.Ensure(ctx, spec(1, 1, port))
		waitErr <- err
	}()
	cancel()
	if err := <-waitErr; !errors.Is(err, context.Canceled) {
		t.Fatalf("waiting Ensure = %v, want context.Canceled", err)
	}

	close(release)
	if err := <-firstErr; err != nil {
		t.Fatalf("starting Ensure = %v", err)
	}
	if !m.Running(1, 1) {
		t.Error("cancelled waiter aborted the start")
	}
}

func TestManagerStartSurvivesCallerCancel(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	entered, release := blockStarts(rt, nil)
	m := newManager(t, rt, backends.Limits{}, nil)
	port := backendPort(t)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, err := m.Ensure(ctx, spec(1, 1, port))
		done <- err
	}()
	<-entered
	cancel()
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("Ensure after caller cancel = %v", err)
	}
	if !m.Running(1, 1) {
		t.Error("backend not running")
	}
}

func TestManagerFailedStartKeepsNewerEntry(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	boom := errors.New("boom")
	entered, release := blockStarts(rt, map[string]error{"c1": boom})
	m := newManager(t, rt, backends.Limits{}, nil)
	port := backendPort(t)

	firstErr := make(chan error, 1)
	go func() {
		_, err := m.Ensure(context.Background(), spec(1, 1, port))
		firstErr <- err
	}()
	if id := <-entered; id != "c1" {
		t.Fatalf("first start = %s", id)
	}

	stopDone := make(chan error, 1)
	go func() { stopDone <- m.StopVersion(context.Background(), 1, 1) }()
	waitFor(t, "StopVersion to drop the starting entry", func() bool {
		tracked, _ := m.TrackedForTest(1, 1)
		return !tracked
	})

	// A newer start for the same key while the first is still starting.
	newer := make(chan error, 1)
	go func() {
		_, err := m.Ensure(context.Background(), spec(1, 1, port))
		newer <- err
	}()
	if id := <-entered; id != "c2" {
		t.Fatalf("second start = %s", id)
	}
	close(release)
	if err := <-newer; err != nil {
		t.Fatalf("newer Ensure = %v", err)
	}
	if err := <-firstErr; !errors.Is(err, boom) {
		t.Fatalf("first Ensure = %v, want boom", err)
	}
	if err := <-stopDone; err != nil {
		t.Fatalf("StopVersion = %v", err)
	}
	if !m.Running(1, 1) {
		t.Fatal("the failed start removed the newer entry")
	}
	if slices.Contains(stopped(rt), "c2") {
		t.Error("newer container was stopped")
	}
}

func TestManagerMaxRunningEvictsLeastRecentlyUsed(t *testing.T) {
	port := backendPort(t)
	t.Run("cap 1", func(t *testing.T) {
		rt := backendstest.NewFakeRuntime()
		m := newManager(t, rt, backends.Limits{MaxRunning: 1}, nil)
		ensure(t, m, spec(1, 1, port))
		ensure(t, m, spec(2, 1, port))
		if m.Running(1, 1) || !m.Running(2, 1) {
			t.Errorf("running: u1 %v, u2 %v", m.Running(1, 1), m.Running(2, 1))
		}
		if got := stopped(rt); !slices.Equal(got, []string{"c1"}) {
			t.Errorf("Stopped = %v", got)
		}
	})
	t.Run("cap 2 with reuse", func(t *testing.T) {
		rt := backendstest.NewFakeRuntime()
		clk := &clock{now: time.Unix(1000, 0)}
		m := newManager(t, rt, backends.Limits{MaxRunning: 2}, clk.Now)
		ensure(t, m, spec(1, 1, port)) // c1
		clk.Advance(time.Second)
		ensure(t, m, spec(2, 1, port)) // c2
		clk.Advance(time.Second)
		ensure(t, m, spec(1, 1, port)) // touches u1
		clk.Advance(time.Second)
		ensure(t, m, spec(3, 1, port)) // evicts u2
		if !m.Running(1, 1) || m.Running(2, 1) || !m.Running(3, 1) {
			t.Errorf("running: u1 %v, u2 %v, u3 %v", m.Running(1, 1), m.Running(2, 1), m.Running(3, 1))
		}
		if got := stopped(rt); !slices.Equal(got, []string{"c2"}) {
			t.Errorf("Stopped = %v", got)
		}
	})
	t.Run("starting entries are not evicted", func(t *testing.T) {
		rt := backendstest.NewFakeRuntime()
		entered, release := blockStarts(rt, nil)
		m := newManager(t, rt, backends.Limits{MaxRunning: 1}, nil)
		done := make(chan error, 2)
		go func() { _, err := m.Ensure(context.Background(), spec(1, 1, port)); done <- err }()
		<-entered
		go func() { _, err := m.Ensure(context.Background(), spec(2, 1, port)); done <- err }()
		<-entered
		close(release)
		for range 2 {
			if err := <-done; err != nil {
				t.Fatal(err)
			}
		}
		if !m.Running(1, 1) || !m.Running(2, 1) || len(stopped(rt)) != 0 {
			t.Errorf("concurrent cold starts: u1 %v, u2 %v, stopped %v", m.Running(1, 1), m.Running(2, 1), stopped(rt))
		}
	})
}

func TestManagerReapIdle(t *testing.T) {
	port := backendPort(t)
	rt := backendstest.NewFakeRuntime()
	clk := &clock{now: time.Unix(1000, 0)}
	m := newManager(t, rt, backends.Limits{IdleTimeout: 15 * time.Minute}, clk.Now)

	ensure(t, m, spec(1, 1, port)) // c1 at t0
	clk.Advance(10 * time.Minute)
	ensure(t, m, spec(2, 1, port)) // c2 at t0+10m
	clk.Advance(6 * time.Minute)
	m.ReapIdle(context.Background())

	if m.Running(1, 1) || !m.Running(2, 1) {
		t.Errorf("running: u1 %v, u2 %v", m.Running(1, 1), m.Running(2, 1))
	}
	if got := stopped(rt); !slices.Equal(got, []string{"c1"}) {
		t.Errorf("Stopped = %v", got)
	}

	// A zero idle timeout never reaps.
	rt2 := backendstest.NewFakeRuntime()
	m2 := newManager(t, rt2, backends.Limits{}, clk.Now)
	ensure(t, m2, spec(1, 1, port))
	clk.Advance(24 * time.Hour)
	m2.ReapIdle(context.Background())
	if !m2.Running(1, 1) {
		t.Error("zero IdleTimeout reaped a backend")
	}
}

func TestManagerRunReapsUntilDone(t *testing.T) {
	backends.SetReapIntervalForTest(t, 5*time.Millisecond)
	port := backendPort(t)
	rt := backendstest.NewFakeRuntime()
	clk := &clock{now: time.Unix(1000, 0)}
	m := newManager(t, rt, backends.Limits{IdleTimeout: time.Minute}, clk.Now)
	ensure(t, m, spec(1, 1, port))
	clk.Advance(2 * time.Minute)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx)
		close(done)
	}()
	waitFor(t, "Run to reap the idle backend", func() bool { return !m.Running(1, 1) })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
}

func TestManagerReadinessFailureRemovesContainer(t *testing.T) {
	backends.SetReadinessForTest(t, 50*time.Millisecond, 5*time.Millisecond)
	rt := backendstest.NewFakeRuntime()
	var dials int
	var mu sync.Mutex
	m := backends.NewManager(backends.Config{
		Runtime: rt, Network: testNetwork, Instance: testInstance,
		Dial: func(context.Context, string, string) (net.Conn, error) {
			mu.Lock()
			dials++
			mu.Unlock()
			return nil, errors.New("connection refused")
		},
	})
	t.Cleanup(func() { _ = m.Close(context.Background()) })

	_, err := m.Ensure(context.Background(), spec(1, 1, 8080))
	if err == nil || !strings.Contains(err.Error(), "port 8080") {
		t.Fatalf("Ensure = %v, want an error naming port 8080", err)
	}
	if !slices.Contains(snapshot(rt, func(f *backendstest.FakeRuntime) []string { return f.Removed }), "c1") {
		t.Error("container not removed after readiness failure")
	}
	if _, ok := rt.Container("c1"); ok {
		t.Error("container still exists")
	}
	if tracked, _ := m.TrackedForTest(1, 1); tracked {
		t.Error("failed start left an entry")
	}
	mu.Lock()
	defer mu.Unlock()
	if dials < 2 {
		t.Errorf("dialled %d times, want retries", dials)
	}
}

func TestManagerStartErrorsLeaveNoEntry(t *testing.T) {
	port := backendPort(t)
	boom := errors.New("boom")
	cases := []struct {
		name  string
		set   func(*backendstest.FakeRuntime, error)
		check func(*testing.T, *backendstest.FakeRuntime)
	}{
		{"pull", func(f *backendstest.FakeRuntime, err error) { f.PullErr = err }, nil},
		{"create", func(f *backendstest.FakeRuntime, err error) { f.CreateErr = err }, nil},
		{"start", func(f *backendstest.FakeRuntime, err error) { f.StartErr = err }, func(t *testing.T, f *backendstest.FakeRuntime) {
			if _, ok := f.Container("c1"); ok {
				t.Error("container of a failed start was not removed")
			}
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rt := backendstest.NewFakeRuntime()
			m := newManager(t, rt, backends.Limits{}, nil)
			tc.set(rt, boom)
			if _, err := m.Ensure(context.Background(), spec(1, 1, port)); !errors.Is(err, boom) {
				t.Fatalf("Ensure = %v, want boom", err)
			}
			if tracked, _ := m.TrackedForTest(1, 1); tracked || m.Running(1, 1) {
				t.Fatal("failed start left an entry")
			}
			if tc.check != nil {
				tc.check(t, rt)
			}
			tc.set(rt, nil)
			ensure(t, m, spec(1, 1, port))
			if !m.Running(1, 1) {
				t.Error("retry did not start the backend")
			}
		})
	}
}

func TestManagerStopUploadAndRemoveData(t *testing.T) {
	port := backendPort(t)
	rt := backendstest.NewFakeRuntime()
	m := newManager(t, rt, backends.Limits{}, nil)
	ensure(t, m, spec(1, 1, port)) // c1
	ensure(t, m, spec(1, 2, port)) // c2
	ensure(t, m, spec(2, 1, port)) // c3

	if err := m.StopVersion(context.Background(), 1, 2); err != nil {
		t.Fatal(err)
	}
	if m.Running(1, 2) || !m.Running(1, 1) {
		t.Error("StopVersion stopped the wrong version")
	}
	ensure(t, m, spec(1, 2, port)) // c4

	if err := m.StopUpload(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if m.Running(1, 1) || m.Running(1, 2) || !m.Running(2, 1) {
		t.Error("StopUpload did not stop exactly upload 1")
	}
	got := stopped(rt)
	slices.Sort(got)
	if !slices.Equal(got, []string{"c1", "c2", "c4"}) {
		t.Errorf("Stopped = %v", got)
	}

	if err := m.RemoveUploadData(context.Background(), 2); err != nil {
		t.Fatal(err)
	}
	if m.Running(2, 1) {
		t.Error("RemoveUploadData left the backend running")
	}
	if vols := snapshot(rt, func(f *backendstest.FakeRuntime) []string { return f.VolumesRemoved }); !slices.Equal(vols, []string{"peek-abcd1234-data-u2"}) {
		t.Errorf("VolumesRemoved = %v", vols)
	}
	if left := rt.Containers(); len(left) != 0 {
		t.Errorf("containers left: %v", left)
	}
}

func TestManagerStopVersionWaitsForStart(t *testing.T) {
	port := backendPort(t)
	rt := backendstest.NewFakeRuntime()
	entered, release := blockStarts(rt, nil)
	m := newManager(t, rt, backends.Limits{}, nil)

	go func() { _, _ = m.Ensure(context.Background(), spec(1, 1, port)) }()
	<-entered
	stopDone := make(chan error, 1)
	go func() { stopDone <- m.StopVersion(context.Background(), 1, 1) }()
	select {
	case err := <-stopDone:
		t.Fatalf("StopVersion returned before the start finished: %v", err)
	case <-time.After(20 * time.Millisecond):
	}
	close(release)
	if err := <-stopDone; err != nil {
		t.Fatal(err)
	}
	if got := stopped(rt); !slices.Equal(got, []string{"c1"}) {
		t.Errorf("Stopped = %v", got)
	}
}

func TestManagerCanceledStopsFinishInBackground(t *testing.T) {
	port := backendPort(t)
	t.Run("StopVersion", func(t *testing.T) {
		rt := backendstest.NewFakeRuntime()
		entered, release := blockStarts(rt, nil)
		m := newManager(t, rt, backends.Limits{}, nil)
		started := make(chan error, 1)
		go func() { _, err := m.Ensure(context.Background(), spec(1, 1, port)); started <- err }()
		<-entered

		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.StopVersion(ctx, 1, 1); !errors.Is(err, context.Canceled) {
			t.Fatalf("StopVersion = %v", err)
		}
		close(release)
		<-started
		if err := m.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := stopped(rt); !slices.Equal(got, []string{"c1"}) {
			t.Errorf("Stopped = %v", got)
		}
	})
	t.Run("image change", func(t *testing.T) {
		rt := backendstest.NewFakeRuntime()
		entered, release := blockStarts(rt, nil)
		m := newManager(t, rt, backends.Limits{}, nil)
		started := make(chan error, 1)
		go func() { _, err := m.Ensure(context.Background(), spec(1, 1, port)); started <- err }()
		<-entered

		ctx, cancel := context.WithCancel(context.Background())
		replaced := make(chan error, 1)
		next := spec(1, 1, port)
		next.Image = "ghcr.io/acme/app:2"
		go func() { _, err := m.Ensure(ctx, next); replaced <- err }()
		waitFor(t, "the new image to take the old entry", func() bool {
			tracked, _ := m.TrackedForTest(1, 1)
			return !tracked
		})
		cancel()
		if err := <-replaced; !errors.Is(err, context.Canceled) {
			t.Fatalf("replacing Ensure = %v", err)
		}
		close(release)
		<-started
		if err := m.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if got := stopped(rt); !slices.Equal(got, []string{"c1"}) {
			t.Errorf("Stopped = %v", got)
		}
	})
	t.Run("Close", func(t *testing.T) {
		rt := backendstest.NewFakeRuntime()
		entered, release := blockStarts(rt, nil)
		m := newManager(t, rt, backends.Limits{}, nil)
		go func() { _, _ = m.Ensure(context.Background(), spec(1, 1, port)) }()
		<-entered
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := m.Close(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("Close = %v", err)
		}
		close(release)
		waitFor(t, "the background stop", func() bool { return slices.Equal(stopped(rt), []string{"c1"}) })
	})
}

func TestManagerLogs(t *testing.T) {
	port := backendPort(t)
	rt := backendstest.NewFakeRuntime()
	rt.LogsData = []byte("2026-01-01T00:00:00Z hello\n")
	m := newManager(t, rt, backends.Limits{}, nil)

	if _, err := m.Logs(context.Background(), 1, 1, 100); !errors.Is(err, backends.ErrNotRunning) {
		t.Fatalf("Logs for unknown backend = %v", err)
	}
	ensure(t, m, spec(1, 1, port))
	logs, err := m.Logs(context.Background(), 1, 1, 100)
	if err != nil || string(logs) != "2026-01-01T00:00:00Z hello\n" {
		t.Fatalf("Logs = %q, %v", logs, err)
	}
}

func TestManagerStartRemovesOwnLeftovers(t *testing.T) {
	rt := backendstest.NewFakeRuntime()
	own := rt.AddContainer(backends.ContainerInfo{Name: "peek-abcd1234-u1-v1", Labels: map[string]string{"peek.managed": "true", "peek.instance": testInstance}})
	other := rt.AddContainer(backends.ContainerInfo{Name: "peek-ffff0000-u1-v1", Labels: map[string]string{"peek.managed": "true", "peek.instance": "ffff0000"}})
	unmanaged := rt.AddContainer(backends.ContainerInfo{Name: "db", Labels: map[string]string{"peek.instance": testInstance}})

	newManager(t, rt, backends.Limits{}, nil)

	if _, ok := rt.Container(own); ok {
		t.Error("own leftover not removed")
	}
	for _, id := range []string{other, unmanaged} {
		if _, ok := rt.Container(id); !ok {
			t.Errorf("container %s of someone else was removed", id)
		}
	}
	if nets := snapshot(rt, func(f *backendstest.FakeRuntime) []string { return f.Networks }); !slices.Equal(nets, []string{testNetwork}) {
		t.Errorf("Networks = %v", nets)
	}
}

func TestManagerStartErrors(t *testing.T) {
	boom := errors.New("boom")
	for name, set := range map[string]func(*backendstest.FakeRuntime){
		"network": func(f *backendstest.FakeRuntime) { f.NetworkErr = boom },
		"list":    func(f *backendstest.FakeRuntime) { f.ListErr = boom },
	} {
		t.Run(name, func(t *testing.T) {
			rt := backendstest.NewFakeRuntime()
			set(rt)
			m := backends.NewManager(backends.Config{Runtime: rt, Network: testNetwork, Instance: testInstance})
			if err := m.Start(context.Background()); !errors.Is(err, boom) {
				t.Fatalf("Start = %v", err)
			}
		})
	}
	t.Run("remove", func(t *testing.T) {
		m := backends.NewManager(backends.Config{Runtime: failingRemove{backendstest.NewFakeRuntime(), boom}, Network: testNetwork, Instance: testInstance})
		if err := m.Start(context.Background()); !errors.Is(err, boom) {
			t.Fatalf("Start = %v", err)
		}
	})
}

// failingRemove lists one leftover container and fails to remove it.
type failingRemove struct {
	*backendstest.FakeRuntime
	err error
}

func (f failingRemove) ListContainers(context.Context, map[string]string) ([]backends.ContainerInfo, error) {
	return []backends.ContainerInfo{{ID: "x", Name: "peek-abcd1234-u1-v1"}}, nil
}

func (f failingRemove) RemoveContainer(context.Context, string) error { return f.err }

func TestManagerCloseStopsEverything(t *testing.T) {
	port := backendPort(t)
	rt := backendstest.NewFakeRuntime()
	m := newManager(t, rt, backends.Limits{}, nil)
	ensure(t, m, spec(1, 1, port))
	ensure(t, m, spec(2, 1, port))

	if err := m.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := stopped(rt)
	slices.Sort(got)
	if !slices.Equal(got, []string{"c1", "c2"}) {
		t.Errorf("Stopped = %v", got)
	}
	if left := rt.Containers(); len(left) != 0 {
		t.Errorf("containers left: %v", left)
	}
	if m.Running(1, 1) {
		t.Error("Running after Close")
	}
	if _, err := m.Ensure(context.Background(), spec(3, 1, port)); err == nil {
		t.Error("Ensure after Close succeeded")
	}
	if n := createdCount(rt); n != 2 {
		t.Errorf("Ensure after Close created a container: %d", n)
	}
}
