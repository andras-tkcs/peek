package cli

import "testing"

func TestDiscoverAuthTransportError(t *testing.T) {
	if _, err := discoverAuth(closedServerURL(t)); err == nil {
		t.Fatal("expected a transport error")
	}
	if ok, err := oauthAvailable(closedServerURL(t)); err == nil || ok {
		t.Fatalf("oauthAvailable = %v, %v; want error", ok, err)
	}
}

func TestDiscoverAuthTreatsHTTPErrorsAsNoDiscovery(t *testing.T) {
	for _, status := range []int{404, 500} {
		ts := jsonServer(t, status, `{"providers":[{"key":"x"}]}`)
		out, err := discoverAuth(ts.URL + "/")
		if err != nil || out.BrowserLogin || len(out.Providers) != 0 {
			t.Fatalf("status %d: out=%+v err=%v", status, out, err)
		}
	}
}

func TestDiscoverAuthRejectsBadJSON(t *testing.T) {
	ts := jsonServer(t, 200, `{not json`)
	if _, err := discoverAuth(ts.URL); err == nil {
		t.Fatal("expected a decode error")
	}
}
