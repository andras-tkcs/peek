package peekd

import (
	"net"
	"testing"
)

func TestRunHealthcheckFailsWhenNothingListens(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	if got := runHealthcheck([]string{"--addr", addr}); got != 1 {
		t.Fatalf("runHealthcheck = %d, want 1", got)
	}
}

func TestRunHealthcheckUsesEnvAddrDefault(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()
	t.Setenv("PEEK_HEALTHCHECK_ADDR", addr)

	if got := runHealthcheck(nil); got != 1 {
		t.Fatalf("runHealthcheck = %d, want 1", got)
	}
}
