package db

import (
	"context"
	"testing"
	"time"
)

func TestCreateCLILoginDeviceWithContextStoresRequestContext(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateCLILoginDeviceWithContext(ctx, "device-code", "ABCDEFGH", time.Now().Add(time.Minute), "203.0.113.7", "peek-cli/1.2.3"); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetCLILoginByUserCode(ctx, "ABCDEFGH")
	if err != nil {
		t.Fatal(err)
	}
	if d.RequestIP != "203.0.113.7" || d.UserAgent != "peek-cli/1.2.3" || d.Status != "pending" {
		t.Fatalf("device = %+v", d)
	}
}

func TestCreateCLILoginDeviceLeavesRequestContextEmpty(t *testing.T) {
	ctx := context.Background()
	s := openTokenTestStore(t)
	if err := s.CreateCLILoginDevice(ctx, "device-code", "ABCDEFGH", time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	d, err := s.GetCLILoginByDevice(ctx, "device-code")
	if err != nil {
		t.Fatal(err)
	}
	if d.RequestIP != "" || d.UserAgent != "" {
		t.Fatalf("device = %+v", d)
	}
}
