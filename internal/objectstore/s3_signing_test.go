package objectstore

import (
	"net/http"
	"testing"
	"time"
)

// Expected Authorization header for the "GET Object" example in
// https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html
const knownVectorAuthorization = "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"

func TestS3SignRequestMatchesKnownVector(t *testing.T) {
	settings := map[string]string{
		"s3_access_key": "AKIAIOSFODNN7EXAMPLE",
		"s3_secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
		"s3_region":     "us-east-1",
	}
	s := NewS3Storage(false, func(k string) string { return settings[k] })
	s.now = func() time.Time { return time.Date(2013, 5, 24, 0, 0, 0, 0, time.UTC) }

	req, err := http.NewRequest(http.MethodGet, "https://examplebucket.s3.amazonaws.com/test.txt", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=0-9")
	s.signRequest(req, "test.txt", nil)

	if got := req.Header.Get("Authorization"); got != knownVectorAuthorization {
		t.Errorf("Authorization = %q, want %q", got, knownVectorAuthorization)
	}
	if got := req.Header.Get("X-Amz-Date"); got != "20130524T000000Z" {
		t.Errorf("X-Amz-Date = %q", got)
	}
}
