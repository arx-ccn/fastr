package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/acme"
)

func TestCooldownStopsAttempt(t *testing.T) {
	ca := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Retry-After", "600")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer ca.Close()
	o, err := endpointOrigin(ca.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := caTransport{base: ca.Client().Transport.(*http.Transport), origin: o}
	client := acme.Client{DirectoryURL: ca.URL, HTTPClient: &http.Client{Transport: &transport}}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now().Unix()
	_, err = client.Discover(ctx)
	var problem *acme.Error
	if !errors.As(err, &problem) || problem.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("Discover did not return the cooldown status: %v", err)
	}
	if transport.retryUntil < start+600 {
		t.Fatalf("Retry-After was lost: %d", transport.retryUntil)
	}
}
