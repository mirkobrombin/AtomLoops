package main

import "testing"

func TestDefaultFeedPerArch(t *testing.T) {
	if got := defaultFeed("amd64"); got != "https://updates.sinty.dev/stable" {
		t.Fatalf("x86_64 feed moved: %s", got)
	}
	if got := defaultFeed("arm64"); got != "https://updates.sinty.dev/stable/aarch64" {
		t.Fatalf("aarch64 feed: %s", got)
	}
}
