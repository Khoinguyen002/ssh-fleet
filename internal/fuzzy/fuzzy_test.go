package fuzzy

import "testing"

func TestRank(t *testing.T) {
	items := []string{"prod-api-sg", "my-thinkpad-laptop", "home-nas-relay"}
	got := Rank(items, "laptop", func(s string) []string { return []string{s} })
	if len(got) != 1 || got[0] != "my-thinkpad-laptop" {
		t.Fatalf("unexpected fuzzy rank result: %v", got)
	}
	subseq := Rank(items, "pasg", func(s string) []string { return []string{s} })
	if len(subseq) == 0 || subseq[0] != "prod-api-sg" {
		t.Fatalf("expected subsequence match prod-api-sg, got %v", subseq)
	}
}
