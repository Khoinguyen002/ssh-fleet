package fuzzy

import (
	"sort"
	"strings"
)

// Score computes a fuzzy match score between query and candidate fields.
// Returns (matched, score) where higher score means better match.
func Score(query string, fields ...string) (bool, int) {
	q := strings.ToLower(strings.TrimSpace(query))
	if q == "" {
		return true, 1
	}

	tokens := strings.Fields(q)
	joined := strings.ToLower(strings.Join(fields, " "))

	totalScore := 0
	for _, tok := range tokens {
		bestTok := 0
		for idx, f := range fields {
			fl := strings.ToLower(f)
			if fl == "" {
				continue
			}
			if fl == tok {
				bestTok = max(bestTok, 200-idx*10)
			} else if strings.HasPrefix(fl, tok) {
				bestTok = max(bestTok, 140-idx*10)
			} else if strings.Contains(fl, tok) {
				bestTok = max(bestTok, 100-idx*10)
			} else if subseqScore, ok := subsequenceScore(tok, fl); ok {
				bestTok = max(bestTok, subseqScore-idx*5)
			}
		}
		if bestTok <= 0 {
			// Fall back to subsequence across joined text.
			if s, ok := subsequenceScore(tok, joined); ok {
				bestTok = s
			} else {
				return false, 0
			}
		}
		totalScore += bestTok
	}
	return true, totalScore
}

func subsequenceScore(needle, haystack string) (int, bool) {
	if needle == "" {
		return 1, true
	}
	ni := 0
	consecutive := 0
	score := 0
	for hi := 0; hi < len(haystack) && ni < len(needle); hi++ {
		if haystack[hi] == needle[ni] {
			ni++
			consecutive++
			score += 10 + consecutive*4
		} else {
			consecutive = 0
		}
	}
	if ni != len(needle) {
		return 0, false
	}
	return score, true
}

type Ranked[T any] struct {
	Item  T
	Score int
}

func Rank[T any](items []T, query string, fieldsFn func(T) []string) []T {
	var matched []Ranked[T]
	for _, it := range items {
		ok, sc := Score(query, fieldsFn(it)...)
		if ok {
			matched = append(matched, Ranked[T]{Item: it, Score: sc})
		}
	}
	sort.SliceStable(matched, func(i, j int) bool {
		return matched[i].Score > matched[j].Score
	})
	out := make([]T, len(matched))
	for i := range matched {
		out[i] = matched[i].Item
	}
	return out
}
