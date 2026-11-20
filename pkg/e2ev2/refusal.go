package e2ev2

import "sort"

// Refusal is an unsealed refusal: one of the 15 enumerated codes with its status, and a
// Retry-After (seconds, 1..180) only for e2e_v2_busy.
type Refusal struct {
	Status     int
	Code       string
	RetryAfter int
}

// codes are the 15 refusal codes a VM may answer (spec section 4.3) and their statuses.
var codes = map[string]int{
	"e2e_v2_undecryptable":    400,
	"e2e_v2_malformed":        400,
	"e2e_v2_stream_mismatch":  400,
	"e2e_v2_stale":            400,
	"e2e_v2_from_the_future":  400,
	"e2e_v2_wrong_endpoint":   403,
	"e2e_v2_wrong_instance":   403,
	"e2e_v2_wrong_path":       403,
	"e2e_v2_route_not_served": 404,
	"e2e_v2_method":           405,
	"e2e_v2_replayed":         409,
	"e2e_v2_app_failed":       502,
	"e2e_v2_answer_too_large": 502,
	"e2e_v2_identity_unknown": 503,
	"e2e_v2_busy":             503,
}

// Codes lists the 15 codes, sorted.
func Codes() []string {
	out := make([]string, 0, len(codes))
	for c := range codes {
		out = append(out, c)
	}
	sort.Strings(out)
	return out
}

// StatusOf is a code's status, or 0 for a code outside the 15.
func StatusOf(code string) int { return codes[code] }

func refusal(code string) *Refusal {
	status, ok := codes[code]
	if !ok {
		panic("e2ev2: refusal code outside the enumerated 15: " + code)
	}
	return &Refusal{Status: status, Code: code}
}

// NewRefusal returns the refusal for one of the 15 codes (it panics for any other code).
func NewRefusal(code string) *Refusal { return refusal(code) }

// Busy is the busy refusal with its Retry-After, clamped to 1..180.
func Busy(retryAfter int) *Refusal {
	r := refusal("e2e_v2_busy")
	r.RetryAfter = min(max(retryAfter, 1), 180)
	return r
}

// Body is the refusal's exact body, the compact {"detail":{"code":"<code>"}}.
func (r *Refusal) Body() []byte {
	if _, ok := codes[r.Code]; !ok {
		panic("e2ev2: refusal code outside the enumerated 15: " + r.Code)
	}
	return []byte(`{"detail":{"code":"` + r.Code + `"}}`)
}
