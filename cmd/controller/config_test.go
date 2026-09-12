package main

import "testing"

func TestParseCustomServiceAccounts(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       string
		want      int
		wantError bool
	}{
		{name: "unset"},
		{name: "empty", raw: "[]"},
		{name: "null", raw: "null"},
		{name: "default namespace", raw: `[{"name":"custom-sa"}]`, want: 1},
		{name: "explicit namespace", raw: `[{"name":"custom-sa","namespace":"sidereal-system"}]`, want: 1},
		{name: "duplicates", raw: `[{"name":"custom-sa"},{"name":"custom-sa"}]`, want: 1},
		{name: "malformed", raw: "[", wantError: true},
		{name: "wrong type", raw: `["custom-sa"]`, wantError: true},
		{name: "missing name", raw: `[{}]`, wantError: true},
		{name: "whitespace", raw: `[{"name":" custom-sa "}]`, wantError: true},
		{name: "wrong namespace", raw: `[{"name":"custom-sa","namespace":"production"}]`, wantError: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseCustomServiceAccounts(tc.raw)
			if (err != nil) != tc.wantError {
				t.Fatalf("unexpected error: %v", err)
			}
			if tc.wantError {
				return
			}
			if got == nil || len(got) != tc.want {
				t.Fatalf("got %v, want non-nil registry with %d entries", got, tc.want)
			}
			if tc.want > 0 && !got["custom-sa"] {
				t.Fatal("registration missing")
			}
		})
	}
}
