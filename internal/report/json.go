package report

import (
	"encoding/json"
	"fmt"
	"io"
)

// WriteJSON renders the report as indented JSON.
//
// The schema is the Report struct and it is stable: findings carry rule IDs so
// a consumer can suppress a rule it disagrees with, and evidence carries its
// source path so a consumer can re-check a claim rather than trusting it.
func WriteJSON(w io.Writer, r *Report) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// Escaping HTML would mangle the `>` and `&` that appear in kubectl
	// commands and registry error messages.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(r); err != nil {
		return fmt.Errorf("encode report: %w", err)
	}
	return nil
}
