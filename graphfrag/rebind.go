// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"fmt"
	"strconv"
)

// GraphFragmentRebind is where a function body may give one of its variables
// another value or overwrite the buffer it holds (graph-fragment-1.23). JSON
// is a positional array: [function, name, line, ...].
//
// function addresses GraphFragmentExport.Functions; name is a variable a call
// of the function passes as a bare argument; the lines (ascending) are the
// lines of the body, between its first line and its last call, that may
// rebind name, as the related-material pass reads them in the source. A
// function whose source the producer could not read is written as
// [function] alone: nothing is known of it. Every other function of a
// fragment whose scan_metadata.rebind_lines is set rebinds no variable on the
// lines not listed.
type GraphFragmentRebind struct {
	Function int
	Name     string
	Lines    []int
}

// Unread reports the entry of a function whose source the producer could
// not read.
func (r GraphFragmentRebind) Unread() bool { return r.Name == "" }

// MarshalJSON encodes the entry as a positional JSON array.
func (r GraphFragmentRebind) MarshalJSON() ([]byte, error) {
	return AppendRebindJSON(nil, r), nil
}

// AppendRebindJSON appends the positional encoding of r to dst.
func AppendRebindJSON(dst []byte, r GraphFragmentRebind) []byte {
	dst = strconv.AppendInt(append(dst, '['), int64(r.Function), 10)
	if r.Unread() {
		return append(dst, ']')
	}
	dst = append(dst, ',')
	dst = appendPositionalStrings(dst, r.Name)
	dst = appendPositionalInts(dst, r.Lines...)
	dst[len(dst)-1] = ']'
	return dst
}

// UnmarshalJSON decodes the positional rebind array.
func (r *GraphFragmentRebind) UnmarshalJSON(data []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) == 0 || len(values) == 2 {
		return fmt.Errorf("graphfrag: rebind has %d fields, want 1 or 3 and more", len(values))
	}
	*r = GraphFragmentRebind{}
	if err := json.Unmarshal(values[0], &r.Function); err != nil {
		return fmt.Errorf("graphfrag: rebind function: %w", err)
	}
	if len(values) == 1 {
		return nil
	}
	if err := json.Unmarshal(values[1], &r.Name); err != nil {
		return fmt.Errorf("graphfrag: rebind name: %w", err)
	}
	if r.Name == "" {
		return fmt.Errorf("graphfrag: rebind of function %d has an empty name", r.Function)
	}
	r.Lines = make([]int, len(values)-2)
	for i := range r.Lines {
		if err := json.Unmarshal(values[i+2], &r.Lines[i]); err != nil {
			return fmt.Errorf("graphfrag: rebind line %d: %w", i, err)
		}
	}
	return nil
}
