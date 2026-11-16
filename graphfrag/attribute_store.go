// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"fmt"
)

// GraphFragmentAttributeStore is one assignment to an attribute of an object,
// `ctx.verify_mode = ssl.CERT_NONE` or `ctx.options |= ssl.OP_NO_TLSv1`
// (Python; optional, no schema bump). JSON is a positional array:
// [function, line, start_col, end_col, receiver, attribute, operator,
// end_line, value].
//
// function addresses GraphFragmentExport.Functions; the span is the whole
// assignment, columns 1-based, end exclusive; receiver is the object written
// (`ctx`, `self._ctx`) and attribute the name assigned, both without
// whitespace; operator is `=` or the augmented operator (`|=`); end_line is
// 0 for an assignment on one line; value is the value assigned, traced as a
// call argument is (its text, resolved value and provenance).
type GraphFragmentAttributeStore struct {
	Function                        int
	Line, StartCol, EndCol, EndLine int
	Receiver, Attribute, Operator   string
	Value                           GraphFragmentParameter
}

// MarshalJSON encodes the store as a positional JSON array.
func (s GraphFragmentAttributeStore) MarshalJSON() ([]byte, error) {
	return AppendAttributeStoreJSON(nil, s), nil
}

// AppendAttributeStoreJSON appends the positional encoding of s to dst.
func AppendAttributeStoreJSON(dst []byte, s GraphFragmentAttributeStore) []byte {
	dst = appendPositionalInts(append(dst, '['), s.Function, s.Line, s.StartCol, s.EndCol)
	dst = appendPositionalStrings(dst, s.Receiver, s.Attribute, s.Operator)
	dst = appendPositionalInts(dst, s.EndLine)
	value, _ := json.Marshal(s.Value) // a parameter always encodes
	return append(append(dst, value...), ']')
}

// UnmarshalJSON decodes the positional store array.
func (s *GraphFragmentAttributeStore) UnmarshalJSON(data []byte) error {
	var values []json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	if len(values) != 9 {
		return fmt.Errorf("graphfrag: attribute store has %d fields, want 9", len(values))
	}
	targets := []any{&s.Function, &s.Line, &s.StartCol, &s.EndCol, &s.Receiver, &s.Attribute, &s.Operator, &s.EndLine, &s.Value}
	for i := range values {
		if err := json.Unmarshal(values[i], targets[i]); err != nil {
			return fmt.Errorf("graphfrag: attribute store field %d: %w", i, err)
		}
	}
	return nil
}
