// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package graphfrag

import (
	"encoding/json"
	"fmt"
)

// GraphFragmentLocalBinding is a statement of a function that gives one of
// its local names a value (Python, graph-algo-py-35; optional, no schema
// bump), written for each name the function binds more than once with a
// call among the values, so a reader tells which assignment of a local
// reaches a use without the source. JSON is a positional array:
// [function, name, line, col, effect_line, effect_col, block_end_line,
// block_end_col, loop_line, loop_col], and for a target of a tuple or list
// pattern assigned a call, [..., element, value_line, value_col].
//
// function addresses GraphFragmentExport.Functions; columns are 1-based.
// line and col start the binding statement (the assignment, the with item,
// the for or except clause, the del, import or def statement): a call
// written from there up to the effect point is the value it binds.
// effect_line and effect_col are where the name holds the new value (the end
// of the statement; the start of the body of a for loop or except clause).
// block_end_line and block_end_col end (exclusive) the innermost block that
// runs the binding whenever it runs, 0 for none: a later use inside it reads
// the new value, not an earlier one. loop_line and loop_col start the
// outermost loop around the binding, 0 for none: a use written before the
// binding inside that loop may read it on the next iteration. A binding the
// producer cannot place (an augmented assignment, an assignment expression,
// a match capture) is not listed, and a name a `global` or `nonlocal`
// statement names has no bindings; a reader then keeps every assignment.
//
// Every target of a tuple or list pattern assigned a call is listed, also
// a name bound once (`pub, priv = rsa.newkeys(..)`; graph-algo-py-35, gap
// 4): element is its position in the pattern (from 0), the element of the
// call's value the name holds, and value_line, value_col start that call
// (the line and start_col of its site). A name after a starred target or
// in a nested pattern holds no fixed element and is not listed.
type GraphFragmentLocalBinding struct {
	Function                  int
	Name                      string
	Line, Col                 int
	EffectLine, EffectCol     int
	BlockEndLine, BlockEndCol int
	LoopLine, LoopCol         int
	// Unpacked marks a tuple-pattern target: Element, ValueLine and
	// ValueCol are written.
	Unpacked            bool
	Element             int
	ValueLine, ValueCol int
}

// MarshalJSON encodes the binding as a positional JSON array.
func (b GraphFragmentLocalBinding) MarshalJSON() ([]byte, error) {
	return AppendLocalBindingJSON(nil, b), nil
}

// AppendLocalBindingJSON appends the positional encoding of b to dst.
func AppendLocalBindingJSON(dst []byte, b GraphFragmentLocalBinding) []byte {
	dst = appendPositionalInts(append(dst, '['), b.Function)
	dst = appendPositionalStrings(dst, b.Name)
	dst = appendPositionalInts(dst, b.Line, b.Col, b.EffectLine, b.EffectCol, b.BlockEndLine, b.BlockEndCol, b.LoopLine, b.LoopCol)
	if b.Unpacked {
		dst = appendPositionalInts(dst, b.Element, b.ValueLine, b.ValueCol)
	}
	dst[len(dst)-1] = ']'
	return dst
}

// UnmarshalJSON decodes the positional binding array: 10 fields, or 13 for
// a tuple-pattern target.
func (b *GraphFragmentLocalBinding) UnmarshalJSON(data []byte) error {
	*b = GraphFragmentLocalBinding{}
	if err := decodePositional("local binding", data, 10, &b.Function, &b.Name, &b.Line, &b.Col, &b.EffectLine, &b.EffectCol,
		&b.BlockEndLine, &b.BlockEndCol, &b.LoopLine, &b.LoopCol, &b.Element, &b.ValueLine, &b.ValueCol); err != nil {
		return err
	}
	var values []json.RawMessage
	_ = json.Unmarshal(data, &values) // decoded above
	switch len(values) {
	case 10:
	case 13:
		b.Unpacked = true
	default:
		return fmt.Errorf("graphfrag: local binding has %d fields, want 10 or 13", len(values))
	}
	return nil
}
