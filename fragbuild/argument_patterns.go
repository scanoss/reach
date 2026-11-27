// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package fragbuild

import "regexp"

// MaxSourceDepth bounds how deep the source nodes of an argument are walked
// to tell whether they all reference objects.
const MaxSourceDepth = 8

// PythonKeywordArgumentPattern matches a Python keyword argument's raw text,
// `<name> = <value>`, e.g. "timeout=30" or "timeout=TIMEOUT". Callers apply it
// to any argument whose keyword they want, JavaScript's `f(a = v)` included
// (see ArgumentSlot); SplitKeywordArgument rejects `==`. A value may span lines (`attributes={\n "name": n,\n}`).
var PythonKeywordArgumentPattern = regexp.MustCompile(`(?s)^([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.+)$`)

// rubyKeywordArgumentPattern matches a Ruby keyword argument's raw text,
// `name: value`. The value is kept with its leading space so a constant
// path (`Net::HTTP`) can be told from a symbol value (`name: :sym`).
var rubyKeywordArgumentPattern = regexp.MustCompile(`(?s)^([A-Za-z_][A-Za-z0-9_]*):(.*)$`)
