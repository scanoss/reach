// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"slices"
	"strings"

	sitter "github.com/smacker/go-tree-sitter"
)

// A dispatch table is a dict display whose keys are literals, read with a
// subscript: `{"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]`, or
// the same through a name the function or the module binds once to the
// display (`TABLE[alg]`). When the key resolves (a literal, or a name that
// traces to literals: an assigned one, the may-values of a variable, the
// value a branch fixes) the subscript is the entry's value: the source of
// the subscript is a VARIABLE named as it is written, holding the value of
// the entry, or of each entry its keys select. A key that does not resolve
// leaves the subscript without a source, unless the function itself writes
// or binds the table: the subscript then may hold any entry's value. The
// table's entries are constant references of their own (dict), always
// reported.

const pythonNodeDictionary = "dictionary"

// pythonTableMutators are the dict methods that change its entries.
var pythonTableMutators = map[string]bool{
	"update": true, "setdefault": true, "pop": true, "popitem": true, "clear": true, "__setitem__": true, "__delitem__": true,
}

// pythonReadOnlyBuiltins are the builtins a table can be passed to without
// its items being written: they read it, or copy it.
var pythonReadOnlyBuiltins = map[string]bool{
	"len": true, "sorted": true, "list": true, "tuple": true, "set": true, "frozenset": true, "dict": true,
	"iter": true, "enumerate": true, "reversed": true, "any": true, "all": true, "min": true, "max": true,
	"repr": true, "str": true, "bool": true, "isinstance": true, "id": true, "hash": true, "type": true,
	"print": true, "zip": true, "map": true, "filter": true,
}

// noteTableWrite records the names whose items the file writes (`T[k] = v`,
// `T[k] += v`, `del T[k]`), changes through a dict method (`T.update(..)`),
// or hands to other code that may write them (addTableWrites): such a
// name is no fixed table, in any scope of the file.
func (fw *pythonFileWalk) noteTableWrite(node *sitter.Node, sym sitter.Symbol, src []byte) {
	var object *sitter.Node
	switch sym {
	case pythonSyms.assignment, pythonSyms.augmentedAssignment:
		if left := node.ChildByFieldName("left"); left != nil && left.Symbol() == pythonSyms.subscript {
			object = left.ChildByFieldName("value")
		}
		// `alias = T`: the alias writes T's items.
		fw.addTableWrites(node.ChildByFieldName("right"), src)
	case pythonSyms.argumentList:
		if !pythonReadOnlyCall(node.Parent(), src) {
			for i := 0; i < int(node.NamedChildCount()); i++ {
				arg := node.NamedChild(i)
				if arg.Symbol() == pythonSyms.keywordArgument {
					arg = arg.ChildByFieldName("value")
				}
				fw.addTableWrites(arg, src)
			}
		}
	case pythonSyms.returnStatement, pythonSyms.yield, pythonSyms.list, pythonSyms.tuple, pythonSyms.set, pythonSyms.expressionList:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			fw.addTableWrites(node.NamedChild(i), src)
		}
	case pythonSyms.pair:
		fw.addTableWrites(node.ChildByFieldName("value"), src)
	case pythonSyms.deleteStatement:
		for i := 0; i < int(node.NamedChildCount()); i++ {
			if target := node.NamedChild(i); target.Symbol() == pythonSyms.subscript {
				fw.addTableWrite(target.ChildByFieldName("value"), src)
			}
		}
	case pythonSyms.call:
		if fn := node.ChildByFieldName("function"); fn != nil && fn.Symbol() == pythonSyms.attribute {
			if attr := fn.ChildByFieldName("attribute"); attr != nil && pythonTableMutators[attr.Content(src)] {
				object = fn.ChildByFieldName("object")
			}
		}
	}
	fw.addTableWrite(object, src)
}

// pythonReadOnlyCall reports a call of a builtin in pythonReadOnlyBuiltins.
func pythonReadOnlyCall(call *sitter.Node, src []byte) bool {
	if call == nil || call.Symbol() != pythonSyms.call {
		return false
	}
	fn := call.ChildByFieldName("function")
	return fn != nil && fn.Symbol() == pythonSyms.identifier && pythonReadOnlyBuiltins[fn.Content(src)]
}

// addTableWrites records the names an expression hands over as its value:
// a name, or one of the names a parenthesized, `and` / `or` or conditional
// expression may evaluate to.
func (fw *pythonFileWalk) addTableWrites(value *sitter.Node, src []byte) {
	if value == nil {
		return
	}
	switch value.Symbol() {
	case pythonSyms.identifier:
		fw.addTableWrite(value, src)
	case pythonSyms.parenthesized, pythonSyms.booleanOperator, pythonSyms.conditionalExpression:
		for i := 0; i < int(value.NamedChildCount()); i++ {
			fw.addTableWrites(value.NamedChild(i), src)
		}
	}
}

func (fw *pythonFileWalk) addTableWrite(object *sitter.Node, src []byte) {
	if object == nil || object.Symbol() != pythonSyms.identifier {
		return
	}
	if fw.tableWrites == nil {
		fw.tableWrites = make(map[string]bool)
	}
	fw.tableWrites[object.Content(src)] = true
}

// tableOf is the dict display name is bound to, when the scope binds the
// name once, to that display, and it is no parameter; known reports that the
// scope binds the name at all.
func (s *pythonLocalSources) tableOf(name string) (table *sitter.Node, known bool) {
	if s == nil {
		return nil, false
	}
	if s.all {
		return nil, true
	}
	e, ok := s.byName[name]
	if !ok {
		return nil, false
	}
	if e.bindings != 1 || e.declared {
		return nil, true
	}
	return e.table, true
}

// pythonTableDisplay is the dict display a subscript's value is: written in
// place, or the one a name of the function, else of the module, is bound to.
// local reports a display the function itself writes or binds.
func pythonTableDisplay(value *sitter.Node, src []byte, bindings pythonBindings, fw *pythonFileWalk) (table *sitter.Node, local bool) {
	value = pythonUnparenthesized(value)
	if value == nil {
		return nil, false
	}
	if value.Type() == pythonNodeDictionary {
		return value, true
	}
	if value.Symbol() != pythonSyms.identifier {
		return nil, false
	}
	name := value.Content(src)
	if fw.tableWrites[name] {
		return nil, false
	}
	if table, known := bindings.locals.tableOf(name); known {
		return table, true
	}
	if pythonNameLocallyShadowed(bindings, fw, name) {
		return nil, false
	}
	table, _ = fw.moduleSources.tableOf(name)
	return table, false
}

// pythonTableSubscript is the source of `table[key]` when table is a
// dispatch table: the value of the entry its key selects, or of each entry
// its keys select, when the key resolves to literals; nil otherwise, but for
// a table the function itself writes or binds, which then may hold the
// value of any of its entries (the may-values of the subscript, not
// exhaustive: the key is not known to be one of the table's). OpenGrep's
// taint reaches such a read from the literals of the display the same way,
// and does not from a module's.
func (p *PythonParser) pythonTableSubscript(node *sitter.Node, src []byte, filePath string, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk, depth int) []SourceNode {
	if depth >= pythonArgProvenanceMaxDepth || node.NamedChildCount() != 2 {
		return nil
	}
	table, local := pythonTableDisplay(node.ChildByFieldName("value"), src, bindings, fw)
	if table == nil {
		return nil
	}
	entries := pythonTableEntries(table, src)
	name := strings.Join(strings.Fields(node.Content(src)), "")
	keys := pythonLiteralValues(p.pythonArgumentSourceFor(node.ChildByFieldName("subscript"), src, filePath, analysis, bindings, fw, depth+1))
	if keys == nil {
		if !local {
			return nil
		}
		return pythonTableMayValues(name, table, src, analysis, bindings, fw)
	}
	var nodes []SourceNode
	for _, key := range keys {
		value := entries[pythonLiteralKey(key)]
		if value == nil {
			continue // no such entry: the read raises
		}
		if fixed, ok := pythonFixedValue(value, false, src, analysis, bindings, fw); ok {
			nodes = append(nodes, fixed)
			continue
		}
		sources := p.pythonArgumentSourceFor(value, src, filePath, analysis, bindings, fw, depth+1)
		if len(sources) == 0 {
			return nil
		}
		nodes = append(nodes, sources...)
	}
	return pythonVariableHolding(name, nodes)
}

// pythonTableMayValues is the VARIABLE of a table read whose key is not
// known: it may hold any fixed value the display writes for an entry (a
// plain string, an integer, a name rooted in an import, as written),
// whatever the entries' keys are. nil when the display writes none.
func pythonTableMayValues(name string, table *sitter.Node, src []byte, analysis *FileAnalysis, bindings pythonBindings, fw *pythonFileWalk) []SourceNode {
	var values []string
	for i := 0; i < int(table.NamedChildCount()); i++ {
		value := table.NamedChild(i).ChildByFieldName("value")
		if value == nil {
			continue // a `**spread`, a comment
		}
		if fixed, ok := pythonFixedValue(value, false, src, analysis, bindings, fw); ok && !slices.Contains(values, fixed.Value) {
			values = append(values, fixed.Value)
		}
	}
	if len(values) == 0 {
		return nil
	}
	return []SourceNode{{Type: sourceNodeVariable, Name: name, MayValues: values}}
}

// pythonTableEntries maps each key of a dict display to its value, the last
// one written for a key. nil when an entry is no `literal: value` pair (a
// `**spread`, a computed key, a comprehension), since any key may then be
// another entry's.
func pythonTableEntries(table *sitter.Node, src []byte) map[string]*sitter.Node {
	entries := make(map[string]*sitter.Node, table.NamedChildCount())
	for i := 0; i < int(table.NamedChildCount()); i++ {
		pair := table.NamedChild(i)
		if pair.Type() == pythonNodeComment {
			continue
		}
		key, value := pair.ChildByFieldName("key"), pair.ChildByFieldName("value")
		if pair.Type() != "pair" || key == nil || value == nil {
			return nil
		}
		switch key.Symbol() {
		case pythonSyms.string:
			if !pythonPlainString(key, src) {
				return nil
			}
		case pythonSyms.integer:
		default:
			return nil
		}
		entries[pythonLiteralKey(key.Content(src))] = value
	}
	return entries
}

// pythonLiteralKey is a literal as a dict key compares it: a plain string
// without its quotes (marked, so "1" is not 1), an integer as written.
func pythonLiteralKey(text string) string {
	if len(text) >= 2 && (text[0] == '"' || text[0] == '\'') && text[len(text)-1] == text[0] {
		return "s:" + text[1:len(text)-1]
	}
	return "i:" + text
}

// pythonLiteralValues are the values sources say an expression holds, all
// of them: a VALUE, the VALUE or VALUEs of a VARIABLE, or its exhaustive
// may-values. nil when it may hold anything else.
func pythonLiteralValues(sources []SourceNode) []string {
	if len(sources) != 1 {
		return nil
	}
	node := &sources[0]
	switch node.Type {
	case sourceNodeValue:
		return []string{node.Value} // a name (`hashes.SHA256`) is no entry's key
	case sourceNodeVariable:
		if node.MayValuesExhaustive {
			return node.MayValues
		}
		var values []string
		for i := range node.SourceNodes {
			value := pythonLiteralValues(node.SourceNodes[i : i+1])
			if value == nil {
				return nil
			}
			values = append(values, value...)
		}
		return values
	}
	return nil
}
