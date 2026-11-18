// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"fmt"
	"sort"

	sitter "github.com/smacker/go-tree-sitter"
)

// node_function_keys.go keeps every function of one Node module under a key
// of its own. A function is keyed by module, class and name, and JavaScript
// lets two functions of one module share all three: `hotp.gen = function`
// and `totp.gen = function` are both gen, as are two `return function sign`
// in different factories. The graph holds one function per key, so without
// this the first one's calls were dropped.
//
// Only functions that collide change key, so a module without such a pair
// keys exactly as before:
//
//   - A function assigned as a property of a plain identifier (`hotp.gen =
//     function`) is keyed by that object as its owner, `m.(hotp).gen`, the
//     key `var hotp = { gen: function }` gives it. A member call on the
//     module binding (`hotp.gen(key)`) then targets hotp's.
//   - Of the functions still sharing a key, the last module-level one (else
//     the last one) keeps it: that is the function the graph held before.
//     Each other one takes its start as a suffix, `sign@131:10`, the scheme
//     `<anonymous>@12:5` uses: `@` is in no JavaScript identifier, so the
//     key collides with no declared name.

// nodeDeclPos is where a function's node starts: its decl's StartLine and
// StartCol, unique within a module.
type nodeDeclPos struct {
	line, col int
}

// nodeFunctionKeys is the outcome of disambiguating one module.
type nodeFunctionKeys struct {
	// ids is the identity each renamed function takes, by start.
	ids map[nodeDeclPos]FunctionID
	// objectMethods lists, by owner object, the names it now owns
	// (`hotp` -> gen), for the member calls on that object.
	objectMethods map[string]map[string]bool
}

// nodePropertyOwner returns the plain identifier a function is assigned as a
// property of (`hotp` for `hotp.gen = function`), or "" for an export
// (`exports.f`, `module.exports.f`), `this`, a prototype or a deeper path.
func nodePropertyOwner(left *sitter.Node, src []byte) string {
	if left == nil || left.Type() != nodeMemberExpression {
		return ""
	}
	object := left.ChildByFieldName("object")
	if object == nil || object.Type() != goNodeIdentifier {
		return ""
	}
	switch name := object.Content(src); name {
	case "exports", "module":
		return ""
	default:
		return name
	}
}

// disambiguateNodeFunctions decides a key of its own for every function of
// a module that shares one, as the file comment describes. It returns nil
// when no two functions collide.
func disambiguateNodeFunctions(functions []FunctionDecl) *nodeFunctionKeys {
	ids := make([]FunctionID, len(functions))
	for i := range functions {
		ids[i] = functions[i].ID
	}
	groups := nodeCollidingGroups(functions, ids)
	if len(groups) == 0 {
		return nil
	}
	out := &nodeFunctionKeys{ids: make(map[nodeDeclPos]FunctionID), objectMethods: make(map[string]map[string]bool)}
	for _, group := range groups {
		for _, i := range group {
			owner := functions[i].nodePropertyOwner
			if owner == "" || ids[i].Type != "" {
				continue
			}
			ids[i].Type = owner
			if out.objectMethods[owner] == nil {
				out.objectMethods[owner] = make(map[string]bool)
			}
			out.objectMethods[owner][ids[i].Name] = true
		}
	}
	for _, group := range nodeCollidingGroups(functions, ids) {
		keeper := group[len(group)-1]
		for _, i := range group {
			if !functions[i].nodeNested {
				keeper = i
			}
		}
		for _, i := range group {
			if i != keeper {
				ids[i].Name = fmt.Sprintf("%s@%d:%d", ids[i].Name, functions[i].StartLine, functions[i].StartCol)
			}
		}
	}
	for i := range functions {
		if ids[i] != functions[i].ID {
			out.ids[nodeDeclPos{line: functions[i].StartLine, col: functions[i].StartCol}] = ids[i]
		}
	}
	return out
}

// nodeCollidingGroups lists, in source order, the indexes of the functions
// that share a key under ids. The synthetic <module> and <clinit> functions
// are left out: the parser declares at most one per owner.
func nodeCollidingGroups(functions []FunctionDecl, ids []FunctionID) [][]int {
	byKey := make(map[FunctionID][]int)
	for i := range functions {
		if ids[i].Name == moduleInitMethodName || ids[i].Name == clinitMethodName {
			continue
		}
		byKey[ids[i]] = append(byKey[ids[i]], i)
	}
	var groups [][]int
	for _, group := range byKey {
		if len(group) < 2 {
			continue
		}
		sort.Slice(group, func(a, b int) bool {
			fa, fb := &functions[group[a]], &functions[group[b]]
			if fa.StartLine != fb.StartLine {
				return fa.StartLine < fb.StartLine
			}
			return fa.StartCol < fb.StartCol
		})
		groups = append(groups, group)
	}
	sort.Slice(groups, func(a, b int) bool { return groups[a][0] < groups[b][0] })
	return groups
}

// renamedNodeFunction applies the key disambiguation chose for decl, if any.
// A function an object now owns is a method of it, as an object literal's
// function is.
func (p *NodeParser) renamedNodeFunction(decl *FunctionDecl) {
	if p.keys == nil {
		return
	}
	id, ok := p.keys.ids[nodeDeclPos{line: decl.StartLine, col: decl.StartCol}]
	if !ok {
		return
	}
	if id.Type != "" && decl.ID.Type == "" {
		decl.OwnerType = ownerTypeClass
		decl.OwnerName = id.Type
		decl.FunctionType = javaFunctionTypeMethod
	}
	decl.ID = id
}

// objectMethodReceiver reports whether a member call `object.name()` made on
// a module binding targets the function the object owns by disambiguation.
func (p *NodeParser) objectMethodReceiver(object, name string) bool {
	return p.keys != nil && p.keys.objectMethods[object][name] && !p.scope.declares(object)
}
