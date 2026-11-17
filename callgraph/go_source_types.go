// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
)

// GoSourceRoot is a tree of Go packages whose exported declarations type the
// scanned code's calls into them: the standard library (Dir is GOROOT/src,
// Module "") or a dependency module (Dir its root, Module its path).
type GoSourceRoot struct {
	Dir    string
	Module string
}

// GoSourceTypeResolver types Go calls from the declarations of the packages
// they call into, as the Java resolver types them from bytecode: a package
// value's type (`base64.StdEncoding`, `crypto.SHA256`) and a function's or
// method's result type. The roots come from the caller; without them only the
// contracts type calls. Contract return types are applied first.
type GoSourceTypeResolver struct {
	contracts *GoContractTypeResolver
	index     *goSourceIndex
}

// NewGoSourceTypeResolver creates a resolver over roots, backed by the
// installed Go contracts KB.
func NewGoSourceTypeResolver(roots []GoSourceRoot) *GoSourceTypeResolver {
	return &GoSourceTypeResolver{
		contracts: NewGoContractTypeResolverFromSource(),
		index:     newGoSourceIndex(roots),
	}
}

// ResolveTypes applies the contracts, then types the calls made on an imported
// package value, and leaves the index on the graph for the passes that type
// receivers bound from a call's result.
func (r *GoSourceTypeResolver) ResolveTypes(graph *CallGraph, packages []PackageDir) error {
	if err := r.contracts.ResolveTypes(graph, packages); err != nil {
		return err
	}
	graph.goSourceTypes = r.index
	for callerKey, fn := range graph.Functions {
		oldKeys := map[string]bool{}
		for i := range fn.Calls {
			call := &fn.Calls[i]
			if call.GoPackageValue == "" || call.Callee.Type != "" {
				continue
			}
			pkg, name := splitQualifiedTypeName(call.GoPackageValue)
			typ := r.index.valueType(pkg, name)
			if typ == "" {
				continue
			}
			oldKeys[call.Callee.String()] = true
			call.Callee = goMethodOn(graph, typ, call.Callee.Name)
			addCaller(graph.Callers, call.Callee.String(), callerKey)
			recordCallEdgeResolution(graph, callerKey, call.Callee.String(), EdgeKindExact, "", call)
		}
		reconcileRewrittenCallers(graph, callerKey, fn, oldKeys)
	}
	return nil
}

// goMethodOn is the identity of method name on a value of typ (`*pkg.T` or
// `pkg.T`), spelled as its declaration is when the graph has one.
func goMethodOn(graph *CallGraph, typ, name string) FunctionID {
	core, ptr := strings.TrimLeft(typ, "*"), ""
	if strings.HasPrefix(typ, "*") {
		ptr = "*"
	}
	pkg, t := splitQualifiedTypeName(core)
	id := FunctionID{Package: pkg, Type: ptr + t, Name: name}
	if _, ok := graph.Functions[id.String()]; !ok {
		toggled := "*" + t
		if ptr != "" {
			toggled = t
		}
		if other := (FunctionID{Package: pkg, Type: toggled, Name: name}); graph.Functions[other.String()] != nil {
			return other
		}
	}
	return id
}

// goSourceIndex reads a package's exported declarations the first time a call
// names it.
type goSourceIndex struct {
	roots    []GoSourceRoot
	mu       sync.Mutex
	packages map[string]*goSourcePackage
}

// goSourcePackage holds one package's exported value types and result types,
// each written `[*]<import path>.<Type>`; "" for a builtin or untraced type.
type goSourcePackage struct {
	types   map[string]bool              // declared type names
	values  map[string]string            // package-level var or const -> type
	funcs   map[string]string            // function -> first result type
	methods map[string]map[string]string // receiver type (no *) -> method -> first result type
}

func newGoSourceIndex(roots []GoSourceRoot) *goSourceIndex {
	return &goSourceIndex{roots: roots, packages: map[string]*goSourcePackage{}}
}

func (x *goSourceIndex) valueType(pkg, name string) string {
	if p := x.pkg(pkg); p != nil {
		return p.values[name]
	}
	return ""
}

// resultType is the first result type of a call to callee, a function or a
// method keyed `pkg.(T).M` / `pkg.(*T).M`.
func (x *goSourceIndex) resultType(callee FunctionID) string {
	if x == nil || callee.Package == "" {
		return ""
	}
	p := x.pkg(callee.Package)
	if p == nil {
		return ""
	}
	name := BaseFunctionName(callee.Name)
	if callee.Type == "" {
		return p.funcs[name]
	}
	return p.methods[strings.TrimLeft(callee.Type, "*")][name]
}

func (x *goSourceIndex) pkg(path string) *goSourcePackage {
	if x == nil || path == "" {
		return nil
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	if p, ok := x.packages[path]; ok {
		return p
	}
	var p *goSourcePackage
	if dir := x.dirOf(path); dir != "" {
		p = parseGoSourcePackage(dir, path)
	}
	x.packages[path] = p
	return p
}

// dirOf is the directory of import path under the roots, or "".
func (x *goSourceIndex) dirOf(path string) string {
	for _, root := range x.roots {
		rel := path
		if root.Module != "" {
			if path != root.Module && !strings.HasPrefix(path, root.Module+"/") {
				continue
			}
			rel = strings.TrimPrefix(strings.TrimPrefix(path, root.Module), "/")
		}
		dir := filepath.Join(root.Dir, filepath.FromSlash(rel))
		if info, err := os.Stat(dir); err == nil && info.IsDir() {
			return dir
		}
	}
	return ""
}

func parseGoSourcePackage(dir, path string) *goSourcePackage {
	p := &goSourcePackage{types: map[string]bool{}, values: map[string]string{}, funcs: map[string]string{}, methods: map[string]map[string]string{}}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return p
	}
	fset := token.NewFileSet()
	type pendingValue struct {
		name  string
		value ast.Expr
		file  map[string]string
	}
	var pending []pendingValue
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, parser.SkipObjectResolution)
		if err != nil {
			continue
		}
		imports := goFileImports(f)
		for _, decl := range f.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if !d.Name.IsExported() || d.Type.Results == nil || len(d.Type.Results.List) == 0 {
					continue
				}
				result := goSourceTypeText(d.Type.Results.List[0].Type, path, imports)
				if d.Recv == nil || len(d.Recv.List) == 0 {
					p.funcs[d.Name.Name] = firstNonEmpty(p.funcs[d.Name.Name], result)
					continue
				}
				recv := strings.TrimLeft(goSourceTypeText(d.Recv.List[0].Type, path, imports), "*")
				if _, t := splitQualifiedTypeName(recv); t != "" {
					if p.methods[t] == nil {
						p.methods[t] = map[string]string{}
					}
					p.methods[t][d.Name.Name] = firstNonEmpty(p.methods[t][d.Name.Name], result)
				}
			case *ast.GenDecl:
				if d.Tok == token.TYPE {
					for _, spec := range d.Specs {
						if ts, ok := spec.(*ast.TypeSpec); ok {
							p.types[ts.Name.Name] = true
						}
					}
					continue
				}
				if d.Tok != token.VAR && d.Tok != token.CONST {
					continue
				}
				var inherited string
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					typ := goSourceTypeText(vs.Type, path, imports)
					switch {
					case typ != "":
						inherited = typ
					case d.Tok == token.CONST && vs.Type == nil && len(vs.Values) == 0:
						typ = inherited // an iota group repeats the previous spec's type
					default:
						inherited = ""
					}
					for i, n := range vs.Names {
						if !n.IsExported() {
							continue
						}
						if typ != "" {
							p.values[n.Name] = firstNonEmpty(p.values[n.Name], typ)
						} else if i < len(vs.Values) {
							pending = append(pending, pendingValue{n.Name, vs.Values[i], imports})
						}
					}
				}
			}
		}
	}
	// A value with no stated type takes the type its initializer builds:
	// `&T{}`, `T{}`, `T(x)`, or a call of a function of this package.
	for _, v := range pending {
		if typ := goSourceValueType(v.value, path, v.file, p); typ != "" {
			p.values[v.name] = firstNonEmpty(p.values[v.name], typ)
		}
	}
	return p
}

func goSourceValueType(e ast.Expr, path string, imports map[string]string, p *goSourcePackage) string {
	switch v := ast.Unparen(e).(type) {
	case *ast.CompositeLit:
		return goSourceTypeText(v.Type, path, imports)
	case *ast.UnaryExpr:
		if v.Op == token.AND {
			if inner := goSourceValueType(v.X, path, imports, p); inner != "" && !strings.HasPrefix(inner, "*") {
				return "*" + inner
			}
		}
	case *ast.CallExpr:
		switch fn := ast.Unparen(v.Fun).(type) {
		case *ast.Ident:
			if p.types[fn.Name] && len(v.Args) == 1 {
				return path + "." + fn.Name // a conversion T(x)
			}
			return p.funcs[fn.Name]
		}
	}
	return ""
}

// goFileImports maps a file's import names to their paths.
func goFileImports(f *ast.File) map[string]string {
	out := map[string]string{}
	for _, s := range f.Imports {
		path, err := strconv.Unquote(s.Path.Value)
		if err != nil {
			continue
		}
		name := GoImplicitImportName(path)
		if s.Name != nil {
			name = s.Name.Name
		}
		out[name] = path
	}
	return out
}

// goSourceTypeText writes a named type `[*]<import path>.<Type>` (type
// arguments dropped); "" for a builtin, an unexported type of another package,
// or any other type expression.
func goSourceTypeText(e ast.Expr, path string, imports map[string]string) string {
	switch t := e.(type) {
	case *ast.StarExpr:
		if inner := goSourceTypeText(t.X, path, imports); inner != "" {
			return "*" + inner
		}
	case *ast.Ident:
		if t.IsExported() || goSourceLocalTypeLike(t.Name) {
			return path + "." + t.Name
		}
	case *ast.SelectorExpr:
		if id, ok := t.X.(*ast.Ident); ok && imports[id.Name] != "" {
			return imports[id.Name] + "." + t.Sel.Name
		}
	case *ast.IndexExpr:
		return goSourceTypeText(t.X, path, imports)
	case *ast.IndexListExpr:
		return goSourceTypeText(t.X, path, imports)
	case *ast.ParenExpr:
		return goSourceTypeText(t.X, path, imports)
	}
	return ""
}

// goSourceLocalTypeLike: an unexported identifier that is not a predeclared
// type still names a type of the package (a method set reached through an
// exported value of that type).
func goSourceLocalTypeLike(name string) bool {
	switch name {
	case "bool", "byte", "complex64", "complex128", "error", "float32", "float64", "int", "int8", "int16",
		"int32", "int64", "rune", "string", "uint", "uint8", "uint16", "uint32", "uint64", "uintptr", "any",
		"comparable":
		return false
	}
	return name != "" && name != "_"
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// goReceiverTypeOf keeps a result type a method can be called on: a named
// type of a package, not a builtin.
func goReceiverTypeOf(typ string) string {
	core := strings.TrimLeft(typ, "*")
	if pkg, t := splitQualifiedTypeName(core); pkg == "" || t == "" {
		return ""
	}
	return typ
}
