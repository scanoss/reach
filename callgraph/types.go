// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

// Package callgraph provides function-level call graph construction and
// backward tracing for linking cryptographic findings in dependencies
// back to user code entry points.
package callgraph

import (
	"fmt"
	"strconv"
	"strings"
)

const constructorMethodName = "<init>"

const fieldExpressionNode = "field_expression"

// clinitMethodName names the synthetic function that represents a Java class's
// static initialization context — its `static { ... }` blocks and its
// initialized static `field_declaration` values. Mirrors the JVM `<clinit>`
// method. Reused by the Python parser for its own class-body synthetic decl
// (calls made directly in a class body, outside any method), for
// cross-language consistency and because callers already special-case the
// `<clinit>` name (e.g. builder.go's virtual-dispatch fan-out suppression).
const clinitMethodName = "<clinit>"

// functionTypeClassInit is the FunctionDecl.FunctionType value for a
// `<clinit>` synthetic decl. Shared across languages (previously
// Java-only as javaFunctionTypeClassInit).
const functionTypeClassInit = "class-init"

// moduleInitMethodName names the synthetic function that represents a
// Python module's load-time execution context — its direct module-level
// statements. Mirrors CPython's own module code-object name. Python-only;
// no Java/Go/Rust/C/C++/Node equivalent exists.
const moduleInitMethodName = "<module>"

// functionTypeModuleInit is the FunctionDecl.FunctionType value for a
// `<module>` synthetic decl.
const functionTypeModuleInit = "module-init"

// Java visibility values exported in call graph metadata.
const (
	VisibilityPublic         = "public"
	VisibilityProtected      = "protected"
	VisibilityPrivate        = "private"
	VisibilityPackagePrivate = "package-private"
)

// TypeResolver provides language-specific type resolution capabilities.
// Each language implements this using its best-fit approach (bytecode analysis,
// go/types, type stubs, LSP, etc.). The builder calls it after tree-sitter
// parsing to enrich the call graph with full type information.
type TypeResolver interface {
	// ResolveTypes enriches function declarations and calls in the graph with
	// type information that tree-sitter alone cannot provide. It receives the
	// full graph and the source/artifact directories, and modifies calls in-place.
	ResolveTypes(graph *CallGraph, sourceRoots []PackageDir) error
}

// StrictResolver reports whether resolver failures should fail the graph build
// instead of being downgraded to a warning.
type StrictResolver interface {
	StrictFailure() bool
}

// TypeRef describes a type reference, optionally carrying nested generic
// parameters. Name holds the erased type name (e.g. "Map", "byte[]"), while
// GenericParameters captures parametrized type arguments recursively (e.g.
// Map<String, List<Foo>> → Name="Map", GenericParameters=[
//
//	{Name:"String"},
//	{Name:"List", GenericParameters:[{Name:"Foo"}]}]).
type TypeRef struct {
	Name              string
	GenericParameters []TypeRef
}

// HasGenerics reports whether the TypeRef carries any generic parameters.
func (t TypeRef) HasGenerics() bool {
	return len(t.GenericParameters) > 0
}

func cloneTypeRef(t TypeRef) TypeRef {
	return TypeRef{
		Name:              t.Name,
		GenericParameters: cloneTypeRefs(t.GenericParameters),
	}
}

func cloneTypeRefs(refs []TypeRef) []TypeRef {
	if len(refs) == 0 {
		return nil
	}
	out := make([]TypeRef, len(refs))
	for i, r := range refs {
		out[i] = cloneTypeRef(r)
	}
	return out
}

// ExternalMethodSignature stores resolver-derived signature data for methods that
// may not have a source-backed FunctionDecl in the graph.
type ExternalMethodSignature struct {
	ParameterTypes    []string
	ReturnType        string
	ParameterTypeRefs []TypeRef
	ReturnTypeRef     TypeRef
}

// JavaPlatformSignatureMetadata records whether Java platform signatures from a
// pinned runtime were available and used during type enrichment.
type JavaPlatformSignatureMetadata struct {
	RequestedMajor    string
	RuntimeVersion    string
	SignaturesUsed    bool
	SignatureSource   string
	UnavailableReason string
}

// BaseFunctionName strips the Java/Go arity suffix and any overload decoration
// from a function name.
// For example, "encrypt#1" returns "encrypt", and
// "signWith#2$SignatureAlgorithm,byte[]" returns "signWith".
func BaseFunctionName(name string) string {
	arityKey := methodArityKey(name)
	idx := strings.Index(arityKey, "#")
	if idx <= 0 {
		return name
	}
	return arityKey[:idx]
}

// methodArityKey extracts the stable "<name>#<arity>" prefix from a decorated
// function name. If the name is not arity-qualified, it returns the original
// input unchanged.
func methodArityKey(name string) string {
	idx := strings.Index(name, "#")
	if idx <= 0 || idx >= len(name)-1 {
		return name
	}

	j := idx + 1
	for j < len(name) && name[j] >= '0' && name[j] <= '9' {
		j++
	}
	if j == idx+1 {
		return name
	}
	return name[:j]
}

// FunctionID uniquely identifies a function or method across packages.
type FunctionID struct {
	// Package is the full package/module path (e.g., "crypto/aes" or "javax.crypto")
	Package string
	// Type is the owning type for methods (Go: receiver like "*Block", Java: class like "Cipher").
	// Empty for plain functions.
	Type string
	// Name is the function/method name (e.g., "NewCipher")
	Name string
	// Linkage records C symbol linkage; empty for other ecosystems and unknown calls.
	Linkage Linkage
}

// Linkage distinguishes externally linked C globals from translation-unit-local symbols.
type Linkage string

const (
	// LinkageExternal marks a C symbol visible beyond its translation unit.
	LinkageExternal Linkage = "external"
	// LinkageInternal marks a C symbol scoped to one translation unit.
	LinkageInternal Linkage = "internal"
)

// String renders the key, arity suffix included: "package.(Type).Name#1" for
// a method, "package.Name#1" for a function. An empty package contributes
// nothing, not a leading separator: a scan root that no manifest names keys
// its symbols as "(Benchmark)._random_bytes" and "main", and an unanchored
// call whose receiver never resolved keys as its bare name.
func (f FunctionID) String() string {
	key := f.Name
	if f.Type != "" {
		key = "(" + f.Type + ")." + f.Name
	}
	if f.Package == "" {
		return key
	}
	return f.Package + "." + key
}

// InferredReturn carries the result of static return-type inference for a function.
// Fields mirror what the export layer surfaces, plus the internal-only join-failed origin.
// The join-failed origin is never emitted in exported output; when a join fails the
// entire field is omitted.
type InferredReturn struct {
	// Type is the inferred fully-qualified return type name, e.g. "javax.crypto.SecretKey".
	Type string
	// TypeRef is the structured generic form when applicable; zero value when none.
	TypeRef TypeRef
	// Confidence is the inference confidence level: "high", "medium", or "low".
	Confidence string
	// Origin is one of: "constructor", "kb-direct", "kb-conditional", "propagated",
	// or the internal-only "join-failed" (never exported).
	Origin string
	// Provenance is the recursive provenance chain (subset of ReturnSources, normalised).
	Provenance []SourceNode
}

// FunctionDecl represents a function or method declaration with its location and outgoing calls.
type FunctionDecl struct {
	ID        FunctionID
	FilePath  string
	StartLine int
	EndLine   int
	// StartCol and EndCol are the 1-based columns of the span's first
	// character on StartLine and one past its last on EndLine, read from the
	// parser's node. Zero means the parser is not column-aware or the span is
	// synthetic; containment then falls back to lines alone.
	StartCol     int
	EndCol       int
	OwnerType    string
	OwnerName    string
	FunctionType string
	ReturnType   string
	// QualifiedReturnType is ReturnType resolved to fully qualified names
	// through the declaring file's imports, in the FunctionParameter
	// QualifiedType format. Empty when not resolved (Java methods only).
	QualifiedReturnType string
	// Static reports a method declared static, which never dispatches
	// virtually (Java only).
	Static bool
	// Abstract reports a method declared without a body: an interface
	// method that is not default or static, or an abstract method (Java
	// only; a native method has a body, outside the source). Every call
	// that reaches it runs an override instead.
	Abstract bool
	// Annotations holds the simple names of the annotations the declaration
	// carries, as "Override" (Java methods; C# attributes without their
	// Attribute suffix, as "NonAction"). Read to recognize functions
	// a framework calls, which no call edge in the graph leads to.
	Annotations []string
	// EntryKind is set when a parser recognizes the declaration as an entry
	// point that a framework or the runtime calls, which no call edge in the
	// graph leads to. entryMark reads it first.
	EntryKind RootKind
	// EntryRule is the ID of the catalog entry that set EntryKind, or empty
	// when language semantics set it (main, an init function).
	EntryRule string
	// ImplicitCalls are calls the source makes without a call expression: a
	// JSX element renders its component, a function written inline as an
	// argument runs when the call it is passed to runs (Node), and a function
	// handed out as a value is referenced (FunctionCall.Reference). They
	// become call edges like Calls, but are kept apart so that finding
	// attribution, which matches a crypto call by its position, never picks
	// one.
	ImplicitCalls []FunctionCall
	// returnedTypes holds the types of the package a Go function returns as
	// &T{}, T{} or new(T), as T: the concrete types behind a constructor that
	// declares an interface result.
	returnedTypes []string
	// boundNames holds every name the declaration binds anywhere in its
	// span, nested closures included (Python only): a callback argument with
	// one of these names is not known to be the module function it spells.
	boundNames map[string]bool
	// pythonStatic marks a @staticmethod: its first parameter is no instance
	// (Python only).
	pythonStatic bool
	// pythonAsync marks an `async def`: calling it returns a coroutine, and
	// only awaiting that yields the annotated return type (Python only).
	pythonAsync bool
	// pythonReturn is the class the return annotation names, resolved where
	// the function is declared (pythonAnnotationClass); zero when it names
	// none (Python only).
	pythonReturn pythonClassRef
	// FileTypeNamesAtRisk is the declaring file's FileAnalysis.TypeNamesAtRisk,
	// shared by every declaration of the file (Java only).
	FileTypeNamesAtRisk map[string]bool
	ReturnTypeRef       TypeRef
	Visibility          string
	OwnerVisibility     string
	// TypeParamBounds maps the declaring class's generic type-parameter names
	// to their erased first bound ("Object" when unbounded). Used to build the
	// erased signature consumers join on (Java only).
	TypeParamBounds map[string]string
	Parameters      []FunctionParameter
	Calls           []FunctionCall
	// ConstantRefs are the qualified constants the body references, at any
	// position (Java and Python).
	ConstantRefs []ConstantRef
	// AttributeStores are the body's assignments to an attribute of an
	// object (Python only).
	AttributeStores []AttributeStore
	// LocalBindings are the bindings of the locals the body binds more than
	// once with a call among the values (Python only).
	LocalBindings []LocalBinding
	// Declarations are the local variables and fields the body declares, and
	// Casts its cast expressions (Java; Python's annotated assignments and
	// typing.cast calls; C and C++ local declarations).
	Declarations []VarDecl
	Casts        []CastExpr
	// WrittenParameters are the function's parameters as the source writes
	// them, type text, name and span (C++ only, graph-algo-cpp-3).
	WrittenParameters []WrittenParameter
	// nodeReturnClass is the class a Node function declares as its return
	// type, `function make(): Base`, when that is a plain class of the project.
	nodeReturnClass FunctionID
	// nodePropertyOwner is the object a Node function is assigned as a
	// property of (`hotp` for `hotp.gen = function`), and nodeNested whether
	// it is declared inside another function: what disambiguateNodeFunctions
	// reads when two functions of a module share a key.
	nodePropertyOwner string
	nodeNested        bool
	// constructed is what the function's own return statements yield as
	// objects (see returnedObjects), for resolveConstructedReceivers.
	constructed returnedObjects
	// localBindings counts how many times the body binds each local name
	// (see countLocalBindings), for resolveConstructedReceivers.
	localBindings map[string]int
	// ReturnSources traces where return values originate when the parser supports it.
	ReturnSources []SourceNode
	// InferredReturn is the result of the post-build inference pass; nil when no inference fires.
	InferredReturn *InferredReturn
	// OwnerBases holds the direct base class names as declared in the source
	// (e.g. ["PKey"] for "class RSAKey(PKey):"). Populated by the Python parser;
	// always nil for Java/Go/Rust declarations. Used by expandPythonSubclassDispatch
	// to expand a base-class call site to its concrete subclass overrides.
	OwnerBases []string
	// cpp is what a C++ definition declares about its result and linkage,
	// for resolveCPPCalls; nil for other ecosystems.
	cpp *cppFunctionFacts
	// OwnerTraits holds the trait an `impl <Trait> for <Type>` block implements,
	// with the path resolved through the file's imports
	// (e.g. ["pkcs8::EncodePrivateKey"] for `impl EncodePrivateKey for MyKey`
	// under `use pkcs8::EncodePrivateKey;`). Populated by the Rust parser only;
	// nil for an inherent `impl <Type>` block and for every other ecosystem.
	//
	// Deliberately NOT folded into OwnerBases: that field feeds Python subclass
	// dispatch and the fragment export's type-hierarchy recovery, and a Rust
	// trait is not a base class. This one is read only where a method's OWNING
	// CRATE matters — a method declared in `impl <CrateTrait> for <LocalType>`
	// is the crate's API even though the receiver type is local.
	OwnerTraits []string
	// ModuleVars names the module-scope variables the function's calls use as
	// receivers without declaring them itself, as `ec` in a function that calls
	// the `ec` its module binds with `const ec = new EC(..)`. Populated by the
	// Node parser only, so the receiver typing pass can seed exactly those names
	// with the module's types and never a local that shadows one.
	ModuleVars []string
}

// FunctionParameter describes a declared function parameter.
type FunctionParameter struct {
	Type    string
	TypeRef TypeRef
	// QualifiedType is the fully qualified erased type the parser resolved for
	// Type through the file's imports and declarations, without array
	// brackets. Where the file's imports leave it open, the possible names
	// are listed in Java's lookup order separated by "|". Empty for
	// primitives and for parsers that do not resolve it (Java only).
	QualifiedType string
	// QualifiedInSource reports that the source spelled the type fully
	// qualified (java.io.File), so QualifiedType is certain.
	QualifiedInSource bool
	// Name is the declared parameter name (e.g. "hashingFunction"), when the
	// parser captures it (1.6+ / Java only as of introduction). Empty for
	// ecosystems whose parser does not populate it — callers that key off Name
	// (e.g. parameter pass-through dispatch resolution) simply find no match and
	// degrade to the prior behavior.
	Name string
}

// GoFieldReceiver names the struct field a Go method call goes through.
type GoFieldReceiver struct {
	Owner FunctionID
	Name  string
	// Part selects which type of the field the call's receiver has: the field
	// itself (zero), or the element or key of a slice, array or map field that
	// a range variable or an index expression yields.
	Part GoFieldPart
}

// GoFieldPart names the component of a struct field a receiver is typed by.
type GoFieldPart int

const (
	// GoFieldWhole types the receiver by the field itself.
	GoFieldWhole GoFieldPart = iota
	// GoFieldElem types it by the element (the value, for a map).
	GoFieldElem
	// GoFieldKey types it by the key of a map field.
	GoFieldKey
)

// GoFieldType is a struct field's declared type, qualified by package path.
type GoFieldType struct {
	Package string
	Type    string // pointer prefix kept, type arguments never present
	// ElemPackage and ElemType type the elements of a slice, array or map
	// field (the values, for a map); KeyPackage and KeyType type a map's keys.
	// Type is empty for such a field.
	ElemPackage string
	ElemType    string
	KeyPackage  string
	KeyType     string
}

// FunctionCall represents a call expression within a function body.
type FunctionCall struct {
	// CandidateModules lists, sorted and unique, the module specifiers a Node
	// member call's receiver may hold the member from when the receiver is,
	// or is a chain headed by (`H.sha256.create()`), a variable bound to an
	// object that merges several modules
	// (`Object.assign({}, require('a'), require('b'))`, `{ ...a, ...b }`). The
	// key stays caller-local, since it cannot name one module; the candidates
	// are the modules the receiver may hold the member from. Nil otherwise.
	CandidateModules []string
	// StaticReceiver reports a call qualified by a type name
	// (TikaInputStream.get(..)), which binds at compile time and never
	// dispatches to a subtype (Java only).
	StaticReceiver bool
	// RubySelfClassReceiver marks a call whose receiver is `self.class`:
	// the class-side method of the class the caller is declared in.
	RubySelfClassReceiver bool
	// RubyDispatchCandidate marks one of the declarations a Ruby call on a
	// receiver nothing types may run (`@algorithm.sign`). Each is an edge
	// the graph guesses, never one it resolved, so each is name-only.
	RubyDispatchCandidate bool
	// RubySelfCandidate marks a call Ruby spells as a bare word, which the
	// grammar cannot tell from a local read: it becomes an edge only where
	// the caller's own class declares the method (resolveRubyLocalCalls),
	// and is dropped otherwise.
	RubySelfCandidate bool
	// Callee is the resolved target function
	Callee FunctionID
	// FieldReceiver is set for a Go call through a struct field of a typed
	// root, `r.cache.Get()`: Owner is the root's type (package and possibly
	// pointer-spelled type) and Name the field. Callee stays untyped until the
	// builder reads the field's declared type from the graph-wide struct table.
	FieldReceiver *GoFieldReceiver
	// GoPackageValue is set for a Go call on an imported package value,
	// `base64.StdEncoding.Strict()`: the value as `<import path>.<Name>`.
	// Callee stays untyped until a GoSourceTypeResolver reads its type.
	GoPackageValue string
	// ResolvedReceiverType is the concrete type inferred for a field receiver
	// when its declaring class has one unambiguous constructor assignment.
	// Empty means the receiver type is declared, unknown, or ambiguous.
	ResolvedReceiverType string
	// OwnerAlternatives lists every fully qualified type Callee's owner can
	// denote when the parser had to guess it: an unqualified name the file
	// neither imports by name nor declares, in a file with on-demand imports.
	// The file's own package comes first, then each on-demand import in source
	// order. Nil when the owner is certain (Java only).
	OwnerAlternatives []string
	// ReceiverVar preserves the original receiver variable name for selector calls
	// like `cipher.Encrypt()` when static type information is incomplete. For a
	// C free-function call it is the handle variable passed first, as in
	// `EVP_DigestUpdate(ctx, ...)` or `crypto_generichash_update(&state, ...)`.
	ReceiverVar string
	// ReceiverBoundOnce reports that ReceiverVar is bound exactly once in the
	// enclosing function and that binding is in scope at this call (Go
	// selector calls on a local only). Only then does the call that produced
	// the variable say what value it holds here.
	ReceiverBoundOnce bool
	// AssignedVar is the local variable this call's result is bound to, e.g.
	// "digest" in `SHA3Digest digest = new SHA3Digest(256)`. Empty when the call
	// result is not assigned to a variable. For fluent chains only the chain root
	// (the outermost call) carries AssignedVar. Used to resolve the identity of a
	// crypto object when deriving its lifecycle/supporting calls.
	AssignedVar string
	// ChainID groups the links of a single fluent method chain such as
	// `Password.hash(p).addRandomSalt().withBcrypt()`. All invocations belonging
	// to the same chain share a non-empty ChainID; standalone calls leave it
	// empty. Used to enumerate the supporting links of a chain-rooted finding.
	ChainID string
	// Raw is the raw call expression text (e.g., "aes.NewCipher")
	Raw string
	// FilePath is the file containing this call
	FilePath string
	// Line is the line number of the call
	Line int
	// StartCol is the 1-based start column (inclusive) of this call expression.
	// 0 when the parser is not column-aware — triggers line-only fallback.
	// Converted from tree-sitter 0-based columns at the parser boundary by +1.
	StartCol int
	// EndCol is the 1-based end column (exclusive) of this call expression.
	// 0 when unknown. Mirrors the opengrep/semgrep convention: exclusive end.
	EndCol int
	// EndLine is the line the call expression ends on, EndCol's line. 0 when
	// unknown; equal to Line for a call written on one line.
	EndLine int
	// Reference marks an implicit call that is only the registration of a
	// function as a value (a callback handed to an API that runs it). The
	// builder indexes it as an exact edge only when Callee names a declared
	// function, and expands no dispatch from it.
	Reference bool
	// pythonImport marks a Python import-time edge (python_import_time.go):
	// indexed as one exact edge, with none of a call's dispatch.
	pythonImport bool
	// pythonClassValue marks a Python class read as a value
	// (python_class_values.go): indexed as one name_only edge to the class
	// object, `pkg.(K).<class>`.
	pythonClassValue bool
	// ASTKind is the tree-sitter node kind of this call expression.
	ASTKind string
	// NamedASTPath is this call's named-node path relative to its containing function.
	NamedASTPath string
	// Arguments are the raw argument expressions passed in this invocation.
	Arguments []string
	// ArgumentSources traces where each argument value comes from.
	// Parallel to Arguments — same indices. Populated by the parser's data flow analysis.
	ArgumentSources [][]SourceNode
	// nodeInstanceKey names the export of a project module that the receiver
	// of a Node call imports, `module.name` or `module.default`. The builder
	// replaces the callee when that export is an instance of a class.
	nodeInstanceKey string
	// nodeReturnOf names the project function whose result a Node call's
	// receiver holds; the callee takes that function's declared return class.
	nodeReturnOf FunctionID
	// nodeNewOf is the constructor call of the `new` expression a Node member
	// call or read is made directly on, `new m.X(p).verify()`, when nothing
	// typed it: the KB types the instance as it types a variable the
	// constructor call is assigned to.
	nodeNewOf *FunctionCall
	// nodeUnboundMember marks a Node member call `<expr>.name(..)` whose
	// receiver is neither an import, `this` in a class, nor a typed value. The
	// callee keeps the bare name so contracts can still match it, but it names
	// no function of the module: while Callee.Type stays empty the caller index
	// draws no edge to a same-named module function.
	nodeUnboundMember bool
	// nodeUnresolved marks a Node member call nothing typed: no import,
	// class or contract bound it and the value flow found no function its
	// receiver's values name (NodeCallUntyped, node_untyped.go).
	nodeUnresolved bool
	// pythonOwner is the caller's own class (qualified, in the callee's
	// module) for a Python call the method resolution order settles:
	// `self.m()` and `cls.m()` (callee `(Class).m`), `cls(...)` (callee
	// `(Class).<init>`) and `super().m()` (pythonSuper set). The builder points
	// the callee at the class of the order that declares the method
	// (python_mro.go).
	pythonOwner string
	// pythonSuper marks a pythonOwner call made through super(): the search
	// starts after the caller's own class.
	pythonSuper bool
	// pythonUntyped is the key the parser gave a Python call it could not
	// type: a method on a receiver it keyed by the receiver's source text
	// (`<module>.(priv).sign`, `<module>.(self.hasher).update`), or a call of
	// a value bound in the caller's scope (`fn(data)` on a parameter, keyed
	// `<module>.fn`). While the callee still has this key nothing typed the
	// receiver (PythonCallUntyped); a pass that types it later (assignment
	// from a factory, a constructor chain) changes the key, and the builder
	// moves the call's edge from this key to the new one.
	pythonUntyped string
	// nodeModuleValue marks a Node call of an imported module value itself:
	// a default or namespace import, `const f = require('m')` with `f(..)`, or
	// `require('m')(..)`. The callee is then m.default whatever the local
	// binding is called (nodeBinding.qualifyValue), and the call reaches the
	// module's default export (module.exports for CommonJS).
	nodeModuleValue bool
	// nodeUntyped is the callee before a receiver type that the builder still
	// checks was applied: a default-imported class, or an unannotated field.
	nodeUntyped FunctionID
	// nodeInferredField names the unannotated class field the receiver was
	// typed from.
	nodeInferredField string
	// cpp is how a C++ call was written, for resolveCPPCalls; nil for
	// other ecosystems.
	cpp *cppCallFacts
}

// SourceNode describes where a value comes from in the data flow.
// Nodes are recursive: each node can have its own SourceNodes showing deeper origins.
type SourceNode struct {
	// Type classifies the origin: VALUE, VARIABLE, FIELD, PARAMETER, CALL_RESULT, EXPRESSION
	Type string
	// Name is the variable/field/parameter name (e.g., "secret", "algorithm")
	Name string
	// DeclaredType is the type if known (e.g., "byte[]", "io.jsonwebtoken.SignatureAlgorithm")
	DeclaredType string
	// Value is the actual value for VALUE nodes (e.g., "\"AES\"", "256")
	Value string
	// ParameterIndex is set for PARAMETER nodes — which param (0-based)
	ParameterIndex int
	// CallTarget is set for CALL_RESULT nodes — the function that produced this value
	CallTarget *FunctionID
	// Location is where this source is defined
	Location *SourceLocation
	// SourceNodes traces where THIS node's value came from (recursive)
	SourceNodes []SourceNode
	// MayValues lists the string literals a local or parameter written more
	// than once is assigned, its initializer included, in source order. Such
	// a variable has no single source (SourceNodes is empty), but each of
	// these is a value it may hold at the use, which is what a taint rule
	// reads: OpenGrep's taint reaches the use from any of them.
	MayValues []string
	// MayValuesExhaustive says every assignment of the variable, the
	// declaration included, is one of MayValues: it always holds a string
	// constant (OpenGrep's constant propagation reads it as one).
	MayValuesExhaustive bool
	// Flow carries optional branch/call-position semantics without inflating
	// every SourceNode in the graph.
	Flow *SourceFlow
	// nameRef names the NamedValues this node's text may denote, for the
	// post-parse fold. Never exported.
	nameRef *nameRef
	// memberRef names the field or enum constant a `Qualifier.member` value
	// reads, so the overload selector can type it (javaMemberType). Unlike
	// nameRef it survives the named-value fold. Never exported.
	memberRef *nameRef
	// getter marks a method call on a receiver of known construction, for
	// the post-parse fold. Never exported.
	getter *ctorGetterRef
	// runtime marks a value read from a runtime input. Never exported.
	runtime *runtimeRef
}

// SourceFlow carries optional branch and call-position semantics.
type SourceFlow struct {
	Guard        *SourceGuard
	ReturnValue  bool
	CallArgument bool
}

// SourceGuard describes a simple parameter equality branch or its default.
// Consumers keep every candidate when the selected parameter is unresolved.
type SourceGuard struct {
	ParameterIndex int
	Value          string
	Default        bool
}

// SourceLocation identifies a position in source code.
type SourceLocation struct {
	FilePath string
	Line     int
}

// FileAnalysis contains all extracted information from a single source file.
type FileAnalysis struct {
	FilePath      string
	PackageName   string
	PackagePath   string
	Imports       map[string]string // alias (or last path segment) -> full import path
	ImportedTypes map[string]bool   // imported symbol alias -> inferred class/type
	FromImports   map[string]bool   // symbols introduced via `from X import Y` (Python only)
	// PythonFromImportOriginals maps the LOCAL name an aliased Python
	// `from X import Sym as Local` binds to the ORIGINAL symbol name `Sym`.
	// Imports records only the module path, so without this the callee key is
	// built from the CONSUMER'S alias -- `from eth_hash.auto import keccak as
	// kek; kek(d)` emitted `eth_hash.auto.kek`, which no contract can declare
	// and which therefore joined nothing. Populated for Python only, and only
	// when the alias differs from the original name.
	PythonFromImportOriginals map[string]string
	WildcardImports           []string        // wildcard import prefixes (e.g., "java.security")
	StaticWildcardImports     []string        // static wildcard owner types (e.g., "java.util.Collections")
	DeclaredTypes             map[string]bool // source-declared fully qualified types (C++ only)
	// ImportAliases maps a local name that STANDS FOR a real path to that path:
	// a renaming import (Rust `use a::b::C as D;` -> "D" -> "a::b::C") or a
	// local type alias (`type D = a::b::C<T>;` -> "D" -> "a::b::C"). It is kept
	// separate from Imports because Imports maps a leaf to its PARENT path and
	// is expanded by concatenation, which cannot express either: the local name
	// has to be substituted away, not prefixed.
	ImportAliases map[string]string
	// ClassBases maps each source-declared (possibly nested, dotted) type name
	// to its extends/implements clause as erased simple names (Java only).
	// Presence of a key also marks the type as declared in this file.
	ClassBases map[string][]string
	// NamedValues holds the string values this file declares under the
	// fully qualified names a use spells (see NamedValue).
	NamedValues map[string]NamedValue
	// JavaMemberTypes maps each field and enum constant this file declares,
	// under the NamedValues key spelling, to its fully qualified type.
	JavaMemberTypes map[string]string
	// NamedValueWrites holds the NamedValue keys, of any module, this file
	// may write at runtime.
	NamedValueWrites []NamedValueWrite
	// Supertypes maps each type declared in this file, fully qualified, to the
	// fully qualified direct supertypes its extends/implements clauses name
	// (generic arguments excluded), resolved through the file's imports. Where
	// an on-demand import leaves a simple name ambiguous every possible package
	// is listed, so an entry may name a type the graph does not know. Java and
	// Python (each class's bases, python_supertypes.go); merged into
	// CallGraph.SourceSupertypes.
	Supertypes map[string][]string
	// TypeNamesAtRisk holds the simple names this file binds in a scope no
	// graph-wide index sees: each type parameter and each local class it
	// declares. A type written with one of these names is never certain
	// (Java only).
	TypeNamesAtRisk map[string]bool
	Functions       []FunctionDecl
	// PythonReExports maps a symbol name to the module dotted path it is
	// re-exported from, recorded ONLY when this file is a Python
	// `__init__.py` and ONLY from explicit relative `from .mod import Sym
	// [as Alias]` statements (wildcard/absolute imports ignored). The
	// builder accumulates these per-package in addAnalyses and stitches
	// re-exported callee packages once at the end of Phase 1
	// (applyPythonReExports, Python-only). Python only; always nil for
	// other ecosystems.
	PythonReExports map[string]string
	// EntryRefs name the functions this file hands to a framework by
	// reference, as the handler in app.get('/x', handler). The function may be
	// declared in another file, so the builder resolves them once every file
	// is parsed (resolveEntryRefs).
	EntryRefs []EntryRef
	// nodeInstances maps each name a Node module exports an instance under,
	// or "default", to the class it is an instance of.
	nodeInstances map[string]FunctionID
	// nodeDefaultClass is the class the module exports as its default.
	nodeDefaultClass FunctionID
	// nodeAssignedProps holds the properties the file assigns on an object
	// other than `this`.
	nodeAssignedProps map[string]bool
	// nodeSupertypeOwners lists the classes whose supertypes the parser
	// resolved through the file's imports, so the hierarchy never re-resolves
	// them by simple name.
	nodeSupertypeOwners []string
	// cppFacts holds the classes a C++ file defines and the namespaces its
	// using-directives name, for resolveCPPCalls. C++ only.
	cppFacts *cppFileFacts
	// rustFacts holds the declared-type facts collected from a Rust file:
	// struct and enum-variant field types, function return types, and the
	// set of types the file declares. The receiver-typing layer resolves
	// through it, so a method call on a struct field or on a helper's
	// return value carries a real identity instead of the local package.
	// Rust only; always nil for other ecosystems.
	rustFacts *rustFileFacts
	// rustCrateIndex is the shared per-crate declaration index the parser built,
	// consulted for facts that live in another file of the same crate. Rust
	// only; always nil for other ecosystems.
	rustCrateIndex *rustCrateIndex
	// rustDependencies is the set of crate names the analyzed crate's manifest
	// declares. A path segment that is not one of them, and not the standard
	// library, cannot name a crate. Rust only.
	rustDependencies map[string]bool
	// GoStructFields maps each struct this Go file declares to its named
	// fields' declared types. A field whose type cannot be named (func,
	// map, slice, generic, anonymous struct) is absent.
	GoStructFields map[string]map[string]GoFieldType
	// pythonFields holds the attribute writes of the file's classes (Python
	// only), for typing `self.<field>` receivers.
	pythonFields *pythonFieldFacts
	// PythonImports lists the bindings of the file's import statements, in
	// source order (Python only).
	PythonImports []PythonImport
	// RustImports lists the bindings of the file's `use` and `extern crate`
	// declarations, and RustItems the items it declares, at any depth, in
	// source order (Rust only).
	RustImports []RustImport
	RustItems   []RustItem
	// RustBinaryExprs lists the binary expressions of the file's function
	// bodies, in source order (Rust only).
	RustBinaryExprs []RustBinaryExpr
	// CSharpUsings lists the file's using directives in source order: the
	// scope facts that say which namespace an unqualified type name can come
	// from.
	CSharpUsings []CSharpUsing
	// GoImports lists the specs of the file's import declarations, in
	// source order (Go only).
	GoImports []GoImport
	// GoValues lists the composite literals, new(T) expressions and field
	// stores of the file, in source order (Go only).
	GoValues []GoValue
	// GoBlocks lists the blocks of the file's function bodies, case clauses
	// included, in source order (Go only).
	GoBlocks []GoBlock
	// NodeImports lists the imports, requires, dynamic imports and
	// re-exports of the file, in source order (Node only).
	NodeImports []NodeImport
	// NodeObjectLiterals lists the outermost object expressions of the file,
	// in source order (Node only).
	NodeObjectLiterals []NodeObjectLiteral
	// nodePropertyReads lists the property reads of the file's functions, in
	// source order, as the parser keyed them (Node only).
	nodePropertyReads []nodePropertyReadSite
	// CIncludes lists the #include directives of the file, in source order
	// (C and C++ only).
	CIncludes []CInclude
	// CStrings lists the string literals of the file, in source order (C and
	// C++ only).
	CStrings []CString
	// nodeReExports holds what the file re-exports from other modules (Node
	// only), nil when nothing.
	nodeReExports *nodeModuleReExports
	// pythonModule holds the file's module-level assignments and __all__
	// (Python only), for the exports.
	pythonModule *pythonModuleFacts
}

// CallGraph is the complete call graph across all analyzed packages.
type CallGraph struct {
	// Functions maps FunctionID.String() to its declaration
	Functions map[string]*FunctionDecl
	// Callers maps callee FunctionID.String() to list of caller FunctionID.String()
	// This is the reverse index for walking backwards from a crypto finding.
	Callers map[string][]string
	// TypeHierarchy maps a fully qualified type name to its fully qualified parent
	// interfaces/superclasses. E.g., "io.jsonwebtoken.JwtBuilder" →
	// ["io.jsonwebtoken.ClaimsMutator"]. Populated by TypeResolver from bytecode.
	TypeHierarchy map[string][]string
	// SourceSupertypes maps a source-declared type to the supertypes its own
	// extends/implements clauses name (see FileAnalysis.Supertypes). Kept apart
	// from TypeHierarchy, which holds only resolver-indexed edges; the dispatch
	// expansions read both to link a call only to real subtypes of its
	// receiver type.
	SourceSupertypes map[string][]string
	// ServiceProviders maps a service type to the implementation classes
	// the scanned source registers for java.util.ServiceLoader in
	// META-INF/services/<service type>, by binary name in file order
	// (Java only). Nil when the source registers none.
	ServiceProviders map[string][]string
	// ExternalMethodSignatures stores resolver-derived signatures for methods that
	// are known to the graph by symbol but do not have a source declaration.
	// Keyed by fully qualified method + arity via ExternalMethodSignatureKey.
	ExternalMethodSignatures map[string][]ExternalMethodSignature
	// pythonDependencyClasses are the classes Python type-only packages
	// declare ("pkg.Type"; PythonDependencyTypeResolver): a call of one
	// builds that class.
	pythonDependencyClasses map[string]bool
	// JavaPlatformSignatures records whether Java platform signatures from the
	// pinned runtime were available and used for this graph build.
	JavaPlatformSignatures *JavaPlatformSignatureMetadata
	// ProjectDeclaredTypes and ProjectDeclaredFunctions record stable C++
	// identities owned by unversioned workspace packages. They keep external
	// contract fallback from overriding project code without hiding contracts
	// for source-parsed dependencies.
	ProjectDeclaredTypes     map[string]bool
	ProjectDeclaredFunctions map[string]bool
	// EdgeResolutions records how each caller->callee call-site/dispatch variant
	// was resolved. Keyed by EdgeResolutionKey(callerKey, calleeKey, resolution).
	// An edge with no entry is an exact, directly-resolved source call. Consumers
	// use this to refuse to present over-broad name/arity dispatch guesses as
	// typed reachability proof. Values carry their caller/callee endpoints
	// (EdgeResolutionEndpoints), so per-pair views are one O(E) pass away —
	// see internal/scan's indexFragmentEdgeResolutions.
	EdgeResolutions map[string]EdgeResolution
	// RebindLines is set on a graph rebuilt from a fragment that records them
	// (graph-fragment-1.23): by function key, then variable name, the lines
	// that may give the variable another value or overwrite its buffer. A
	// function with an entry (nil when it rebinds nothing) needs no source to
	// tell; one without, or a graph without the map, reads its source.
	RebindLines map[string]map[string][]int
	// artifacts records which artifact declares each source type, so a pass
	// that links a call by a type's simple name keeps it within artifacts
	// the caller compiles against. Nil for a graph not built by a Builder.
	artifacts *artifactScope
	// PublicTypePaths maps a type's declaring path to the public paths a
	// `pub use` re-exports it under ("rsa::pkcs1v15::signing_key::SigningKey"
	// -> ["rsa::pkcs1v15::SigningKey"]). Contracts name the public path, the
	// declaration carries the declaring one. Rust only.
	PublicTypePaths map[string][]string
	// PythonPublicPaths maps the path a package's `__init__.py` gives a name
	// it imports to the path of the module that declares it ("jwt.encode" ->
	// "jwt.api_jwt.encode"), following re-exports through nested packages.
	// A declaration is keyed by its defining module, while a consumer and a
	// rule name the public path. Python only.
	PythonPublicPaths map[string]string
	// PythonImports holds the import bindings of each project source file,
	// by file path (Python only), the project's own modules requalified as
	// its calls are.
	PythonImports map[string][]PythonImport
	// RustImports and RustItems hold, by file path, the `use` and `extern
	// crate` bindings and the items of each Rust source file whose functions
	// the graph holds, as written (Rust only).
	RustImports map[string][]RustImport
	RustItems   map[string][]RustItem
	// RustBinaryExprs holds, by file path, the binary expressions of the
	// function bodies of each Rust source file whose functions the graph
	// holds, as written (Rust only).
	RustBinaryExprs map[string][]RustBinaryExpr
	// CSharpUsings holds the using directives of each project source file,
	// by file path (C# only), paths and aliases as written.
	CSharpUsings map[string][]CSharpUsing
	// GoImports holds the import specs of each project source file, by
	// file path (Go only), paths and names as written.
	GoImports map[string][]GoImport
	// GoValues holds the composite literals, new(T) expressions and field
	// stores of each project source file, by file path (Go only).
	GoValues map[string][]GoValue
	// GoBlocks holds the blocks of the function bodies of each project
	// source file, by file path (Go only).
	GoBlocks map[string][]GoBlock
	// NodeImports holds the imports, requires, dynamic imports and
	// re-exports of each project source file, by file path (Node only), with
	// module specifiers as written.
	NodeImports map[string][]NodeImport
	// NodeObjectLiterals holds the outermost object expressions of each
	// project source file, by file path (Node only), for a rule whose pattern
	// is a bare object literal.
	NodeObjectLiterals map[string][]NodeObjectLiteral
	// NodePropertyReads holds the property reads of each project source file,
	// by file path, in source order (Node only), each keyed as a call of the
	// expression would be, for a rule whose pattern is a bare member
	// expression. nodePropertyReads holds them while the graph is built.
	NodePropertyReads map[string][]NodePropertyRead
	nodePropertyReads []*nodePropertyReadSite
	// CIncludes holds the #include directives of each project source file, by
	// file path (C and C++ only), with headers as written.
	CIncludes map[string][]CInclude
	// CStrings holds the string literals of each project source file, by file
	// path (C and C++ only), as written.
	CStrings map[string][]CString
	// PythonExports maps each public name of the project's Python modules
	// that names a declaration of the project made elsewhere to it
	// (resolvePythonExports): "jwt.encode" -> "jwt.api_jwt.(PyJWT).encode",
	// "jwt.PyJWT" -> "jwt.api_jwt.(PyJWT)".
	PythonExports map[string]string
	// NodePackageExports maps each key a caller spells through a specifier of
	// one of the build's Node packages to the function the package declares
	// under another key (recordNodePackageExports): "acme-sign.sign" ->
	// "acme-sign/index.sign", "notp.hotp.gen" -> "notp/index.(hotp).gen",
	// "acme-sign.default" -> "acme-sign/index.exports". A domain writes it as
	// a fragment's `exports`, which the stitch joins a client's call through.
	NodePackageExports map[string]string
	// RubyExports maps each public constant path of the component's Ruby
	// methods to the declaration behind it (resolveRubyExports):
	// "(JWT).encode" -> "lib.(JWT).encode#4". A Ruby constant is public where
	// it is defined -- there is no __init__.py, no re-export and no __all__ --
	// so the path is the module and class nesting of the `def`, and the key
	// carries no arity: optional parameters make a count meaningless to a
	// caller, which is the same reason Python's keys carry none.
	RubyExports map[string]string
	// RustExports maps each public path of the crate's Rust functions, types
	// and modules, in function-key form, to the declaration behind it
	// (rustExports): "jsonwebtoken.decode" -> "jsonwebtoken::decoding.decode",
	// "jsonwebtoken.DecodingKey" -> "jsonwebtoken::decoding.(DecodingKey)",
	// "ring.hmac" -> "ring::hmac". A `pub use` item (a glob or a module
	// included) or a `pub type` alias gives a declaration a public path in
	// another module, and a re-export of a dependency's item names it as that
	// crate keys it ("rand::rngs.OsRng" -> "rand_core.(OsRng)"); a module is public
	// at its own path, which joins the key a call through an imported module
	// gets (`use ring::hmac; hmac::sign(..)` is `ring.(hmac).sign`). A domain
	// writes it as a fragment's `exports`, which the stitch joins a client's
	// call through.
	RustExports map[string]string
	// NamedValues merges every parsed file's NamedValues.
	NamedValues map[string]NamedValue
	// javaMemberTypes merges every parsed file's JavaMemberTypes ("" when two
	// files disagree).
	javaMemberTypes map[string]string
	// namedValueWrites merges every file's NamedValueWrites by key, true when
	// a write reaches the key itself and not only the keys under it.
	namedValueWrites map[string]bool
	// entryRefs collects FileAnalysis.EntryRefs while files are merged;
	// resolveEntryRefs consumes it.
	entryRefs []EntryRef
	// goStructFields merges FileAnalysis.GoStructFields keyed by
	// `package.Struct`; a field two declarations disagree on (build-tag
	// variants) is stored with an empty Type and never resolves.
	goStructFields map[string]map[string]GoFieldType
	// goSourceTypes is the GoSourceTypeResolver's declaration index, for the
	// passes that type a receiver from its producer's result type.
	goSourceTypes *goSourceIndex
	// nodeInstances indexes the instances Node modules export, by
	// `module.name`, while files are merged; resolveNodeImportedInstances
	// consumes it.
	nodeInstances map[string]nodeModuleInstance
	// nodeDefaultClasses indexes the class each Node module exports as its
	// default, by module path.
	nodeDefaultClasses map[string]nodeModuleInstance
	// nodeAssignedProps holds every property name any Node module assigns on
	// an object other than `this`.
	nodeAssignedProps map[string]bool
	// nodeReExports indexes each Node module's re-exports by module path, for
	// resolveNodeReExportedCalls.
	nodeReExports map[string]*nodeModuleReExports
	// nodeClassOwners holds the Node classes whose supertypes the parser
	// resolved through imports.
	nodeClassOwners map[string]bool
	// pythonFields collects every parsed file's FileAnalysis.pythonFields
	// (Python only); typePythonSelfFieldReceivers consumes it.
	pythonFields []*pythonFieldFacts
	// pythonImportedNames maps a name as an attribute of the module that
	// imports it with a from-import ("app.views.Signer", any module, not only
	// a package's `__init__.py`) to the declaration it names, through chains
	// (Python only).
	pythonImportedNames map[string]string
}

// EdgeKind classifies how confidently a caller->callee edge was resolved.
type EdgeKind string

const (
	// EdgeKindExact means the receiver's static type was known and the method
	// resolved to a unique declared target (or an overload on that exact type).
	EdgeKindExact EdgeKind = "exact"
	// EdgeKindInterfaceDispatch is a synthesized edge from an interface/abstract
	// method call site to a concrete implementation matched by name+arity within
	// a namespace root.
	EdgeKindInterfaceDispatch EdgeKind = "interface_dispatch"
	// EdgeKindNameOnly is a fluent-fallback edge matched by method name+arity (and
	// namespace heuristics) with no receiver type anchor.
	EdgeKindNameOnly EdgeKind = "name_only"
	// EdgeKindPythonSubclassDispatch is a synthesized edge from a base-class method
	// call site to a concrete subclass override. Populated by expandPythonSubclassDispatch
	// using OwnerBases declared in the Python source. Python-only; Java dispatch uses
	// EdgeKindInterfaceDispatch instead.
	EdgeKindPythonSubclassDispatch EdgeKind = "python_subclass_dispatch"
)

// edgeKindRank orders kinds by trust so a stronger classification is never
// downgraded when the same edge is reached via multiple resolution paths.
func edgeKindRank(k EdgeKind) int {
	switch k {
	case EdgeKindExact:
		return 3
	case EdgeKindInterfaceDispatch:
		return 2
	case EdgeKindPythonSubclassDispatch:
		return 2
	case EdgeKindNameOnly:
		return 1
	default:
		return 0
	}
}

// EdgeResolution describes how one caller->callee edge was resolved, plus the
// call-site identity needed to group ambiguous dispatch siblings downstream.
type EdgeResolution struct {
	Kind         EdgeKind
	DeclaredType string // interface/static type for dispatch edges (e.g. "dep.Sink")
	MethodName   string // base method name (no arity decoration)
	Arity        int
	CallSite     int // source line of the call expression
	StartCol     int // 1-based, inclusive; 0 when the parser is not column-aware
	EndCol       int // 1-based, exclusive; 0 when unknown
	callerKey    string
	calleeKey    string

	// ResolvedReceiverType is the concrete receiver type resolveParameterPassthroughDispatch
	// determined for THIS specific dispatch edge, when the call site is a
	// single-use pass-through parameter and the calling context supplied a
	// statically concrete argument (e.g. password4j's
	// `with(AlgorithmFinder.getPBKDF2Instance())` calling into
	// `with(HashingFunction h) { h.hash(...) }`). Empty when no such resolution
	// applies. Exported verbatim as graph-fragment resolved_receiver_type so the
	// stitcher can disambiguate a dispatch group at serve time.
	ResolvedReceiverType string
}

// RecordEdgeResolution stores res as the resolution of the callerKey ->
// calleeKey edge, as the builder records one, keeping the highest-trust kind
// of an edge recorded twice. It rebuilds a graph from a stored projection.
func (g *CallGraph) RecordEdgeResolution(callerKey, calleeKey string, res EdgeResolution) {
	if g.EdgeResolutions == nil {
		g.EdgeResolutions = make(map[string]EdgeResolution)
	}
	res.callerKey, res.calleeKey = callerKey, calleeKey
	key := EdgeResolutionKey(callerKey, calleeKey, res)
	if existing, ok := g.EdgeResolutions[key]; ok && edgeKindRank(existing.Kind) >= edgeKindRank(res.Kind) {
		return
	}
	g.EdgeResolutions[key] = res
}

// EdgeResolutionKey is the stable map key for one resolved caller->callee
// call-site/dispatch variant.
func EdgeResolutionKey(callerKey, calleeKey string, resolution EdgeResolution) string {
	return EdgeResolutionKeyPrefix(callerKey, calleeKey) +
		strconv.Itoa(resolution.CallSite) + "\x00" +
		strconv.Itoa(resolution.StartCol) + "\x00" +
		strconv.Itoa(resolution.EndCol) + "\x00" +
		resolution.DeclaredType + "\x00" +
		resolution.MethodName + "\x00" +
		strconv.Itoa(resolution.Arity)
}

// EdgeResolutionKeyPrefix returns the stable prefix shared by all resolution
// variants for one caller->callee pair.
func EdgeResolutionKeyPrefix(callerKey, calleeKey string) string {
	return callerKey + "\x00" + calleeKey + "\x00"
}

// EdgeResolutionEndpoints returns the caller/callee pair for a stored edge
// resolution. Values recorded by this package carry endpoints directly so
// large export paths do not need to repeatedly split the map key; hand-built
// tests or older in-memory fixtures still fall back to parsing the key.
func EdgeResolutionEndpoints(key string, resolution EdgeResolution) (callerKey, calleeKey string, ok bool) {
	if resolution.callerKey != "" && resolution.calleeKey != "" {
		return resolution.callerKey, resolution.calleeKey, true
	}
	parts := strings.SplitN(key, "\x00", 3)
	if len(parts) < 3 {
		return "", "", false
	}
	return parts[0], parts[1], true
}

// FunctionArity parses the "#<n>" arity suffix from a decorated function name.
// Returns 0 when the name carries no arity suffix.
func FunctionArity(name string) int { return functionArity(name) }

func functionArity(name string) int {
	idx := strings.Index(name, "#")
	if idx < 0 || idx >= len(name)-1 {
		return 0
	}
	n := 0
	for j := idx + 1; j < len(name) && name[j] >= '0' && name[j] <= '9'; j++ {
		n = n*10 + int(name[j]-'0')
	}
	return n
}

// ExternalMethodSignatureKey returns the stable graph key for resolver-provided
// method signatures. The key normalizes overload decoration down to name+arity.
func ExternalMethodSignatureKey(id FunctionID) string {
	return qualifiedMethodArityKey(id.Package, id.Type, id.Name)
}

// CallChain represents a traced path from user code to a crypto finding.
type CallChain struct {
	// Steps is ordered from user entry point to crypto call site
	Steps []CallChainStep
	// RootKind says what the first step is (TraceBackCondensed only).
	RootKind RootKind
}

// CallChainStep represents a single step in a call chain.
type CallChainStep struct {
	Function FunctionID
	FilePath string
	Line     int
	StartCol int
	EndCol   int
}

// ParseFunctionID parses a fully-qualified function string back into a FunctionID.
// It handles both plain functions ("crypto/aes.NewCipher") and methods with
// a type receiver ("crypto/aes.(*Block).Encrypt").
//
// ParseFunctionID splits plain function identifiers at the last "." in the input,
// treating everything before that point as the package or fully-qualified class
// name and everything after it as the function name. Go package paths may contain
// "/" before that final ".", while Java package and class names use "." throughout.
func ParseFunctionID(s string) (FunctionID, error) {
	// Method pattern: "package.(Type).Name", or "(Type).Name" when the package
	// is empty (String emits no separator for one, so ".(Type).Name" is
	// malformed).
	parenStart := strings.Index(s, ".(") + 1 // 0 when absent, else the "(" position
	if strings.HasPrefix(s, "(") || parenStart > 0 {
		if parenStart == 1 {
			return FunctionID{}, fmt.Errorf("invalid function ID: malformed method components in %q", s)
		}
		pkg := strings.TrimSuffix(s[:parenStart], ".")
		if strings.HasPrefix(pkg, ".") {
			return FunctionID{}, fmt.Errorf("invalid function ID: package starts with a separator in %q", s)
		}
		rest := s[parenStart+1:] // skip "("
		parenEnd := strings.Index(rest, ").")
		if parenEnd == -1 {
			return FunctionID{}, fmt.Errorf("invalid function ID: unmatched parentheses in %q", s)
		}
		typ := rest[:parenEnd]
		name := rest[parenEnd+2:] // skip ")."
		if typ == "" || name == "" {
			return FunctionID{}, fmt.Errorf("invalid function ID: malformed method components in %q", s)
		}

		return FunctionID{Package: pkg, Type: typ, Name: name}, nil
	}

	// Plain function: "package<sep>Name" — find the last separator-appropriate
	// dot. No dot at all is a function with no package: a declaration at an
	// unnamed scan root, or a call whose receiver never resolved to a type.
	// Parsing it back keeps the pair symmetric with String; rejecting it
	// silently drops the method name from every edge built through
	// recordEdgeResolution.
	lastDot := strings.LastIndex(s, ".")
	if lastDot == -1 {
		if s == "" {
			return FunctionID{}, fmt.Errorf("invalid function ID: empty")
		}
		return FunctionID{Name: s}, nil
	}
	if lastDot == 0 || lastDot == len(s)-1 {
		return FunctionID{}, fmt.Errorf("invalid function ID: no package separator in %q", s)
	}
	// String never emits a separator for an empty package, so a package that
	// starts with one is a key joined from "" and a name with a dot, not a
	// package named ".a". Rejecting it keeps the pair symmetric.
	if s[0] == '.' {
		return FunctionID{}, fmt.Errorf("invalid function ID: package starts with a separator in %q", s)
	}

	return FunctionID{
		Package: s[:lastDot],
		Name:    s[lastDot+1:],
	}, nil
}
