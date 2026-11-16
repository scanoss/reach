// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import "testing"

func TestDispatch_ThisDelegationTypedByEnumConstant(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"p/Purpose.java": "package p;\npublic enum Purpose { ANY, SIGN }\n",
		"p/Digest.java": `package p;
public class Digest {
  public Digest() { this(Purpose.ANY); }
  public Digest(Purpose purpose) {}
  public Digest(Digest other) {}
}
`,
	})
	caller := "p.(Digest).<init>#0"
	if !hasCaller(graph, "p.(Digest).<init>#1$Purpose", caller) {
		t.Errorf("this(Purpose.ANY) must link the Purpose constructor")
	}
	if hasCaller(graph, "p.(Digest).<init>#1$Digest", caller) {
		t.Errorf("Purpose.ANY is a Purpose, so the copy constructor must not be linked")
	}
}

func TestDispatch_OverloadArgumentTypedByFieldOfVariable(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"p/Img.java": `package p;
public class Img {
  public static Img get(Img i) { return i; }
  public static Img get(java.net.URL u) { return null; }
}
`,
		"p/Cell.java": `package p;
public class Cell {
  protected Img image;
  public Cell(Cell c) { Img.get(c.image); }
}
`,
	})
	caller := "p.(Cell).<init>#1"
	if !hasCaller(graph, "p.(Img).get#1$Img", caller) {
		t.Errorf("Img.get(c.image) must link get(Img)")
	}
	if hasCaller(graph, "p.(Img).get#1$URL", caller) {
		t.Errorf("c.image is an Img, so get(URL) must not be linked")
	}
}

func TestJavaParser_UnimportedJavaLangReceiverResolvesToJavaLang(t *testing.T) {
	graph := buildJavaGraph(t, map[string]string{
		"p/M.java": `package p;
public class M {
  public void go(String s) { s.trim(); }
}
`,
	})
	fn := graph.Functions["p.(M).go#1"]
	if fn == nil || len(fn.Calls) == 0 {
		t.Fatalf("go not parsed")
	}
	if got := fn.Calls[0].Callee.String(); got != "java.lang.(String).trim#0" {
		t.Errorf("callee = %q, want java.lang.(String).trim#0", got)
	}
}

// platformReturnTypes stands in for the bytecode resolver: it records the
// platform signatures the graph's calls name, and java.lang.String's place in
// the platform hierarchy.
type platformReturnTypes map[string]string

func (r platformReturnTypes) ResolveTypes(graph *CallGraph, _ []PackageDir) error {
	graph.TypeHierarchy = map[string][]string{"java.lang.String": {"java.lang.CharSequence"}}
	graph.ExternalMethodSignatures = make(map[string][]ExternalMethodSignature)
	for key, ret := range r {
		graph.ExternalMethodSignatures[key] = []ExternalMethodSignature{{ReturnType: ret}}
	}
	return nil
}

func TestDispatch_ThisDelegationTypedByPlatformReturnTypeAfterTypeResolution(t *testing.T) {
	root := writeJavaSources(t, map[string]string{
		"p/Verifier.java": `package p;
import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
public class Verifier {
  public Verifier(byte[] secret) {}
  public Verifier(String secret) { this(secret.getBytes(StandardCharsets.UTF_8)); }
  public Verifier(SecretKey key) { this(key.getEncoded()); }
}
`,
	})
	builder := NewBuilderForEcosystem(ecosystemJava, NewJavaParser())
	builder.SetTypeResolver(platformReturnTypes{
		qualifiedMethodArityKey("javax.crypto", "SecretKey", "getEncoded#0"): "byte[]",
		qualifiedMethodArityKey("java.lang", "String", "getBytes#1"):         "byte[]",
	})
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	for _, caller := range []string{"p.(Verifier).<init>#1$SecretKey", "p.(Verifier).<init>#1$String"} {
		if !hasCaller(graph, "p.(Verifier).<init>#1$byte[]", caller) {
			t.Errorf("%s must link the byte[] constructor", caller)
		}
		for _, wrong := range []string{"p.(Verifier).<init>#1$SecretKey", "p.(Verifier).<init>#1$String"} {
			if hasCaller(graph, wrong, caller) {
				t.Errorf("%s: the argument is a byte[], so %s must not be linked", caller, wrong)
			}
			if kind := edgeKindOf(graph, caller, wrong); kind != "" {
				t.Errorf("%s -> %s keeps a %s resolution", caller, wrong, kind)
			}
		}
	}
}

func TestDispatch_PlatformReturnTypeMakesOverloadExactDespiteNullArguments(t *testing.T) {
	root := writeJavaSources(t, map[string]string{
		// The JDK ships another String (com.sun.org.apache.xpath.internal.operations);
		// an unimported String still means java.lang.String.
		"q/String.java": "package q;\npublic class String { public void touch() {} }\n",
		"p/Factory.java": `package p;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
public class Factory {
  public Factory(SSLContext context, String host) { this(context.getSocketFactory(), null, null, host); }
  public Factory(SSLSocketFactory factory, String[] protocols, String[] suites, String host) {}
  public Factory(SSLContext context, String[] protocols, String[] suites, String host) {}
}
`,
	})
	builder := NewBuilderForEcosystem(ecosystemJava, NewJavaParser())
	builder.SetTypeResolver(platformReturnTypes{
		qualifiedMethodArityKey("javax.net.ssl", "SSLContext", "getSocketFactory#0"): "javax.net.ssl.SSLSocketFactory",
	})
	graph, err := builder.BuildFromDirectories([]PackageDir{{Dir: root}}, nil)
	if err != nil {
		t.Fatalf("BuildFromDirectories: %v", err)
	}
	caller := "p.(Factory).<init>#2"
	if !hasCaller(graph, "p.(Factory).<init>#4$SSLSocketFactory,String[],String[],String", caller) {
		t.Errorf("the SSLSocketFactory constructor must be linked")
	}
	if hasCaller(graph, "p.(Factory).<init>#4$SSLContext,String[],String[],String", caller) {
		t.Errorf("getSocketFactory() returns an SSLSocketFactory, so the SSLContext constructor must not be linked")
	}
}
