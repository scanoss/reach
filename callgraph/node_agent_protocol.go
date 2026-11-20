// Copyright (C) 2026 SCANOSS.COM
// SPDX-License-Identifier: MIT

package callgraph

import (
	sitter "github.com/smacker/go-tree-sitter"
)

// node_agent_protocol.go models what the Node runtime does with an HTTP
// agent. An agent exists to be passed to http.request / https.request (as
// the `agent` option, or a client's agent, often through another package
// such as axios); the runtime then calls its addRequest, which calls
// createSocket, which calls createConnection, and agent-base's createSocket
// calls the subclass's connect. Where the agent is passed is usually in
// another package the fragment does not see, so the edges are drawn from
// the agent's construction: the constructor of a class whose chain of
// bases reaches http.Agent, https.Agent or agent-base's Agent reaches the
// protocol methods the class and its bases in the package declare. A class
// that does not extend one of those gets no edge, whatever its methods are
// called.

// nodeAgentBases are the modules whose Agent class the runtime drives.
var nodeAgentBases = map[string]bool{
	"http": true, "https": true, "node:http": true, "node:https": true, "agent-base": true,
}

// nodeAgentProtocol are the methods the runtime calls on an agent.
var nodeAgentProtocol = []string{"addRequest", "createSocket", "createConnection", "connect"}

// nodeAgentClass is the Agent class nodeAgentBases export.
const nodeAgentClass = "Agent"

// linkAgentProtocol adds, for each agent class of the package, an edge from
// its constructor to each protocol method its chain declares.
func (f *nodeValueFlow) linkAgentProtocol(files []string) {
	for _, file := range files {
		m := f.shapes.module(file)
		if m == nil {
			continue
		}
		nodeWalk(m.root, func(n *sitter.Node) {
			if n.Type() != nodeClassDeclaration && n.Type() != nodeClassExpression {
				return
			}
			chain, ok := f.agentChain(nodeShapeValue{m: m, n: n})
			if !ok {
				return
			}
			ctor := nodeClassMember(m, n, "constructor", false)
			if ctor == nil {
				return
			}
			from := f.functionKey(m, ctor)
			if from == "" {
				return
			}
			for _, method := range nodeAgentProtocol {
				for _, class := range chain {
					member := nodeClassMember(class.m, class.n, method, false)
					if member == nil || member.Type() != nodeMethodDefinition {
						continue
					}
					if key := f.functionKey(class.m, member); key != "" {
						f.edge(from, key, f.graph.Functions[key].ID, ctor, "")
					}
					break // the most derived declaration is the one that runs
				}
			}
		})
	}
}

// agentChain lists the class v and its bases in the package, most derived
// first, when the chain ends at an Agent the runtime drives.
func (f *nodeValueFlow) agentChain(v nodeShapeValue) ([]nodeShapeValue, bool) {
	chain := []nodeShapeValue{v}
	for depth := 0; depth < nodeInheritanceDepth; depth++ {
		q := f.shapes.query()
		q.budget = nodeValueBudget / 8
		var next *nodeShapeValue
		for _, base := range q.bases(chain[len(chain)-1], 0) {
			if base.external != nil {
				if nodeIsRuntimeAgent(base.external) {
					return chain, true
				}
				continue
			}
			if base.class() && next == nil {
				b := nodeShapeValue{m: base.m, n: base.n}
				next = &b
			}
		}
		if next == nil {
			return nil, false
		}
		chain = append(chain, *next)
	}
	return nil, false
}

// nodeIsRuntimeAgent reports `http.Agent`, `https.Agent` or agent-base's
// `Agent` (extended: one step, constructed).
func nodeIsRuntimeAgent(a *nodeValueAccess) bool {
	return nodeAgentBases[a.module] && len(a.steps) == 1 && a.steps[0].name == nodeAgentClass && !a.steps[0].call
}
