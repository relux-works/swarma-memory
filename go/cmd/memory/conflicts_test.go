package main

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/relux-works/swarma-memory/go/agentprofile"
	"github.com/relux-works/swarma-memory/go/escalation"
)

// The public/private pair uses the same signed history. A private opposing
// assessment affects only the reader allowed to see it; hidden and missing exact
// refs refuse identically with no partial packet or leaked evidence reference.
func TestConflictDisclosurePairs(t *testing.T) {
	h := newCLI(t)
	h.appendRecord("record:visible", "Visible dependency")
	for _, polarity := range []string{"support", "oppose"} {
		h.appendUsing("space:test", "assessment:"+polarity, "", func(r map[string]any) {
			e := agentprofile.Object(r["envelope"])
			e["kind"] = "assessment"
			e["schema"] = nil
			if polarity == "oppose" {
				agentprofile.Object(e["disclosure"])["audiences"] = []any{"aud:private"}
			}
			target := agentprofile.Ref("record:visible", 1)
			r["body"] = map[string]any{"check_kind": "semantic_review", "executor": "model", "result": "pass", "pins": map[string]any{"subject": target, "rule": agentprofile.Ref("check:semantic_review", 1), "policy": agentprofile.Ref("evidence:agent-memory", 1), "environment": agentprofile.Ref("environment:agent-memory", 1)}, "target": map[string]any{"assertion": target, "polarity": polarity}, "sources": []any{}, "origin": "origin:" + polarity, "source_requirement": "current", "usable_until": nil, "declassification": nil}
		})
	}
	h.appendRecord("record:hidden", "Private dependency")
	// A distinct private assertion is written with the same production writer and
	// signed Git path as the ordinary controls.
	h.appendUsing("space:test", "record:private", "Do not put this content in a packet", func(r map[string]any) {
		agentprofile.Object(agentprofile.Object(r["envelope"])["disclosure"])["audiences"] = []any{"aud:private"}
	})
	h.invoke(h.owner, 0, "policy", "grant", "--space", "space:test", "--identity", "public", "--role", "reader")
	h.invoke(h.reader, 0, "keys", "init", "--identity", "agent:public")
	h.invoke(h.reader, 0, "spaces", "add", "space:test", "--remote", h.remote, "--genesis", h.pin)
	private, _ := h.invoke(h.owner, 7, "explain", "record:visible", "--space", "space:test", "--require-current")
	packet := agentprofile.Object(agentprofile.Object(private["data"])["escalation"])
	if escalation.Validate(packet) != nil || len(agentprofile.Array(packet["conflicts"])) != 1 {
		t.Fatal(packet)
	}
	public, _ := h.invoke(h.reader, 0, "explain", "record:visible", "--space", "space:test", "--require-current")
	if agentprofile.Object(public["data"])["escalation"] != nil {
		t.Fatal("hidden opposition produced packet")
	}
	empty, _ := h.invoke(h.reader, 0, "conflicts", "--space", "space:test", "--id", "record:visible")
	if len(agentprofile.Array(agentprofile.Object(empty["data"])["conflicts"])) != 0 {
		t.Fatal(empty)
	}
	hidden, _ := h.invoke(h.reader, 3, "conflicts", "--ref", "space:test:record:private:1")
	mixed, _ := h.invoke(h.reader, 3, "conflicts", "--ref", "space:test:record:visible:1", "--ref", "space:test:record:private:1")
	absent, _ := h.invoke(h.reader, 3, "conflicts", "--ref", "space:test:record:missing:1")
	if errorCodeOf(hidden) != "record_not_found" || errorCodeOf(absent) != "record_not_found" || hidden["data"] != nil || absent["data"] != nil || errorCodeOf(mixed) != "record_not_found" || mixed["data"] != nil {
		t.Fatal(hidden, absent)
	}
	// A valid private control discloses the exact same formerly hidden ref.
	visible, _ := h.invoke(h.owner, 7, "conflicts", "--ref", "space:test:record:private:1")
	b, _ := json.Marshal(visible)
	if !strings.Contains(string(b), "record:private") || strings.Contains(string(b), "Do not put this content") {
		t.Fatal(string(b))
	}
}

func processBoundary(source string) bool { return processBoundaryUnix(source, false) }
func processBoundaryUnix(source string, allowUnix bool) bool {
	f, e := parser.ParseFile(token.NewFileSet(), "boundary.go", source, 0)
	if e != nil {
		return false
	}
	aliases := map[string]string{}
	for _, i := range f.Imports {
		path, _ := strconv.Unquote(i.Path.Value)
		name := filepath.Base(path)
		if i.Name != nil {
			name = i.Name.Name
		}
		aliases[name] = path
		if strings.HasPrefix(path, "net") && path != "net/url" && path != "net/netip" && !(allowUnix && path == "net" && name != "." && name != "_") || path == "syscall" || path == "unsafe" || path == "plugin" || path == "C" || path == "os/exec" && (name == "." || name == "_") {
			return false
		}
	}
	valid := true
	ast.Inspect(f, func(n ast.Node) bool {
		if selector, ok := n.(*ast.SelectorExpr); ok && allowUnix {
			if name, ok := selector.X.(*ast.Ident); ok && aliases[name.Name] == "net" && selector.Sel.Name != "Dialer" {
				valid = false
			}
			// Dial method values are not permitted: every dial must be a checked call.
			if strings.HasPrefix(selector.Sel.Name, "Dial") && selector.Sel.Name != "Dialer" {
				checked := false
				ast.Inspect(f, func(parent ast.Node) bool {
					if c, ok := parent.(*ast.CallExpr); ok && c.Fun == selector {
						at := 0
						if selector.Sel.Name == "DialContext" {
							at = 1
						}
						if selector.Sel.Name == "Dial" || selector.Sel.Name == "DialContext" {
							if len(c.Args) > at {
								literal, ok := c.Args[at].(*ast.BasicLit)
								checked = ok && literal.Kind == token.STRING && literal.Value == `"unix"`
							}
						}
					}
					return true
				})
				if !checked {
					valid = false
				}
			}
		}
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		name, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		path := aliases[name.Name]
		if path == "os" && selector.Sel.Name == "StartProcess" {
			valid = false
		}
		if path == "os/exec" {
			at := 0
			if selector.Sel.Name == "CommandContext" {
				at = 1
			} else if selector.Sel.Name != "Command" {
				valid = false
				return true
			}
			if len(call.Args) <= at {
				valid = false
				return true
			}
			literal, ok := call.Args[at].(*ast.BasicLit)
			if !ok || literal.Kind != token.STRING || literal.Value != `"git"` {
				valid = false
			}
		}
		return true
	})
	return valid
}

// Production call sites start only literal git commands. Only sshagent.go may
// import net, with literal Unix dials; TCP/HTTP and board clients remain refused.
// net/url and net/netip are data parsers without network I/O, allowed everywhere.
// Checker plants prove an aliased task-board command,
// variable program and network import are refused; this is a static call-site
// guarantee, not a claim about git's configured transport/signature subprocesses.
func TestMemoryProcessBoundary(t *testing.T) {
	for _, source := range []string{`package p;import x "os/exec";func f(){x.Command("task-board")}`, `package p;import "os/exec";func f(s string){exec.Command(s)}`, `package p;import "net/http"`, `package p;import "net"`, `package p;import "net/rpc"`, `package p;import . "os/exec";func f(){Command("task-board")}`, `package p;import "plugin"`} {
		if processBoundary(source) {
			t.Fatal("bad process plant accepted")
		}
	}
	if !processBoundary(`package p;import "net/netip";func f(){netip.ParseAddr("2001:db8::1")}`) {
		t.Fatal("pure address parser refused")
	}
	if !processBoundary(`package p;import "os/exec";func f(){exec.Command("git")}`) {
		t.Fatal("git positive refused")
	}
	for _, source := range []string{
		`package p; import "net";func f(){d:=net.Dialer{};d.DialContext(nil,"tcp","localhost:80")}`,
		`package p; import "net";func f(p string){d:=net.Dialer{};d.Dial(p,"x")}`,
		`package p; import "net";func f(){net.Listen("unix","x")}`,
		`package p; import "net";func f(){d:=net.Dialer{};f:=d.DialContext;_ = f}`,
		`package p; import . "net"`, `package p; import "net/http"`,
	} {
		if processBoundaryUnix(source, true) {
			t.Fatal("non-Unix plant accepted")
		}
	}
	if !processBoundaryUnix(`package p;import "net";func f(){d:=net.Dialer{};d.DialContext(nil,"unix","explicit")}`, true) {
		t.Fatal("explicit Unix positive refused")
	}
	e := filepath.WalkDir("../..", func(path string, d os.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() && (d.Name() == "vendor" || d.Name() == ".temp") {
			return filepath.SkipDir
		}
		if !d.IsDir() && strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go") {
			b, e := os.ReadFile(path)
			if e != nil {
				return e
			}
			allowUnix := filepath.ToSlash(path) == "../../sign/sshagent/sshagent.go"
			if !processBoundaryUnix(string(b), allowUnix) {
				t.Errorf("process boundary: %s", path)
			}
		}
		return nil
	})
	if e != nil {
		t.Fatal(e)
	}
}

// Opaque ref IDs keep embedded colons; ambiguous configured prefixes and invalid
// versions refuse instead of silently choosing a different space or version.
func TestReportedRefSelection(t *testing.T) {
	c := localConfig{Spaces: []localSpace{{ID: "space:a"}}}
	r, e := parseReportedRef("space:a:record:x:y:2", c)
	if e != nil || r != (dependencyRef{"space:a", "record:x:y", 2}) {
		t.Fatal(r, e)
	}
	for _, raw := range []string{"space:a:record:x:0", "space:a:record:x:-1", "space:a:record:x:no", "space:a::1", "missing"} {
		if _, e := parseReportedRef(raw, c); e == nil {
			t.Fatal("invalid ref accepted", raw)
		}
	}
	c.Spaces = append(c.Spaces, localSpace{ID: "space:a:record"})
	if _, e := parseReportedRef("space:a:record:x:1", c); classify(e).Code != "usage" {
		t.Fatal(e)
	}
}

// Neither packet form can mask anti-rollback failure or return record prose;
// restoring the exact accepted head makes the same visible dependency reportable.
func TestConflictsPreserveRewriteRefusal(t *testing.T) {
	h := newCLI(t)
	h.appendRecord("record:dependency", "Dependency")
	h.invoke(h.owner, 7, "conflicts", "--ref", "space:test:record:dependency:1")
	head := strings.TrimSpace(h.git(h.remote, "rev-parse", "main"))
	h.git(h.remote, "update-ref", "refs/heads/main", h.genesis, head)
	r, _ := h.invoke(h.owner, 4, "conflicts", "--ref", "space:test:record:dependency:1")
	if errorCodeOf(r) != "history_rewritten" || r["data"] != nil {
		t.Fatal(r)
	}
	exact, _ := h.invoke(h.owner, 4, "conflicts", "--space", "space:test", "--id", "record:dependency")
	if errorCodeOf(exact) != "history_rewritten" || exact["data"] != nil {
		t.Fatal("exact error leaked explain payload", exact)
	}
	h.git(h.remote, "update-ref", "refs/heads/main", head, h.genesis)
	h.invoke(h.owner, 7, "conflicts", "--ref", "space:test:record:dependency:1")
}
