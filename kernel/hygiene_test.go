package kernel

import (
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"strconv"
	"strings"
	"testing"
)

// Keep this explicit: new imports require review for kernel purity.
var pureStandardImports = map[string]bool{
	"bytes": true, "cmp": true,
	"container/heap": true, "container/list": true, "container/ring": true,
	"crypto/sha256": true, "crypto/sha512": true,
	"encoding/base64": true, "encoding/binary": true,
	"encoding/hex": true, "encoding/json": true,
	"errors": true, "fmt": true, "hash": true, "hash/fnv": true,
	"io": true, "iter": true, "maps": true,
	"math": true, "math/big": true, "math/bits": true,
	"regexp": true, "slices": true, "sort": true,
	"strconv": true, "strings": true, "unicode": true, "unicode/utf8": true,
}

func checkKernelImports(filename, source string) error {
	f, err := parser.ParseFile(token.NewFileSet(), filename, source, parser.ImportsOnly)
	if err != nil {
		return err
	}
	for _, spec := range f.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			return err
		}
		if !pureStandardImports[path] {
			return fmt.Errorf("%s: forbidden kernel import %q", filename, path)
		}
	}
	return nil
}

// TestKernelHygiene proves all non-test Go files in this package use only the explicit pure-stdlib allowlist.
func TestKernelHygiene(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			source, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkKernelImports(name, string(source)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestKernelImportControls proves errors is accepted and planted forbidden imports are rejected by name, including aliases.
func TestKernelImportControls(t *testing.T) {
	for _, test := range []struct {
		name   string
		source string
		denied string
	}{
		{name: "pure errors", source: `package kernel; import "errors"`},
		{name: "no imports", source: `package kernel`},
		{name: "network control", source: `package kernel; import "net/http"`, denied: "net/http"},
		{name: "net", source: `package kernel; import "net"`, denied: "net"},
		{name: "os", source: `package kernel; import "os"`, denied: "os"},
		{name: "exec alias", source: `package kernel; import process "os/exec"`, denied: "os/exec"},
		{name: "syscall", source: `package kernel; import "syscall"`, denied: "syscall"},
		{name: "plugin blank", source: `package kernel; import _ "plugin"`, denied: "plugin"},
		{name: "unsafe dot", source: `package kernel; import . "unsafe"`, denied: "unsafe"},
		{name: "third party", source: `package kernel; import "example.com/library"`, denied: "example.com/library"},
		{name: "module internal", source: `package kernel; import "github.com/relux-works/swarma-memory/space"`, denied: "github.com/relux-works/swarma-memory/space"},
		{name: "mixed imports", source: "package kernel\nimport (\"errors\"; \"net/http\")", denied: "net/http"},
		{name: "escaped import", source: `package kernel; import "net\x2fhttp"`, denied: "net/http"},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := checkKernelImports("control.go", test.source)
			if test.denied == "" {
				if err != nil {
					t.Fatalf("pure source refused: %v", err)
				}
				return
			}
			want := fmt.Sprintf("control.go: forbidden kernel import %q", test.denied)
			if err == nil || err.Error() != want {
				t.Fatalf("refusal = %v; want %s", err, want)
			}
		})
	}
}
