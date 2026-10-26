package main

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"runtime/debug"
	"strings"
	"testing"
)

// Version reports module/VCS metadata without inventing missing provenance;
// malformed or absent modified settings remain unknown, not a clean-tree claim.
func TestBuildVersion(t *testing.T) {
	for _, tc := range []struct {
		name       string
		info       *debug.BuildInfo
		ok         bool
		json, text string
	}{
		{"unavailable", nil, false, `{"version":"(devel)","vcs_revision":"","vcs_modified":null}`, "memory (devel) revision unknown modified unknown"},
		{"no vcs", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}}, true, `{"version":"v1.2.3","vcs_revision":"","vcs_modified":null}`, "memory v1.2.3 revision unknown modified unknown"},
		{"clean", &debug.BuildInfo{Main: debug.Module{Version: "v1.2.3"}, Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "abc123"}, {Key: "vcs.modified", Value: "false"}}}, true, `{"version":"v1.2.3","vcs_revision":"abc123","vcs_modified":false}`, "memory v1.2.3 revision abc123 modified false"},
		{"dirty", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "def456"}, {Key: "vcs.modified", Value: "true"}}}, true, `{"version":"(devel)","vcs_revision":"def456","vcs_modified":true}`, "memory (devel) revision def456 modified true"},
		{"malformed", &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.modified", Value: "maybe"}}}, true, `{"version":"(devel)","vcs_revision":"","vcs_modified":null}`, "memory (devel) revision unknown modified unknown"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := buildVersion(tc.info, tc.ok)
			b, e := json.Marshal(v)
			if e != nil || string(b) != tc.json || v.String() != tc.text {
				t.Fatal(string(b), v, e)
			}
		})
	}
}

// The built command exposes a closed three-field version payload without a home,
// and its plain output identifies the same module version and provenance fields.
func TestVersionCommand(t *testing.T) {
	cmd := exec.Command(binary, "--json", "version")
	b, e := cmd.Output()
	if e != nil {
		t.Fatal(e)
	}
	var out struct {
		Type, Command, DataClassification string
		Data                              map[string]json.RawMessage
		Error                             any
	}
	if e = json.Unmarshal(b, &out); e != nil || out.Type != "result" || out.Command != "version" || len(out.Data) != 3 || out.Error != nil {
		t.Fatal(string(b), e)
	}
	for _, name := range []string{"version", "vcs_revision", "vcs_modified"} {
		if _, ok := out.Data[name]; !ok {
			t.Fatal("missing", name)
		}
	}
	var moduleVersion string
	if json.Unmarshal(out.Data["version"], &moduleVersion) != nil || moduleVersion == "" || moduleVersion == "dev" {
		t.Fatal(string(b))
	}
	cmd = exec.Command(binary, "version")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	plain, e := cmd.Output()
	if e != nil || stderr.Len() != 0 || !strings.HasPrefix(string(plain), "memory "+moduleVersion+" revision ") || !strings.Contains(string(plain), " modified ") {
		t.Fatal(string(plain), stderr.String(), e)
	}
}
