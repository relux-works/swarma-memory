package main

import (
	"fmt"
	"runtime/debug"
	"strconv"
)

type versionData struct {
	Version     string `json:"version"`
	VCSRevision string `json:"vcs_revision"`
	VCSModified *bool  `json:"vcs_modified"`
}

func buildVersion(info *debug.BuildInfo, ok bool) versionData {
	result := versionData{Version: "(devel)"}
	if !ok || info == nil {
		return result
	}
	if info.Main.Version != "" {
		result.Version = info.Main.Version
	}
	for _, setting := range info.Settings {
		switch setting.Key {
		case "vcs.revision":
			result.VCSRevision = setting.Value
		case "vcs.modified":
			if value, err := strconv.ParseBool(setting.Value); err == nil {
				result.VCSModified = &value
			}
		}
	}
	return result
}

func currentVersion() versionData { return buildVersion(debug.ReadBuildInfo()) }

func (v versionData) String() string {
	revision, modified := v.VCSRevision, "unknown"
	if revision == "" {
		revision = "unknown"
	}
	if v.VCSModified != nil {
		modified = strconv.FormatBool(*v.VCSModified)
	}
	return fmt.Sprintf("memory %s revision %s modified %s", v.Version, revision, modified)
}
