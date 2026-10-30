package cmd

import (
	"runtime/debug"
	"strings"
)

func sourceVersion(version string, info *debug.BuildInfo) string {
	if version != "dev" {
		return version
	}
	if info == nil {
		return "dev"
	}
	revision, modified := "", false
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			revision = setting.Value
		}
		if setting.Key == "vcs.modified" {
			modified = setting.Value == "true"
		}
	}
	if revision == "" {
		if info.Main.Version != "" && info.Main.Version != "(devel)" {
			return info.Main.Version
		}
		return "dev"
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	version = "dev+" + revision
	if modified {
		version += ".dirty"
	}
	return version
}

func init() {
	info, _ := debug.ReadBuildInfo()
	Version = sourceVersion(Version, info)
	rootCmd.Version = Version
	rootCmd.Long = strings.Replace(rootCmd.Long, "Version: dev", "Version: "+Version, 1)
}
