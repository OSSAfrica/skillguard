package cmd

import (
	"runtime/debug"
	"testing"
)

func TestSourceVersion(t *testing.T) {
	info := &debug.BuildInfo{Settings: []debug.BuildSetting{{Key: "vcs.revision", Value: "123456789abcdef"}, {Key: "vcs.modified", Value: "true"}}}
	if got := sourceVersion("dev", info); got != "dev+123456789abc.dirty" {
		t.Fatal(got)
	}
	if got := sourceVersion("1.2.0", info); got != "1.2.0" {
		t.Fatal(got)
	}
	if got := sourceVersion("dev", nil); got != "dev" {
		t.Fatal(got)
	}
	info.Main.Version = "v1.2.0+dirty"
	if got := sourceVersion("dev", info); got != "dev+123456789abc.dirty" {
		t.Fatal(got)
	}
	moduleInfo := &debug.BuildInfo{Main: debug.Module{Version: "v1.2.0"}}
	if got := sourceVersion("dev", moduleInfo); got != "v1.2.0" {
		t.Fatal(got)
	}
}

func TestUpdateCommandRejectsArguments(t *testing.T) {
	c := newUpdateCommand()
	c.SetArgs([]string{"unexpected"})
	if err := c.Execute(); err == nil {
		t.Fatal("expected argument rejection")
	}
}
