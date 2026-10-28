package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type transport func(*http.Request) (*http.Response, error)

func (f transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func archiveFor(t *testing.T, headers []*tar.Header, contents []string) []byte {
	t.Helper()
	var b bytes.Buffer
	gz := gzip.NewWriter(&b)
	tw := tar.NewWriter(gz)
	for i, h := range headers {
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(contents[i])); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func fixtureReleases(t *testing.T, requests *[]string, corrupt bool) *Releases {
	t.Helper()
	return &Releases{API: "https://fixture.invalid/latest", Base: "https://fixture.invalid/download/", Client: &http.Client{Transport: transport(func(req *http.Request) (*http.Response, error) {
		*requests = append(*requests, req.URL.Path)
		var body []byte
		status := 200
		if req.URL.Path == "/latest" {
			body = []byte(`{"tag_name":"v1.2.0"}`)
		} else {
			parts := strings.Split(req.URL.Path, "/")
			version := strings.TrimPrefix(parts[len(parts)-2], "v")
			name := "skillguard"
			if runtime.GOOS == "windows" {
				name += ".exe"
			}
			content := "old"
			if version == "1.2.0" {
				content = "new"
			}
			archive := archiveFor(t, []*tar.Header{{Name: name, Typeflag: tar.TypeReg, Size: int64(len(content)), Mode: 0o600}}, []string{content})
			asset := fmt.Sprintf("skillguard_%s_%s_%s.tar.gz", version, runtime.GOOS, runtime.GOARCH)
			switch parts[len(parts)-1] {
			case "checksums.txt":
				body = fmt.Appendf(nil, "%x  %s\n", sha256.Sum256(archive), asset)
			case asset:
				body = archive
				if corrupt {
					body = []byte("corrupt")
				}
			default:
				status = 404
			}
		}
		return &http.Response{StatusCode: status, Body: io.NopCloser(bytes.NewReader(body)), Header: make(http.Header)}, nil
	})}}
}

func TestCompare(t *testing.T) {
	for _, tt := range []struct {
		a, b    string
		want    int
		invalid bool
	}{
		{"v1.2.0", "1.2.0", 0, false}, {"1.9.0", "1.10.0", -1, false}, {"2.0.0", "1.99.99", 1, false},
		{"dev+abc", "1.0.0", 0, true}, {"1.0.0-rc.1", "1.0.0", 0, true}, {"01.0.0", "1.0.0", 0, true},
	} {
		got, err := Compare(tt.a, tt.b)
		if (err != nil) != tt.invalid || got != tt.want {
			t.Errorf("Compare(%q,%q)=%d,%v", tt.a, tt.b, got, err)
		}
	}
}

func TestReleaseIntegrity(t *testing.T) {
	for _, corrupt := range []bool{false, true} {
		var requests []string
		r := fixtureReleases(t, &requests, corrupt)
		binary, err := r.Binary(context.Background(), "1.2.0", runtime.GOOS, runtime.GOARCH)
		if corrupt && (err == nil || !strings.Contains(err.Error(), "checksum mismatch")) {
			t.Fatalf("corruption accepted: %v", err)
		}
		if !corrupt && (err != nil || string(binary) != "new") {
			t.Fatalf("valid archive rejected: %v", err)
		}
	}
}

func TestUnsafeArchives(t *testing.T) {
	for _, headers := range [][]*tar.Header{
		{{Name: "../skillguard", Typeflag: tar.TypeReg, Size: 1}},
		{{Name: "skillguard", Typeflag: tar.TypeSymlink, Linkname: "/tmp/other"}},
		{{Name: "skillguard", Typeflag: tar.TypeReg, Size: 1}, {Name: "skillguard", Typeflag: tar.TypeReg, Size: 1}},
		{{Name: "other", Typeflag: tar.TypeReg, Size: 1}},
	} {
		contents := make([]string, len(headers))
		for i, h := range headers {
			if h.Size > 0 {
				contents[i] = "x"
			}
		}
		if _, err := extract(archiveFor(t, headers, contents), "skillguard"); err == nil {
			t.Errorf("accepted unsafe/missing executable: %+v", headers)
		}
	}
}

func executable(t *testing.T, name string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func TestReplaceFailureAndRollback(t *testing.T) {
	for _, failure := range []string{"none", "stage", "installed", "changed"} {
		t.Run(failure, func(t *testing.T) {
			path := executable(t, "skillguard")
			calls := 0
			run := func(_ context.Context, name string, _ ...string) ([]byte, error) {
				calls++
				if failure == "changed" && calls == 1 {
					if err := os.WriteFile(path, []byte("other"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if failure == "stage" && calls == 1 || failure == "installed" && name == path {
					return nil, fmt.Errorf("verification failed")
				}
				return []byte("skillguard version 1.2.0\n"), nil
			}
			err := Replace(context.Background(), path, []byte("old"), []byte("new"), "1.2.0", run)
			if (err != nil) != (failure != "none") {
				t.Fatalf("unexpected result %v", err)
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := "old"
			if failure == "none" {
				want = "new"
			}
			if failure == "changed" {
				want = "other"
			}
			if string(data) != want {
				t.Fatalf("got %q, want %q", data, want)
			}
			if _, err := os.Stat(path + ".update-lock"); !os.IsNotExist(err) {
				t.Fatal("update lock was not released")
			}
		})
	}
}

func TestCheckDoesNotDownloadOrExecuteUpdate(t *testing.T) {
	path := executable(t, "skillguard")
	t.Setenv("PATH", t.TempDir())
	var requests []string
	var out bytes.Buffer
	err := Execute(context.Background(), Options{Executable: path, Version: "1.1.0", Distribution: "release", Check: true, Out: &out, Releases: fixtureReleases(t, &requests, false), Run: func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("unexpected subprocess")
		return nil, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) != 1 || requests[0] != "/latest" {
		t.Fatalf("unexpected requests %v", requests)
	}
	data, _ := os.ReadFile(path)
	if string(data) != "old" || !strings.Contains(out.String(), "Update available") {
		t.Fatal(out.String())
	}
}

func TestPinnedAndProtectedInstallations(t *testing.T) {
	for _, kind := range []string{"plugin", "custom-cache", "launcher"} {
		t.Run(kind, func(t *testing.T) {
			root := t.TempDir()
			dir := root
			switch kind {
			case "plugin":
				dir = filepath.Join(root, "plugin-runtime", "v1.1.0", "linux_amd64")
			case "custom-cache":
				dir = filepath.Join(root, "v1.1.0", "linux_amd64")
			}
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "skillguard")
			if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
				t.Fatal(err)
			}
			marker := "skillguard_1.1.0_linux_amd64.tar.gz"
			if kind == "launcher" {
				marker = "installation.json"
			}
			if err := os.WriteFile(filepath.Join(dir, marker), []byte("{}"), 0o600); err != nil {
				t.Fatal(err)
			}
			i, err := Detect(context.Background(), path, "release", "1.1.0", Run)
			if err != nil || i.Method == "standalone" {
				t.Fatalf("pinned installation not protected: %+v %v", i, err)
			}
		})
	}
}

func TestHomebrewOwnership(t *testing.T) {
	root := t.TempDir()
	caskRoot := filepath.Join(root, "Caskroom", "skillguard")
	dir := filepath.Join(caskRoot, "1.1.0")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	owned := filepath.Join(dir, "skillguard")
	if err := os.WriteFile(owned, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	owned, err := filepath.EvalSymlinks(owned)
	if err != nil {
		t.Fatal(err)
	}
	run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if args[0] == "--caskroom" {
			return []byte(caskRoot), nil
		}
		return []byte(`{"casks":[{"token":"skillguard","tap":"ossafrica/skillguard","installed":"1.1.0","version":"1.2.0"}]}`), nil
	}
	i, ok := detectBrew(context.Background(), owned, "/fixture/brew", run)
	if !ok || i.Method != "homebrew" || i.Available != "1.2.0" {
		t.Fatalf("ownership not detected: %+v", i)
	}
	if _, ok := detectBrew(context.Background(), executable(t, "skillguard"), "/fixture/brew", run); ok {
		t.Fatal("unrelated standalone copy treated as Homebrew")
	}
	other := filepath.Join(root, "Caskroom", "skillguard-evil", "1.1.0", "skillguard")
	if _, ok := detectBrew(context.Background(), other, "/fixture/brew", run); ok {
		t.Fatal("path prefix treated as ownership")
	}
}

func TestReleaseRequestFailures(t *testing.T) {
	for _, body := range []string{`{"tag_name":"v1.0.0","prerelease":true}`, `{"tag_name":"v1.0.0","draft":true}`, `{"tag_name":"dev"}`, `invalid`} {
		r := &Releases{API: "https://fixture.invalid", Client: &http.Client{Transport: transport(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(body))}, nil
		})}}
		if _, err := r.Latest(context.Background()); err == nil {
			t.Errorf("accepted invalid release %s", body)
		}
	}
}

func TestStandaloneUpdate(t *testing.T) {
	for _, scenario := range []string{"success", "corrupt", "modified", "unknown"} {
		t.Run(scenario, func(t *testing.T) {
			t.Setenv("PATH", t.TempDir())
			path := executable(t, "skillguard")
			if scenario == "modified" {
				if err := os.WriteFile(path, []byte("modified"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var requests []string
			var out bytes.Buffer
			distribution := "release"
			if scenario == "unknown" {
				distribution = "unknown"
			}
			err := Execute(context.Background(), Options{Executable: path, Version: "1.1.0", Distribution: distribution, Out: &out, Releases: fixtureReleases(t, &requests, scenario == "corrupt"), Run: func(_ context.Context, _ string, args ...string) ([]byte, error) {
				if len(args) != 1 || args[0] != "--version" {
					t.Fatal("unexpected command", args)
				}
				return []byte("skillguard version 1.2.0\n"), nil
			}})
			if (err != nil) != (scenario != "success") {
				t.Fatalf("unexpected result %v: %s", err, out.String())
			}
			data, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			want := "old"
			if scenario == "success" {
				want = "new"
			}
			if scenario == "modified" {
				want = "modified"
			}
			if string(data) != want {
				t.Fatalf("got %q, want %q", data, want)
			}
			if scenario == "unknown" && len(requests) != 1 {
				t.Fatal("unknown installation downloaded archives")
			}
		})
	}
}

func TestSymlinkInstallationAndSourceGuidance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires special privileges on Windows")
	}
	t.Setenv("PATH", t.TempDir())
	path := executable(t, "skillguard")
	link := filepath.Join(t.TempDir(), "skillguard")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	i, err := Detect(context.Background(), link, "source", "dev", Run)
	if err != nil || i.Path != path || i.Method != "source" {
		t.Fatalf("unexpected installation %+v %v", i, err)
	}
	var requests []string
	var out bytes.Buffer
	if err := Execute(context.Background(), Options{Executable: link, Version: "dev+abc", Distribution: "source", Check: true, Out: &out, Releases: fixtureReleases(t, &requests, false)}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "cannot be compared") || !strings.Contains(out.String(), "rebuild") {
		t.Fatal(out.String())
	}
}

func TestHomebrewUpgradeUsesManagerAndVerifiesResult(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Homebrew installation uses POSIX symlinks")
	}
	for _, scenario := range []string{"success", "behind", "failure"} {
		t.Run(scenario, func(t *testing.T) {
			prefix := t.TempDir()
			bin := filepath.Join(prefix, "bin")
			root := filepath.Join(prefix, "Caskroom", "skillguard")
			installed := "1.2.0"
			if scenario == "behind" {
				installed = "1.1.0"
			}
			dir := filepath.Join(root, installed)
			for _, directory := range []string{bin, dir} {
				if err := os.MkdirAll(directory, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			brew := filepath.Join(bin, "brew")
			if err := os.WriteFile(brew, []byte("fake"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(brew, 0o700); err != nil {
				t.Fatal(err)
			} // Executable lookup only; the fixture is never executed.
			t.Setenv("PATH", bin)
			path := filepath.Join(dir, "skillguard")
			if err := os.WriteFile(path, []byte("managed"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(path, filepath.Join(bin, "skillguard")); err != nil {
				t.Fatal(err)
			}
			run := func(_ context.Context, _ string, args ...string) ([]byte, error) {
				switch args[0] {
				case "--prefix":
					return []byte(prefix), nil
				case "--caskroom":
					return []byte(root), nil
				case "info":
					return fmt.Appendf(nil, `{"casks":[{"token":"skillguard","tap":"ossafrica/skillguard","installed":%q,"version":"1.2.0"}]}`, installed), nil
				case "--version":
					return []byte("skillguard version " + installed), nil
				default:
					t.Fatal("unexpected read command", args)
					return nil, nil
				}
			}
			var calls []string
			upgrade := func(_ context.Context, name string, _ io.Writer, args ...string) error {
				if name != brew {
					t.Fatalf("wrong manager %s", name)
				}
				calls = append(calls, strings.Join(args, " "))
				if scenario == "failure" {
					return fmt.Errorf("synthetic manager failure")
				}
				return nil
			}
			err := upgradeBrew(context.Background(), Installation{Brew: brew}, "1.1.0", io.Discard, run, upgrade)
			if (err != nil) != (scenario != "success") {
				t.Fatalf("unexpected result: %v", err)
			}
			if scenario != "failure" && strings.Join(calls, ";") != "update;upgrade --cask "+cask {
				t.Fatal("wrong upgrade commands", calls)
			}
		})
	}
}
