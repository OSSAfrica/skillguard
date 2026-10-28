// Package update implements explicit, installation-aware CLI updates.
package update

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

const repository = "https://github.com/OSSAfrica/skillguard"
const maxArchive = 64 << 20

var stableVersion = regexp.MustCompile(`^v?(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)

// Compare compares stable release versions, rejecting development/prerelease labels.
func Compare(a, b string) (int, error) {
	x, y := stableVersion.FindStringSubmatch(a), stableVersion.FindStringSubmatch(b)
	if x == nil || y == nil {
		return 0, fmt.Errorf("cannot compare non-stable versions %q and %q", a, b)
	}
	for i := 1; i <= 3; i++ {
		xi, err := strconv.ParseUint(x[i], 10, 64)
		if err != nil {
			return 0, err
		}
		yi, err := strconv.ParseUint(y[i], 10, 64)
		if err != nil {
			return 0, err
		}
		if xi < yi {
			return -1, nil
		}
		if xi > yi {
			return 1, nil
		}
	}
	return 0, nil
}

type Releases struct {
	Client *http.Client
	API    string
	Base   string
}

func NewReleases() *Releases {
	return &Releases{Client: &http.Client{Timeout: 90 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 || req.URL.Scheme != "https" {
			return fmt.Errorf("unsafe release redirect")
		}
		switch req.URL.Hostname() {
		case "github.com", "api.github.com", "release-assets.githubusercontent.com", "objects.githubusercontent.com", "github-releases.githubusercontent.com":
			return nil
		default:
			return fmt.Errorf("unexpected release redirect host")
		}
	}}, API: "https://api.github.com/repos/OSSAfrica/skillguard/releases/latest", Base: repository + "/releases/download/"}
}

func (r *Releases) get(ctx context.Context, address string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, address, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "skillguard-update")
	resp, err := r.Client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("release request returned HTTP %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("release response exceeds size limit")
	}
	return data, nil
}

func (r *Releases) Latest(ctx context.Context) (string, error) {
	data, err := r.get(ctx, r.API, 2<<20)
	if err != nil {
		return "", err
	}
	var release struct {
		Tag        string `json:"tag_name"`
		Draft      bool   `json:"draft"`
		Prerelease bool   `json:"prerelease"`
	}
	if err := json.Unmarshal(data, &release); err != nil {
		return "", err
	}
	if !stableVersion.MatchString(release.Tag) || release.Draft || release.Prerelease {
		return "", fmt.Errorf("latest release is not a stable version")
	}
	return strings.TrimPrefix(release.Tag, "v"), nil
}

// Binary verifies the archive before extracting only its expected regular executable.
func (r *Releases) Binary(ctx context.Context, version, system, arch string) ([]byte, error) {
	if !stableVersion.MatchString(version) {
		return nil, fmt.Errorf("invalid release version")
	}
	if (system != "darwin" && system != "linux" && system != "windows") || (arch != "amd64" && arch != "arm64") {
		return nil, fmt.Errorf("unsupported release platform %s/%s", system, arch)
	}
	version = strings.TrimPrefix(version, "v")
	asset := "skillguard_" + version + "_" + system + "_" + arch + ".tar.gz"
	base := r.Base + url.PathEscape("v"+version) + "/"
	checksums, err := r.get(ctx, base+"checksums.txt", 1<<20)
	if err != nil {
		return nil, err
	}
	want := ""
	for _, line := range strings.Split(string(checksums), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && strings.TrimPrefix(fields[1], "*") == asset {
			if want != "" {
				return nil, fmt.Errorf("duplicate checksum for %s", asset)
			}
			want = strings.ToLower(fields[0])
		}
	}
	if decoded, err := hex.DecodeString(want); err != nil || len(decoded) != sha256.Size {
		return nil, fmt.Errorf("missing or invalid checksum for %s", asset)
	}
	archive, err := r.get(ctx, base+asset, maxArchive)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(archive)
	if hex.EncodeToString(sum[:]) != want {
		return nil, fmt.Errorf("release archive checksum mismatch")
	}
	name := "skillguard"
	if system == "windows" {
		name += ".exe"
	}
	return extract(archive, name)
}

func extract(data []byte, name string) ([]byte, error) {
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(io.LimitReader(gz, maxArchive+1))
	var binary []byte
	for count := 0; ; count++ {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		if count >= 100 || h.Size < 0 || h.Size > maxArchive || strings.HasPrefix(h.Name, "/") || strings.Contains(h.Name, "\\") {
			return nil, fmt.Errorf("unsafe release archive")
		}
		for _, part := range strings.Split(h.Name, "/") {
			if part == ".." {
				return nil, fmt.Errorf("unsafe release archive path")
			}
		}
		if h.Typeflag != tar.TypeReg && h.Typeflag != tar.TypeDir {
			return nil, fmt.Errorf("unsupported archive entry")
		}
		if h.Name != name {
			continue
		}
		if binary != nil || h.Typeflag != tar.TypeReg || h.Size == 0 {
			return nil, fmt.Errorf("invalid or duplicate executable")
		}
		binary, err = io.ReadAll(io.LimitReader(tr, maxArchive+1))
		if err != nil {
			return nil, err
		}
	}
	if len(binary) == 0 {
		return nil, fmt.Errorf("release archive has no %s", name)
	}
	return binary, nil
}
