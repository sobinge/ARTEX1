package server

import (
	"os"
	"path/filepath"
	"strings"
)

// detectProxyGuardShims finds host-level tool wrappers that force traffic through
// a fixed proxy (e.g. a `proxy-guard` PATH shim wrapping nmap/httpx/nuclei with
// proxychains). Such a wrapper overrides the egress the platform injects, so an
// agent configured for Tor can still exit through the operator's proxy — silently.
// We cannot defeat it (the wrapper is outside the platform), but we must say so
// instead of claiming Tor coverage we do not have.
func detectProxyGuardShims() (dirs []string, count int) {
	seen := map[string]bool{}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" || seen[dir] {
			continue
		}
		seen[dir] = true
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		hits := 0
		for _, e := range entries {
			p := filepath.Join(dir, e.Name())
			fi, err := os.Lstat(p)
			if err != nil || fi.Mode()&os.ModeSymlink == 0 {
				continue
			}
			target, err := os.Readlink(p)
			if err != nil {
				continue
			}
			if strings.Contains(filepath.Base(target), "proxy-guard") {
				hits++
			}
		}
		if hits > 0 {
			dirs = append(dirs, dir)
			count += hits
		}
	}
	return dirs, count
}
