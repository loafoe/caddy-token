/*
Copyright © 2024 Andy Lo-A-Foe <andy.loafoe@gmail.com>
*/
package main

import (
	"fmt"
	"regexp"
	"runtime"
	"runtime/debug"

	"github.com/spf13/cobra"
)

// pseudoVersionRE matches a Go pseudo-version's trailing timestamp and commit,
// e.g. v1.1.2-0.20260617112814-04145d123848 -> "20260617112814", "04145d123848".
// Used as a fallback when building from a proxy-downloaded module, where Go does
// not embed the vcs.revision/vcs.time build settings.
var pseudoVersionRE = regexp.MustCompile(`(\d{14})-([0-9a-f]{12})$`)

// Build metadata. These default to "dev"/"none" and can be overridden at build
// time with -ldflags, e.g.:
//
//	go build -ldflags "-X main.version=v1.2.0 -X main.commit=$(git rev-parse --short HEAD) -X main.date=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
//
// When not injected, the values fall back to the VCS information Go embeds in
// the binary (commit, build date and dirty state) via runtime/debug.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// resolveBuildInfo fills in any build metadata not provided via -ldflags using
// the VCS data the Go toolchain embeds in the binary.
func resolveBuildInfo() (ver, rev, built string) {
	ver, rev, built = version, commit, date

	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ver, rev, built
	}

	// Prefer the module version if no explicit version was injected.
	if ver == "dev" && info.Main.Version != "" && info.Main.Version != "(devel)" {
		ver = info.Main.Version
	}

	var modified bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if rev == "none" && s.Value != "" {
				rev = s.Value
				if len(rev) > 12 {
					rev = rev[:12]
				}
			}
		case "vcs.time":
			if built == "unknown" && s.Value != "" {
				built = s.Value
			}
		case "vcs.modified":
			modified = s.Value == "true"
		}
	}
	if modified && rev != "none" {
		rev += "-dirty"
	}

	// Proxy-downloaded modules carry no vcs.* settings; recover the commit and
	// build date from the pseudo-version's trailing timestamp-commit segment.
	if m := pseudoVersionRE.FindStringSubmatch(ver); m != nil {
		if rev == "none" {
			rev = m[2]
		}
		if built == "unknown" {
			t := m[1] // YYYYMMDDhhmmss
			built = fmt.Sprintf("%s-%s-%sT%s:%s:%sZ",
				t[0:4], t[4:6], t[6:8], t[8:10], t[10:12], t[12:14])
		}
	}
	return ver, rev, built
}

// versionCmd represents the version command
var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Print the build version",
	Long:    `Print the build version, commit and date of caddy-token-gen.`,
	Run: func(cmd *cobra.Command, args []string) {
		ver, rev, built := resolveBuildInfo()
		fmt.Printf("caddy-token-gen %s\n", ver)
		fmt.Printf("  commit: %s\n", rev)
		fmt.Printf("  built:  %s\n", built)
		fmt.Printf("  go:     %s %s/%s\n", runtime.Version(), runtime.GOOS, runtime.GOARCH)
	},
}

func init() {
	rootCmd.AddCommand(versionCmd)
}
