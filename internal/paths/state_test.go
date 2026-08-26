package paths

import (
	pathpkg "path"
	"path/filepath"
	"testing"
)

func TestResolveStateDir(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		goos string
		env  map[string]string
		home string
		want string
	}{
		{name: "xdg", goos: "linux", env: map[string]string{"XDG_STATE_HOME": "/state"}, home: "/home/me", want: pathpkg.Join("/state", "ward", "core")},
		{name: "unix fallback", goos: "darwin", env: map[string]string{}, home: "/Users/me", want: pathpkg.Join("/Users/me", ".local", "state", "ward", "core")},
		{name: "windows slash", goos: "windows", env: map[string]string{"LOCALAPPDATA": filepath.Clean("C:/Users/me/AppData/Local")}, home: "ignored", want: filepath.Join(filepath.Clean("C:/Users/me/AppData/Local"), "Ward", "state", "core")},
		{name: "windows backslash", goos: "windows", env: map[string]string{"LOCALAPPDATA": `C:\Users\me\AppData\Local`}, home: "ignored", want: `C:\Users\me\AppData\Local\Ward\state\core`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := resolveStateDir(Environment{GOOS: test.goos, Home: test.home, Getenv: func(key string) string { return test.env[key] }})
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("state dir = %q, want %q", got, test.want)
			}
		})
	}
}

func TestResolveStateDirRejectsMissingOrRelativeAuthorityRoots(t *testing.T) {
	t.Parallel()
	tests := []Environment{
		{GOOS: "linux", Home: "relative", Getenv: func(string) string { return "" }},
		{GOOS: "linux", Home: "/home/me", Getenv: func(key string) string {
			if key == "XDG_STATE_HOME" {
				return "relative"
			}
			return ""
		}},
		{GOOS: "windows", Home: "ignored", Getenv: func(string) string { return "" }},
		{GOOS: "windows", Home: "ignored", Getenv: func(key string) string {
			if key == "LOCALAPPDATA" {
				return "relative"
			}
			return ""
		}},
	}
	for _, test := range tests {
		if _, err := resolveStateDir(test); err == nil {
			t.Fatalf("resolveStateDir(%+v) accepted an invalid authority root", test)
		}
	}
}
