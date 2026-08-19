package version

import "testing"

func TestString(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	Version = "1.2.3"
	if got := String(); got != "ward 1.2.3" {
		t.Fatalf("String() = %q", got)
	}
}
