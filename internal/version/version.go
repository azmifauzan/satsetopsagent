package version

// Version is overridden at build time via -ldflags.
var Version = "dev"

func String() string {
	return Version
}
