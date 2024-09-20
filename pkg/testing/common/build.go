package common

// Build describes a build and its paths.
type Build struct {
	// Version of the Elastic Agent build.
	Version string
	// Type of OS this build is for.
	Type string
	// Arch is architecture this build is for.
	Arch string
	// Path is the path to the build.
	Path string
	// SHA512 is the path to the SHA512 file.
	SHA512Path string
}
