package component

const (
	// Container represents running inside a container
	Container = "container"
	// Darwin represents running on Mac OSX
	Darwin = "darwin"
	// Linux represents running on Linux
	Linux = "linux"
	// Windows represents running on Windows
	Windows = "windows"
)

const (
	// I386 represents the i386 architecture
	I386 = "386"
	// AMD64 represents the amd64 architecture
	AMD64 = "amd64"
	// ARM64 represents the arm64 architecture
	ARM64 = "arm64"
	// PPC64 represents the ppc64el architecture
	PPC64 = "ppc64el"
)

// Platforms defines the platforms that a component can support
var Platforms = []struct {
	OS   string
	Arch string
	GOOS string
}{
	{
		OS:   Container,
		Arch: AMD64,
		GOOS: Linux,
	},
	{
		OS:   Container,
		Arch: ARM64,
		GOOS: Linux,
	},
	{
		OS:   Container,
		Arch: PPC64,
		GOOS: Linux,
	},
	{
		OS:   Darwin,
		Arch: AMD64,
		GOOS: Darwin,
	},
	{
		OS:   Darwin,
		Arch: ARM64,
		GOOS: Darwin,
	},
	{
		OS:   Linux,
		Arch: I386,
		GOOS: Linux,
	},
	{
		OS:   Linux,
		Arch: AMD64,
		GOOS: Linux,
	},
	{
		OS:   Linux,
		Arch: ARM64,
		GOOS: Linux,
	},
	{
		OS:   Linux,
		Arch: PPC64,
		GOOS: Linux,
	},
	{
		OS:   Windows,
		Arch: I386,
		GOOS: Windows,
	},
	{
		OS:   Windows,
		Arch: AMD64,
		GOOS: Windows,
	},
	{
		OS:   Windows,
		Arch: ARM64,
		GOOS: Windows,
	},
}
