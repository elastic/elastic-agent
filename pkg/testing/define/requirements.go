package define

const (
	// DarwinAMD64 runs test on an amd64 Mac OS host
	DarwinAMD64 = "darwin/amd64"
	// DarwinARM64 runs test on an arm64 Mac OS host
	DarwinARM64 = "darwin/arm64"
	// LinuxAMD64 runs test on an amd64 Linux host
	LinuxAMD64 = "linux/amd64"
	// LinuxARM64 runs test on an arm64 Linux host
	LinuxARM64 = "linux/arm64"
	// WindowsAMD64 runs test on an amd64 Windows host
	WindowsAMD64 = "windows/amd64"
)

// Requirements defines the testing requirements for the test to run.
type Requirements struct {
	// Local defines if this test can safely be performed on a local development machine.
	// If not set then the test will not be performed when local only testing is performed.
	Local bool `yaml:"local"`
	// Defines the platforms that this test can only run on. If no platforms are defined then
	// the test will run on all platforms.
	Platforms []string `yaml:"platforms,omitempty"`
	// Isolate defines that this test must be isolated to its own dedicated VM and the test
	// cannot be shared with other tests.
	Isolate bool `yaml:"isolate"`
}
