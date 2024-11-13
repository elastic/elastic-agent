package pkgcommon

// PackageType defines the file format of the package (e.g. zip, rpm, etc).
type PackageType int

// List of possible package types.
const (
	RPM PackageType = iota + 1
	Deb
	Zip
	TarGz
	Docker
)

var AllPackageTypes = []PackageType{
	RPM,
	Deb,
	Zip,
	TarGz,
	Docker,
}
