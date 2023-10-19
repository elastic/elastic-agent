
set -exuo pipefail

$COV_FILE="build/TEST-go-unit.cov"

go install github.com/wadey/gocovmerge@latest
mkdir unit-tests-2204 && buildkite-agent artifact download --step unit-tests-2204 $COV_FILE unit-tests-2204
mkdir unit-tests-2204-arm64 && buildkite-agent artifact download --step unit-tests-2204-arm64 $COV_FILE unit-tests-2204-arm64
ls unit-tests-2204
ls unit-tests-2204-arm64
gocovmerge unit-tests-2204/$COV_FILE unit-tests-2204-arm64/$COV_FILE > build/TEST-go-unit.cov
cat build/TEST-go-unit.cov