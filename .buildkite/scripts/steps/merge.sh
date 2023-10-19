
set -exuo pipefail

go install github.com/wadey/gocovmerge@latest
buildkite-agent artifact download --step unit-tests-2204 build/TEST-go-unit.cov coverage-unit-tests-2204.cov
buildkite-agent artifact download --step unit-tests-2204-arm64 build/TEST-go-unit.cov coverage-unit-tests-2204-arm64.cov
ls ./unit-tests-2204
gocovmerge coverage-unit-tests-2204.cov coverage-unit-tests-2204-arm64.cov > build/TEST-go-unit.cov
cat build/TEST-go-unit.cov