module github.com/elastic/elastic-agent/wrapper/windows/archive-proxy

go 1.26.5

require (
	github.com/elastic/elastic-agent v0.0.0-00010101000000-000000000000
	github.com/elastic/elastic-agent-libs v0.46.2-0.20260717072702-02294d812c7d
)

require (
	github.com/elastic/go-ucfg v0.9.1 // indirect
	github.com/magefile/mage v1.17.2 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.28.0 // indirect
	golang.org/x/sys v0.46.0 // indirect
	gopkg.in/yaml.v2 v2.4.0 // indirect
)

replace github.com/elastic/elastic-agent => ../../../
