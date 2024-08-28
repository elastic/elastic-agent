.PHONY: all

all:
	go run go.opentelemetry.io/collector/cmd/builder@v0.107.0 --skip-compilation --skip-get-modules --config builder-config.yaml
	@rm main.go main_others.go main_windows.go go.mod
	sed -i 's/package main/\/\/go:build \!windows\npackage otel/g' components.go
