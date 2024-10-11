// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package testing

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHttpFetcher_Fetch(t *testing.T) {
	type fields struct {
		baseURL string
	}
	type args struct {
		operatingSystem string
		architecture    string
		version         string
		pkgFormat       string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    FetcherResult
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "default elastic artifacts http fetcher",
			args: args{
				operatingSystem: "linux",
				architecture:    "arm64",
				version:         "1.2.3",
				pkgFormat:       "targz",
			},
			want: &httpFetcherResult{
				baseURL:     "https://artifacts.elastic.co/downloads/beats/elastic-agent/",
				packageName: "elastic-agent-1.2.3-linux-arm64.tar.gz",
			},
			wantErr: assert.NoError,
		},
		{
			name:   "custom baseURL http fetcher",
			fields: fields{baseURL: "http://somehost.somedomain/some/path/here"},
			args: args{
				operatingSystem: "windows",
				architecture:    "amd64",
				version:         "1.2.3",
				pkgFormat:       "zip",
			},
			want: &httpFetcherResult{
				baseURL:     "http://somehost.somedomain/some/path/here",
				packageName: "elastic-agent-1.2.3-windows-x86_64.zip",
			},
			wantErr: assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []HttpFetcherOpt
			if tt.fields.baseURL != "" {
				opts = append(opts, WithBaseURL(tt.fields.baseURL))
			}
			h := NewHttpFetcher(opts...)
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			got, err := h.Fetch(ctx, tt.args.operatingSystem, tt.args.architecture, tt.args.version, tt.args.pkgFormat)
			if !tt.wantErr(t, err, fmt.Sprintf("Fetch(%v, %v, %v, %v)", ctx, tt.args.operatingSystem, tt.args.architecture, tt.args.version)) {
				return
			}
			assert.Equalf(t, tt.want, got, "Fetch(%v, %v, %v, %v)", ctx, tt.args.operatingSystem, tt.args.architecture, tt.args.version)
		})
	}
}

func TestHttpFetcher_Name(t *testing.T) {
	type fields struct {
		baseURL string
	}
	tests := []struct {
		name   string
		fields fields
		want   string
	}{
		{
			name: "default elastic artifacts http fetcher",
			want: "httpFetcher-artifacts.elastic.co",
		},
		{
			name:   "http fetcher with custom http url",
			fields: fields{baseURL: "http://somehost.somedomain:8888"},
			want:   "httpFetcher-somehost.somedomain",
		},
		{
			name:   "http fetcher with base url not mantching regex",
			fields: fields{baseURL: "foo.bar-baz"},
			want:   "httpFetcher-foo.bar-baz",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var opts []HttpFetcherOpt
			if tt.fields.baseURL != "" {
				opts = append(opts, WithBaseURL(tt.fields.baseURL))
			}
			h := NewHttpFetcher(opts...)
			assert.Equalf(t, tt.want, h.Name(), "Name()")
		})
	}
}

func Test_httpFetcherResult_Fetch(t *testing.T) {
	type fields struct {
		packageName string
	}
	type args struct {
		availableFiles map[string]string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr assert.ErrorAssertionFunc
	}{

		{
			name:   "happy path linux package",
			fields: fields{packageName: "elastic-agent-1.2.3-linux-arm64.tar.gz"},
			args: args{availableFiles: map[string]string{
				"/elastic-agent-1.2.3-linux-arm64.tar.gz":        "elastic-agent-package-placeholder",
				"/elastic-agent-1.2.3-linux-arm64.tar.gz.sha512": "elastic-agent-package hash",
				"/elastic-agent-1.2.3-linux-arm64.tar.gz.asc":    "elastic-agent-package signature",
			}},
			wantErr: assert.NoError,
		},
		{
			name:   "linux package missing hash",
			fields: fields{packageName: "elastic-agent-1.2.3-linux-arm64.tar.gz"},
			args: args{availableFiles: map[string]string{
				"/elastic-agent-1.2.3-linux-arm64.tar.gz":     "elastic-agent-package-placeholder",
				"/elastic-agent-1.2.3-linux-arm64.tar.gz.asc": "elastic-agent-package signature",
			}},
			wantErr: assert.Error,
		},
		{
			name:   "windows package missing signature",
			fields: fields{packageName: "elastic-agent-1.2.3-windows-x86_64.zip"},
			args: args{availableFiles: map[string]string{
				"/elastic-agent-1.2.3-windows-x86_64.zip":        "elastic-agent-package-placeholder",
				"/elastic-agent-1.2.3-windows-x86_64.zip.sha512": "elastic-agent-package hash",
			}},
			wantErr: assert.Error,
		},
		{
			name:    "linux package missing completely",
			fields:  fields{packageName: "elastic-agent-1.2.3-linux-arm64.tar.gz"},
			args:    args{availableFiles: map[string]string{}},
			wantErr: assert.Error,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hf := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				path := request.URL.Path
				content, ok := tt.args.availableFiles[path]
				if !ok {
					writer.WriteHeader(http.StatusNotFound)
					return
				}

				_, err := writer.Write([]byte(content))
				require.NoError(t, err, "error writing file content")
			})
			server := httptest.NewServer(hf)
			defer server.Close()
			h := httpFetcherResult{
				baseURL:     server.URL,
				packageName: tt.fields.packageName,
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			outdir := t.TempDir()
			tt.wantErr(t, h.Fetch(ctx, t, outdir), fmt.Sprintf("Fetch(%v, %v)", tt.fields.packageName, outdir))
		})
	}
}
