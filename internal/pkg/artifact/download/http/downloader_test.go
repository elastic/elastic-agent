// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package http

import (
	"context"
	"io/ioutil"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/elastic/elastic-agent/internal/pkg/artifact"
)

func TestDownloadBodyError(t *testing.T) {
	// This tests the scenario where the download encounters a network error
	// part way through the download, while copying the response body.

	type connKey struct{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		conn := r.Context().Value(connKey{}).(net.Conn)
		conn.Close()
	}))
	defer srv.Close()
	client := srv.Client()
	srv.Config.ConnContext = func(ctx context.Context, c net.Conn) context.Context {
		return context.WithValue(ctx, connKey{}, c)
	}

	targetDir, err := ioutil.TempDir(os.TempDir(), "")
	if err != nil {
		t.Fatal(err)
	}

	config := &artifact.Config{
		SourceURI:       srv.URL,
		TargetDirectory: targetDir,
		OperatingSystem: "linux",
		Architecture:    "64",
	}

	testClient := NewDownloaderWithClient(config, *client)
	artifactPath, err := testClient.Download(context.Background(), beatSpec, version)
	if err == nil {
		os.Remove(artifactPath)
		t.Fatal("expected Download to return an error")
	}
}
