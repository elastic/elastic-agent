package translate

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/elastic/elastic-agent-libs/transport/tlscommontest"
	mockes "github.com/elastic/mock-es/pkg/api"
	"github.com/elastic/opentelemetry-collector-components/extension/beatsauthextension"
	"github.com/gofrs/uuid/v5"
	"github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter"
	"github.com/stretchr/testify/require"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/config/configauth"
	"go.opentelemetry.io/collector/config/confighttp"
	"go.opentelemetry.io/collector/config/configoptional"
	"go.opentelemetry.io/collector/confmap/xconfmap"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/exporter/exporterhelper"
	"go.opentelemetry.io/collector/exporter/exportertest"
	"go.opentelemetry.io/collector/extension"
	"go.opentelemetry.io/collector/extension/extensiontest"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.uber.org/zap"
)

// This test package tests ES exporter + beatsauth extension together

// tests mutual TLS
func TestMTLS(t *testing.T) {
	caCert, err := tlscommontest.GenCA()
	if err != nil {
		t.Fatalf("could not generate root CA certificate: %s", err)
	}

	// create server certificates
	serverCerts, err := tlscommontest.GenSignedCert(caCert, x509.KeyUsageCertSign, false, "server", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, false)
	if err != nil {
		t.Fatalf("could not generate certificates: %s", err)
	}

	// get client certificates
	clientCertificate, clientKey := getClientCerts(t, caCert)

	serverName := startTestServer(t, []tls.Certificate{serverCerts}, caCert)
	exp := newTestESExporterWithAuth(t, serverName)

	beatsauth := newAuthenticator(t, beatsauthextension.Config{
		BeatAuthconfig: map[string]any{
			"ssl": map[string]any{
				"enabled": true,
				"certificate_authorities": []string{
					string(
						pem.EncodeToMemory(&pem.Block{
							Type:  "CERTIFICATE",
							Bytes: caCert.Leaf.Raw,
						}))},
				"certificate": clientCertificate,
				"key":         clientKey,
			},
		},
	})

	host := extensionsMap{component.NewID(component.MustNewType("beatsauth")): beatsauth}
	err = beatsauth.Start(t.Context(), host)
	require.NoError(t, err, "could not start extension")

	err = exp.Start(t.Context(), host)
	require.NoError(t, err, "could not start exporter")

	mustSendLogs(t, exp, getLogRecord(t))

	require.Eventually(t, func() bool {
		time.Sleep(50 * time.Second)
		return true
	}, 1*time.Minute, 10*time.Second, "did not receiver record")
}

func newAuthenticator(t *testing.T, config beatsauthextension.Config) extension.Extension {
	beatsauth := beatsauthextension.NewFactory()
	extension, err := beatsauth.Create(t.Context(), extensiontest.NewNopSettings(beatsauth.Type()), &config)
	if err != nil {
		t.Fatalf("could not create extension: %v", err)
	}

	return extension
}

func newTestESExporterWithAuth(t *testing.T, url string, fns ...func(*elasticsearchexporter.Config)) exporter.Logs {
	testauthID := component.NewID(component.MustNewType("beatsauth"))

	f := elasticsearchexporter.NewFactory()
	queueConfig := exporterhelper.NewDefaultQueueConfig()
	queueConfig.Batch = configoptional.Some(exporterhelper.BatchConfig{
		Sizer:   exporterhelper.RequestSizerTypeItems,
		MinSize: 0,
	})

	cfg := &elasticsearchexporter.Config{
		Endpoints: []string{url},
		ClientConfig: confighttp.ClientConfig{
			Auth:        configoptional.Some(configauth.Config{AuthenticatorID: testauthID}),
			Compression: "none",
		},
		Mapping: elasticsearchexporter.MappingsSettings{
			Mode:         "bodymap",
			AllowedModes: []string{"bodymap", "ecs", "none", "otel", "raw"},
		},
		QueueBatchConfig: queueConfig,
	}

	for _, fn := range fns {
		fn(cfg)
	}
	require.NoError(t, xconfmap.Validate(cfg))

	settings := exportertest.NewNopSettings(component.MustNewType("elasticsearch"))
	var err error
	settings.Logger, err = zap.NewDevelopment()
	require.NoError(t, err, "could not create logger")
	exp, err := f.CreateLogs(context.Background(), settings, cfg)
	require.NoError(t, err)
	return exp
}

type extensionsMap map[component.ID]component.Component

func (m extensionsMap) GetExtensions() map[component.ID]component.Component {
	return m
}

// start MOCK ES with given certificates
func startTestServer(t *testing.T, serverCerts []tls.Certificate, caCert tls.Certificate) string {

	uid := uuid.Must(uuid.NewV4())
	clusterUUID := uuid.Must(uuid.NewV4()).String()

	mux := http.NewServeMux()
	mux.Handle("/", mockes.NewAPIHandler(
		uid,
		clusterUUID,
		nil,
		time.Now().Add(time.Hour),
		0,
		0, 0, 0, 0, 0))

	server := httptest.NewUnstartedServer(mux)
	server.TLS = &tls.Config{}

	// NOTE: client certificates are not verified  unless ClientAuth is set to RequireAndVerifyClientCert.
	server.TLS.ClientAuth = tls.RequireAndVerifyClientCert

	certPool := x509.NewCertPool()
	certPool.AddCert(caCert.Leaf)

	server.TLS.ClientCAs = certPool
	server.TLS.Certificates = serverCerts

	server.StartTLS()
	t.Cleanup(func() { server.Close() })
	return server.URL
}

// getLogRecord returns a single bodymap encoded log record
func getLogRecord(t *testing.T) plog.Logs {
	logs := plog.NewLogs()
	resourceLogs := logs.ResourceLogs().AppendEmpty()
	scopeLogs := resourceLogs.ScopeLogs().AppendEmpty()
	logRecords := scopeLogs.LogRecords()
	logRecord := logRecords.AppendEmpty()
	body := pcommon.NewValueMap()
	m := body.Map()
	m.PutStr("@timestamp", "2024-03-12T20:00:41.123456789Z")
	m.PutInt("id", 1)
	m.PutStr("key", "value")
	body.CopyTo(logRecord.Body())
	return logs
}

// sends log to given exporter
func mustSendLogs(t *testing.T, exporter exporter.Logs, logs plog.Logs) {
	logs.MarkReadOnly()
	err := exporter.ConsumeLogs(t.Context(), logs)
	require.NoError(t, err)
}

// getClientCerts creates client certificates, writes them to a file and return the path of certificate and key
func getClientCerts(t *testing.T, caCert tls.Certificate) (certificate string, key string) {
	// create client certificates
	clientCerts, err := tlscommontest.GenSignedCert(caCert, x509.KeyUsageCertSign, false, "client", []string{"localhost"}, []net.IP{net.IPv4(127, 0, 0, 1)}, false)
	if err != nil {
		t.Fatalf("could not generate certificates: %s", err)
	}

	clientKey, err := x509.MarshalPKCS8PrivateKey(clientCerts.PrivateKey)
	if err != nil {
		t.Fatalf("could not marshal private key: %v", err)
	}

	tempDir := t.TempDir()
	clientCertPath := filepath.Join(tempDir, "client-cert.pem")
	clientKeyPath := filepath.Join(tempDir, "client-key.pem")

	if err = os.WriteFile(clientCertPath, pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: clientCerts.Leaf.Raw,
	}), 0o777); err != nil {
		t.Fatalf("could not write client certificate to file")
	}

	if err = os.WriteFile(clientKeyPath, pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: clientKey,
	}), 0o777); err != nil {
		t.Fatalf("could not write client key to file")
	}

	return clientCertPath, clientKeyPath
}
