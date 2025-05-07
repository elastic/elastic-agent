// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License 2.0;
// you may not use this file except in compliance with the Elastic License 2.0.

package enroll

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/otiai10/copy"
	"gopkg.in/yaml.v2"

	"github.com/elastic/elastic-agent-libs/file"
	"github.com/elastic/elastic-agent-libs/transport/tlscommon"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/filelock"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/info"
	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/internal/pkg/core/backoff"
	monitoringConfig "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/crypto"
	"github.com/elastic/elastic-agent/internal/pkg/fleetapi"
	fleetclient "github.com/elastic/elastic-agent/internal/pkg/fleetapi/client"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/internal/pkg/remote"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

const (
	maxRetriesstoreAgentInfo       = 5
	enrollBackoffInit              = time.Second * 5
	enrollBackoffMax               = time.Minute * 10
	defaultFleetServerHost         = "0.0.0.0"
	defaultFleetServerPort         = 8220
	defaultFleetServerInternalHost = "localhost"
	defaultFleetServerInternalPort = 8221
	statusPath                     = "/api/status"
	apiStatusTimeout               = 15 * time.Second
	backupSuffix                   = ".enroll.bak"
)

type saver interface {
	Save(io.Reader) error
}

func CheckRemote(ctx context.Context, c fleetclient.Sender) error {
	ctx, cancel := context.WithTimeout(ctx, apiStatusTimeout)
	defer cancel()

	// TODO: a HEAD should be enough as we need to test only the connectivity part
	resp, err := c.Send(ctx, http.MethodGet, "/api/status", nil, nil, nil)
	if err != nil {
		return fmt.Errorf("fail to communicate with Fleet Server API client hosts: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fleet server ping returned a bad status code: %d", resp.StatusCode)
	}

	// discard body for proper cancellation and connection reuse
	_, _ = io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	return nil
}

// BackupConfig creates a backup of currently used fleet config
func BackupConfig() error {
	configFile := paths.AgentConfigFile()
	backup := configFile + backupSuffix

	err := copy.Copy(configFile, backup, copy.Options{
		PermissionControl: copy.AddPermission(0600),
	})
	if err != nil {
		return fmt.Errorf("failed to backup config file %s -> %s: %w", configFile, backup, err)
	}

	return nil
}

// RestoreConfig restores from backup if needed and signals restore was performed
func RestoreConfig() error {
	configFile := paths.AgentConfigFile()
	backup := configFile + backupSuffix

	// check backup exists
	if _, err := os.Stat(backup); os.IsNotExist(err) {
		return nil
	}

	if err := file.SafeFileRotate(configFile, backup); err != nil {
		return fmt.Errorf("failed to safe rotate backup config file: %w", err)
	}

	return nil
}

// CleanBackupConfig removes backup config file
func CleanBackupConfig() error {
	backup := paths.AgentConfigFile() + backupSuffix
	if err := os.RemoveAll(backup); err != nil && !os.IsNotExist(err) {
		return err
	}

	return nil
}

func EnrollWithBackoff(
	ctx context.Context,
	log *logger.Logger,
	persistentConfig map[string]interface{},
	enrollDelay time.Duration,
	options EnrollOptions,
	configStore saver,
	backoffFactory func(done <-chan struct{}) backoff.Backoff,
) error {
	if backoffFactory == nil {
		backoffFactory = func(done <-chan struct{}) backoff.Backoff {
			return backoff.NewEqualJitterBackoff(done, enrollBackoffInit, enrollBackoffMax)
		}
	}
	delay(ctx, enrollDelay)

	remoteConfig, err := options.RemoteConfig(true)
	if err != nil {
		return errors.New(
			err, "Error",
			errors.TypeConfig,
			errors.M(errors.MetaKeyURI, options.URL))
	}

	client, err := fleetclient.NewWithConfig(log, remoteConfig)
	if err != nil {
		return errors.New(
			err, "Error",
			errors.TypeNetwork,
			errors.M(errors.MetaKeyURI, options.URL))
	}

	log.Infof("Starting enrollment to URL: %s", client.URI())
	err = enroll(ctx, log, persistentConfig, client, options, configStore)
	if err == nil {
		return nil
	}

	log.Infof("1st enrollment attempt failed, retrying enrolling to URL: %s with exponential backoff (init %s, max %s)", client.URI(), enrollBackoffInit, enrollBackoffMax)

	signal := make(chan struct{})
	defer close(signal)
	backExp := backoffFactory(signal)

	for {
		retry := false
		switch {
		case errors.Is(err, fleetapi.ErrTooManyRequests):
			log.Warn("Too many requests on the remote server, will retry in a moment.")
			retry = true
		case errors.Is(err, fleetapi.ErrConnRefused):
			log.Warn("Remote server is not ready to accept connections(Connection Refused), will retry in a moment.")
			retry = true
		case errors.Is(err, fleetapi.ErrTemporaryServerError):
			log.Warnf("Remote server failed to handle the request(%s), will retry in a moment.", err.Error())
			retry = true
		case err != nil:
			log.Warnf("Enrollment failed: %s", err.Error())
		}
		if !retry {
			break
		}
		backExp.Wait()
		log.Infof("Retrying enrollment to URL: %s", client.URI())
		err = enroll(ctx, log, persistentConfig, client, options, configStore)
	}

	return err
}

func enroll(
	ctx context.Context,
	log *logger.Logger,
	persistentConfig map[string]interface{},
	client fleetclient.Sender,
	options EnrollOptions,
	configStore saver,
) error {
	cmd := fleetapi.NewEnrollCmd(client)

	metadata, err := info.Metadata(ctx, log)
	if err != nil {
		return fmt.Errorf("acquiring metadata failed: %w", err)
	}

	// Automatically add the namespace as a tag when installed into a namepsace.
	// Ensures the development agent is differentiated from others when on the same host.
	if namespace := paths.InstallNamespace(); namespace != "" {
		options.Tags = append(options.Tags, namespace)
	}

	r := &fleetapi.EnrollRequest{
		EnrollAPIKey: options.EnrollAPIKey,
		Type:         fleetapi.PermanentEnroll,
		ID:           options.ID,
		ReplaceToken: options.ReplaceToken,
		Metadata: fleetapi.Metadata{
			Local:        metadata,
			UserProvided: options.UserProvidedMetadata,
			Tags:         cleanTags(options.Tags),
		},
	}

	resp, err := cmd.Execute(ctx, r)
	if err != nil {
		return errors.New(err,
			"fail to execute request to fleet-server",
			errors.TypeNetwork)
	}

	remoteConfig, err := options.RemoteConfig(true)
	if err != nil {
		return errors.New(err,
			"fail to create remote fleet-server config",
			errors.TypeNetwork)
	}

	fleetConfig, err := createFleetConfigFromEnroll(resp.Item.AccessAPIKey, options.EnrollAPIKey, options.ReplaceToken, remoteConfig)
	if err != nil {
		return err
	}

	agentConfig := CreateAgentConfig(resp.Item.ID, persistentConfig, options.FleetServer.Headers, options.Staging)

	localFleetServer := options.FleetServer.ConnStr != ""
	if localFleetServer {
		//nolint:dupl // not duplicates, just similar params are passed
		serverConfig, err := CreateFleetServerBootstrapConfig(
			options.FleetServer.ConnStr, options.FleetServer.ServiceToken, options.FleetServer.ServiceTokenPath,
			options.FleetServer.PolicyID,
			options.FleetServer.Host, options.FleetServer.Port, options.FleetServer.InternalPort,
			options.FleetServer.Cert, options.FleetServer.CertKey, options.FleetServer.CertKeyPassphrasePath, options.FleetServer.ElasticsearchCA, options.FleetServer.ElasticsearchCASHA256,
			options.CAs, options.FleetServer.ClientAuth,
			options.FleetServer.ElasticsearchCert, options.FleetServer.ElasticsearchCertKey,
			options.FleetServer.Headers,
			options.ProxyURL, options.ProxyDisabled, options.ProxyHeaders,
			options.FleetServer.ElasticsearchInsecure,
		)
		if err != nil {
			return fmt.Errorf(
				"failed creating fleet-server bootstrap config: %w", err)
		}

		// no longer need bootstrap at this point
		serverConfig.Server.Bootstrap = false
		fleetConfig.Server = serverConfig.Server
		// use internal URL for future requests
		if options.InternalURL != "" {
			fleetConfig.Client.Host = options.InternalURL
			// fleet-server will bind the internal listenter to localhost:8221
			// InternalURL is localhost:8221, however cert uses $HOSTNAME, so we need to disable hostname verification.
			fleetConfig.Client.Transport.TLS.VerificationMode = tlscommon.VerifyCertificate
		}
	}

	configToStore := map[string]interface{}{
		"fleet": fleetConfig,
		"agent": agentConfig,
	}

	reader, err := yamlToReader(configToStore)
	if err != nil {
		return fmt.Errorf("yamlToReader failed: %w", err)
	}

	if err := SafelyStoreAgentInfo(configStore, reader); err != nil {
		return fmt.Errorf("failed to store agent config: %w", err)
	}

	// clear action store
	// fail only if file exists and there was a failure
	if err := os.Remove(paths.AgentActionStoreFile()); !os.IsNotExist(err) {
		return err
	}

	// clear action store
	// fail only if file exists and there was a failure
	if err := os.Remove(paths.AgentStateStoreFile()); !os.IsNotExist(err) {
		return err
	}

	return nil
}

func CreateFleetServerBootstrapConfig(
	connStr, serviceToken, serviceTokenPath, policyID, host string,
	port uint16, internalPort uint16,
	cert, key, passphrasePath, esCA, esCASHA256 string,
	cas []string, clientAuth string,
	esClientCert, esClientCertKey string,
	headers map[string]string,
	proxyURL string,
	proxyDisabled bool,
	proxyHeaders map[string]string,
	insecure bool,
) (*configuration.FleetAgentConfig, error) {
	localFleetServer := connStr != ""

	es, err := configuration.ElasticsearchFromConnStr(connStr, serviceToken, serviceTokenPath, insecure)
	if err != nil {
		return nil, err
	}
	if esCA != "" {
		if es.TLS == nil {
			es.TLS = &tlscommon.Config{
				CAs: []string{esCA},
			}
		} else {
			es.TLS.CAs = []string{esCA}
		}
	}
	if esCASHA256 != "" {
		if es.TLS == nil {
			es.TLS = &tlscommon.Config{
				CATrustedFingerprint: esCASHA256,
			}
		} else {
			es.TLS.CATrustedFingerprint = esCASHA256
		}
	}
	if esClientCert != "" || esClientCertKey != "" {
		if es.TLS == nil {
			es.TLS = &tlscommon.Config{}
		}

		es.TLS.Certificate = tlscommon.CertificateConfig{
			Certificate: esClientCert,
			Key:         esClientCertKey,
		}
	}
	if host == "" {
		host = defaultFleetServerHost
	}
	if port == 0 {
		port = defaultFleetServerPort
	}
	if internalPort == 0 {
		internalPort = defaultFleetServerInternalPort
	}
	if len(headers) > 0 {
		if es.Headers == nil {
			es.Headers = make(map[string]string)
		}
		// overwrites previously set headers
		for k, v := range headers {
			es.Headers[k] = v
		}
	}
	es.ProxyURL = proxyURL
	es.ProxyDisable = proxyDisabled
	es.ProxyHeaders = proxyHeaders

	cfg := configuration.DefaultFleetAgentConfig()
	cfg.Enabled = true
	cfg.Server = &configuration.FleetServerConfig{
		Bootstrap: true,
		Output: configuration.FleetServerOutputConfig{
			Elasticsearch: es,
		},
		Host: host,
		Port: port,
	}

	if policyID != "" {
		cfg.Server.Policy = &configuration.FleetServerPolicyConfig{ID: policyID}
	}
	if cert != "" || key != "" {
		cfg.Server.TLS = &tlscommon.ServerConfig{
			Certificate: tlscommon.CertificateConfig{
				Certificate:    cert,
				Key:            key,
				PassphrasePath: passphrasePath,
			},
		}
		if insecure {
			cfg.Server.TLS.VerificationMode = tlscommon.VerifyNone
		}

		cfg.Server.TLS.CAs = cas

		var cAuth tlscommon.TLSClientAuth
		cfg.Server.TLS.ClientAuth = &cAuth
		if err := cfg.Server.TLS.ClientAuth.Unpack(clientAuth); err != nil {
			return nil, errors.New(err, "failed to unpack --fleet-server-client-auth", errors.TypeConfig)
		}
	}

	if localFleetServer {
		cfg.Client.Transport.Proxy.Disable = true
		cfg.Server.InternalPort = internalPort
	}

	if err := cfg.Valid(); err != nil {
		return nil, errors.New(err, "invalid enrollment options", errors.TypeConfig)
	}
	return cfg, nil
}

func CreateAgentConfig(agentID string, pc map[string]interface{}, headers map[string]string, staging string) map[string]interface{} {
	agentConfig := map[string]interface{}{
		"id": agentID,
	}

	if len(headers) > 0 {
		agentConfig["headers"] = headers
	}

	if staging != "" {
		staging := fmt.Sprintf("https://staging.elastic.co/%s-%s/downloads/", release.Version(), staging[:8])
		agentConfig["download"] = map[string]interface{}{
			"sourceURI": staging,
		}
	}

	for k, v := range pc {
		agentConfig[k] = v
	}

	return agentConfig
}

func SafelyStoreAgentInfo(s saver, reader io.Reader) error {
	var err error
	signal := make(chan struct{})
	backExp := backoff.NewExpBackoff(signal, 100*time.Millisecond, 3*time.Second)

	for i := 0; i <= maxRetriesstoreAgentInfo; i++ {
		backExp.Wait()
		err = storeAgentInfo(s, reader)
		if !errors.Is(err, filelock.ErrAppAlreadyRunning) {
			break
		}
	}

	close(signal)
	return err
}

func LoadPersistentConfig(pathConfigFile string) (map[string]interface{}, error) {
	persistentMap := make(map[string]interface{})
	rawConfig, err := config.LoadFile(pathConfigFile)
	if os.IsNotExist(err) {
		return persistentMap, nil
	}
	if err != nil {
		return nil, errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	pc := &struct {
		Headers        map[string]string                      `json:"agent.headers,omitempty" yaml:"agent.headers,omitempty" config:"agent.headers,omitempty"`
		LogLevel       string                                 `json:"agent.logging.level,omitempty" yaml:"agent.logging.level,omitempty" config:"agent.logging.level,omitempty"`
		MonitoringHTTP *monitoringConfig.MonitoringHTTPConfig `json:"agent.monitoring.http,omitempty" yaml:"agent.monitoring.http,omitempty" config:"agent.monitoring.http,omitempty"`
	}{
		MonitoringHTTP: monitoringConfig.DefaultConfig().HTTP,
	}

	if err := rawConfig.UnpackTo(&pc); err != nil {
		return nil, err
	}

	if pc.LogLevel != "" {
		persistentMap["logging.level"] = pc.LogLevel
	}

	if pc.MonitoringHTTP != nil {
		persistentMap["monitoring.http"] = pc.MonitoringHTTP
	}

	return persistentMap, nil
}

func delay(ctx context.Context, d time.Duration) {
	t := time.NewTimer(rand.N(d))
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

func yamlToReader(in interface{}) (io.Reader, error) {
	data, err := yaml.Marshal(in)
	if err != nil {
		return nil, errors.New(err, "could not marshal to YAML")
	}
	return bytes.NewReader(data), nil
}

func storeAgentInfo(s saver, reader io.Reader) error {
	fileLock := paths.AgentConfigFileLock()
	if err := fileLock.TryLock(); err != nil {
		return err
	}
	defer func() {
		_ = fileLock.Unlock()
	}()

	if err := s.Save(reader); err != nil {
		return errors.New(err, "could not save enrollment information", errors.TypeFilesystem)
	}

	return nil
}

func createFleetConfigFromEnroll(accessAPIKey string, enrollmentToken string, replaceToken string, cli remote.Config) (*configuration.FleetAgentConfig, error) {
	var err error
	cfg := configuration.DefaultFleetAgentConfig()
	cfg.Enabled = true
	cfg.AccessAPIKey = accessAPIKey
	cfg.Client = cli
	cfg.EnrollmentTokenHash, err = fleetHashToken(enrollmentToken)
	if err != nil {
		return nil, errors.New(err, "failed to generate enrollment hash", errors.TypeConfig)
	}
	cfg.ReplaceTokenHash, err = fleetHashToken(replaceToken)
	if err != nil {
		return nil, errors.New(err, "failed to generate replace token hash", errors.TypeConfig)
	}
	if err := cfg.Valid(); err != nil {
		return nil, errors.New(err, "invalid enrollment options", errors.TypeConfig)
	}
	return cfg, nil
}

func fleetHashToken(token string) (string, error) {
	enrollmentHashBytes, err := crypto.GeneratePBKDF2FromPassword([]byte(token))
	if err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(enrollmentHashBytes), nil
}

func cleanTags(tags []string) []string {
	var r []string
	// Create a map to store unique elements
	seen := make(map[string]bool)
	for _, str := range tags {
		tag := strings.TrimSpace(str)
		if tag != "" {
			if _, ok := seen[tag]; !ok {
				seen[tag] = true
				r = append(r, tag)
			}
		}
	}
	return r
}
