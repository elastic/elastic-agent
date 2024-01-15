// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package cmd

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/paths"
	"github.com/elastic/elastic-agent/internal/pkg/agent/configuration"
	"github.com/elastic/elastic-agent/internal/pkg/agent/errors"
	"github.com/elastic/elastic-agent/internal/pkg/cli"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

func newEnrollCommandWithArgs(_ []string, streams *cli.IOStreams) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll the Elastic Agent into Fleet",
		Long:  "This command will enroll the Elastic Agent into Fleet.",
		Run: func(c *cobra.Command, args []string) {
			if err := enroll(streams, c); err != nil {
				fmt.Fprintf(streams.Err, "Error: %v\n%s\n", err, troubleshootMessage())
				os.Exit(1)
			}
		},
	}

	addEnrollFlags(cmd)
	cmd.Flags().BoolP("force", "f", false, "Force overwrite the current and do not prompt for confirmation")

	// used by install command
	cmd.Flags().BoolP("from-install", "", false, "Set by install command to signal this was executed from install")
	cmd.Flags().MarkHidden("from-install") //nolint:errcheck //not required

	return cmd
}

func addEnrollFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("url", "", "", "URL to enroll Agent into Fleet")
	cmd.Flags().StringP("enrollment-token", "t", "", "Enrollment token to use to enroll Agent into Fleet")
	cmd.Flags().StringP("fleet-server-es", "", "", "Start and run a Fleet Server along side this Elastic Agent connecting to the provided elasticsearch")
	cmd.Flags().StringP("fleet-server-es-ca", "", "", "Path to certificate authority to use with communicate with elasticsearch")
	cmd.Flags().StringP("fleet-server-es-ca-trusted-fingerprint", "", "", "Elasticsearch certificate authority's SHA256 fingerprint")
	cmd.Flags().BoolP("fleet-server-es-insecure", "", false, "Disables validation of certificates")
	cmd.Flags().StringP("fleet-server-es-cert", "", "", "Client certificate to use when connecting to Elasticsearch.")
	cmd.Flags().StringP("fleet-server-es-cert-key", "", "", "Client private key to use when connecing to Elasticsearch.")
	cmd.Flags().StringP("fleet-server-service-token", "", "", "Service token to use for communication with elasticsearch")
	cmd.Flags().StringP("fleet-server-service-token-path", "", "", "Filepath for service token secret file to use for communication with elasticsearch")
	cmd.Flags().StringP("fleet-server-policy", "", "", "Start and run a Fleet Server on this specific policy")
	cmd.Flags().StringP("fleet-server-host", "", "", "Fleet Server HTTP binding host (overrides the policy)")
	cmd.Flags().Uint16P("fleet-server-port", "", 0, "Fleet Server HTTP binding port (overrides the policy)")
	cmd.Flags().StringP("fleet-server-cert", "", "", "Certificate to use for exposed Fleet Server HTTPS endpoint")
	cmd.Flags().StringP("fleet-server-cert-key", "", "", "Private key to use for exposed Fleet Server HTTPS endpoint")
	cmd.Flags().StringP("fleet-server-cert-key-passphrase", "", "", "Path for private key passphrase file used to decrypt certificate key")
	cmd.Flags().StringP("fleet-server-client-auth", "", "none", "Fleet-server mTLS client authentication for connecting elastic-agents. Must be one of [none, optional, required]")
	cmd.Flags().StringSliceP("header", "", []string{}, "Headers used in communication with elasticsearch")
	cmd.Flags().BoolP("fleet-server-insecure-http", "", false, "Expose Fleet Server over HTTP (not recommended; insecure)")
	cmd.Flags().StringP("certificate-authorities", "a", "", "Comma separated list of root certificate for server verifications")
	cmd.Flags().StringP("ca-sha256", "p", "", "Comma separated list of certificate authorities hash pins used for certificate verifications")
	cmd.Flags().StringP("elastic-agent-cert", "", "", "Elastic-agent client certificate to use with fleet-server during authentication")
	cmd.Flags().StringP("elastic-agent-cert-key", "", "", "Elastic-agent client certificate to use with fleet-server during authentication")
	cmd.Flags().BoolP("insecure", "i", false, "Allow insecure connection to fleet-server")
	cmd.Flags().StringP("staging", "", "", "Configures agent to download artifacts from a staging build")
	cmd.Flags().StringP("proxy-url", "", "", "Configures the proxy url")
	cmd.Flags().BoolP("proxy-disabled", "", false, "Disable proxy support including environment variables")
	cmd.Flags().StringSliceP("proxy-header", "", []string{}, "Proxy headers used with CONNECT request")
	cmd.Flags().BoolP("delay-enroll", "", false, "Delays enrollment to occur on first start of the Elastic Agent service")
	cmd.Flags().DurationP("daemon-timeout", "", 0, "Timeout waiting for Elastic Agent daemon")
	cmd.Flags().DurationP("fleet-server-timeout", "", 0, "Timeout waiting for Fleet Server to be ready to start enrollment")
	cmd.Flags().Bool("skip-daemon-reload", false, "Skip daemon reload after enrolling")
	cmd.Flags().StringSliceP("tag", "", []string{}, "User set tags")

	cmd.Flags().MarkHidden("skip-daemon-reload") //nolint:errcheck // an error is only returned if the flag does not exist.
}

func validateEnrollFlags(cmd *cobra.Command) error {
	ca, _ := cmd.Flags().GetString("certificate-authorities")
	if ca != "" && !filepath.IsAbs(ca) {
		return errors.New("--certificate-authorities must be provided as an absolute path", errors.M("path", ca), errors.TypeConfig)
	}
	cert, _ := cmd.Flags().GetString("elastic-agent-cert")
	if cert != "" && !filepath.IsAbs(cert) {
		return errors.New("--elastic-agent-cert must be provided as an absolute path", errors.M("path", cert), errors.TypeConfig)
	}
	key, _ := cmd.Flags().GetString("elastic-agent-cert-key")
	if key != "" && !filepath.IsAbs(key) {
		return errors.New("--elastic-agent-cert-key must be provided as an absolute path", errors.M("path", key), errors.TypeConfig)
	}
	esCa, _ := cmd.Flags().GetString("fleet-server-es-ca")
	if esCa != "" && !filepath.IsAbs(esCa) {
		return errors.New("--fleet-server-es-ca must be provided as an absolute path", errors.M("path", esCa), errors.TypeConfig)
	}
	esCert, _ := cmd.Flags().GetString("fleet-server-es-cert")
	if esCert != "" && !filepath.IsAbs(esCert) {
		return errors.New("--fleet-server-es-cert must be provided as an absolute path", errors.M("path", esCert), errors.TypeConfig)
	}
	esCertKey, _ := cmd.Flags().GetString("fleet-server-es-cert-key")
	if esCertKey != "" && !filepath.IsAbs(esCertKey) {
		return errors.New("--fleet-server-es-cert-key must be provided as an absolute path", errors.M("path", esCertKey), errors.TypeConfig)
	}
	fCert, _ := cmd.Flags().GetString("fleet-server-cert")
	if fCert != "" && !filepath.IsAbs(fCert) {
		return errors.New("--fleet-server-cert must be provided as an absolute path", errors.M("path", fCert), errors.TypeConfig)
	}
	fCertKey, _ := cmd.Flags().GetString("fleet-server-cert-key")
	if fCertKey != "" && !filepath.IsAbs(fCertKey) {
		return errors.New("--fleet-server-cert-key must be provided as an absolute path", errors.M("path", fCertKey), errors.TypeConfig)
	}
	fTokenPath, _ := cmd.Flags().GetString("fleet-server-service-token-path")
	if fTokenPath != "" && !filepath.IsAbs(fTokenPath) {
		return errors.New("--fleet-server-service-token-path must be provided as an absolute path", errors.M("path", fTokenPath), errors.TypeConfig)
	}
	fToken, _ := cmd.Flags().GetString("fleet-server-service-token")
	if fToken != "" && fTokenPath != "" {
		return errors.New("--fleet-server-service-token and --fleet-server-service-token-path are mutually exclusive", errors.TypeConfig)
	}
	fPassphrase, _ := cmd.Flags().GetString("fleet-server-cert-key-passphrase")
	if fPassphrase != "" && !filepath.IsAbs(fPassphrase) {
		return errors.New("--fleet-server-cert-key-passphrase must be provided as an absolute path", errors.M("path", fPassphrase), errors.TypeConfig)
	}
	fClientAuth, _ := cmd.Flags().GetString("fleet-server-client-auth")
	switch fClientAuth {
	case "none", "optional", "required":
		// NOTE we can split this case if we want to do additional checks when optional or required is passed.
	default:
		return errors.New("--fleet-server-client-auth must be one of [none, optional, required]")
	}
	return nil
}

func buildEnrollmentFlags(cmd *cobra.Command, url string, token string) []string {
	if url == "" {
		url, _ = cmd.Flags().GetString("url")
	}
	if token == "" {
		token, _ = cmd.Flags().GetString("enrollment-token")
	}
	fServer, _ := cmd.Flags().GetString("fleet-server-es")
	fElasticSearchCA, _ := cmd.Flags().GetString("fleet-server-es-ca")
	fElasticSearchCASHA256, _ := cmd.Flags().GetString("fleet-server-es-ca-trusted-fingerprint")
	fElasticSearchInsecure, _ := cmd.Flags().GetBool("fleet-server-es-insecure")
	fElasticSearchClientCert, _ := cmd.Flags().GetString("fleet-server-es-cert")
	fElasticSearchClientCertKey, _ := cmd.Flags().GetString("fleet-server-es-cert-key")
	fServiceToken, _ := cmd.Flags().GetString("fleet-server-service-token")
	fServiceTokenPath, _ := cmd.Flags().GetString("fleet-server-service-token-path")
	fPolicy, _ := cmd.Flags().GetString("fleet-server-policy")
	fHost, _ := cmd.Flags().GetString("fleet-server-host")
	fPort, _ := cmd.Flags().GetUint16("fleet-server-port")
	fCert, _ := cmd.Flags().GetString("fleet-server-cert")
	fCertKey, _ := cmd.Flags().GetString("fleet-server-cert-key")
	fPassphrase, _ := cmd.Flags().GetString("fleet-server-cert-key-passphrase")
	fClientAuth, _ := cmd.Flags().GetString("fleet-server-client-auth")
	fHeaders, _ := cmd.Flags().GetStringSlice("header")
	fInsecure, _ := cmd.Flags().GetBool("fleet-server-insecure-http")
	ca, _ := cmd.Flags().GetString("certificate-authorities")
	cert, _ := cmd.Flags().GetString("elastic-agent-cert")
	key, _ := cmd.Flags().GetString("elastic-agent-cert-key")
	sha256, _ := cmd.Flags().GetString("ca-sha256")
	insecure, _ := cmd.Flags().GetBool("insecure")
	staging, _ := cmd.Flags().GetString("staging")
	fProxyURL, _ := cmd.Flags().GetString("proxy-url")
	fProxyDisabled, _ := cmd.Flags().GetBool("proxy-disabled")
	fProxyHeaders, _ := cmd.Flags().GetStringSlice("proxy-header")
	delayEnroll, _ := cmd.Flags().GetBool("delay-enroll")
	daemonTimeout, _ := cmd.Flags().GetDuration("daemon-timeout")
	fTimeout, _ := cmd.Flags().GetDuration("fleet-server-timeout")
	skipDaemonReload, _ := cmd.Flags().GetBool("skip-daemon-reload")
	fTags, _ := cmd.Flags().GetStringSlice("tag")
	args := []string{}
	if url != "" {
		args = append(args, "--url")
		args = append(args, url)
	}
	if token != "" {
		args = append(args, "--enrollment-token")
		args = append(args, token)
	}
	if fServer != "" {
		args = append(args, "--fleet-server-es")
		args = append(args, fServer)
	}
	if fElasticSearchCA != "" {
		args = append(args, "--fleet-server-es-ca")
		args = append(args, fElasticSearchCA)
	}
	if fElasticSearchCASHA256 != "" {
		args = append(args, "--fleet-server-es-ca-trusted-fingerprint")
		args = append(args, fElasticSearchCASHA256)
	}
	if fElasticSearchClientCert != "" {
		args = append(args, "--fleet-server-es-cert")
		args = append(args, fElasticSearchClientCert)
	}
	if fElasticSearchClientCertKey != "" {
		args = append(args, "--fleet-server-es-cert-key")
		args = append(args, fElasticSearchClientCertKey)
	}
	if fServiceToken != "" {
		args = append(args, "--fleet-server-service-token")
		args = append(args, fServiceToken)
	}
	if fServiceTokenPath != "" {
		args = append(args, "--fleet-server-service-token-path")
		args = append(args, fServiceTokenPath)
	}
	if fPolicy != "" {
		args = append(args, "--fleet-server-policy")
		args = append(args, fPolicy)
	}
	if fHost != "" {
		args = append(args, "--fleet-server-host")
		args = append(args, fHost)
	}
	if fPort > 0 {
		args = append(args, "--fleet-server-port")
		args = append(args, strconv.Itoa(int(fPort)))
	}
	if fCert != "" {
		args = append(args, "--fleet-server-cert")
		args = append(args, fCert)
	}
	if fCertKey != "" {
		args = append(args, "--fleet-server-cert-key")
		args = append(args, fCertKey)
	}
	if fPassphrase != "" {
		args = append(args, "--fleet-server-cert-key-passphrase")
		args = append(args, fPassphrase)
	}
	if fClientAuth != "" {
		args = append(args, "--fleet-server-client-auth")
		args = append(args, fClientAuth)
	}
	if daemonTimeout != 0 {
		args = append(args, "--daemon-timeout")
		args = append(args, daemonTimeout.String())
	}
	if fTimeout != 0 {
		args = append(args, "--fleet-server-timeout")
		args = append(args, fTimeout.String())
	}

	for k, v := range mapFromEnvList(fHeaders) {
		args = append(args, "--header")
		args = append(args, k+"="+v)
	}

	if fInsecure {
		args = append(args, "--fleet-server-insecure-http")
	}
	if ca != "" {
		args = append(args, "--certificate-authorities")
		args = append(args, ca)
	}
	if cert != "" {
		args = append(args, "--elastic-agent-cert")
		args = append(args, cert)
	}
	if key != "" {
		args = append(args, "--elastic-agent-cert-key")
		args = append(args, key)
	}
	if sha256 != "" {
		args = append(args, "--ca-sha256")
		args = append(args, sha256)
	}
	if insecure {
		args = append(args, "--insecure")
	}
	if staging != "" {
		args = append(args, "--staging")
		args = append(args, staging)
	}

	if fProxyURL != "" {
		args = append(args, "--proxy-url")
		args = append(args, fProxyURL)
	}
	if fProxyDisabled {
		args = append(args, "--proxy-disabled")
		args = append(args, "true")
	}
	for k, v := range mapFromEnvList(fProxyHeaders) {
		args = append(args, "--proxy-header")
		args = append(args, k+"="+v)
	}

	if delayEnroll {
		args = append(args, "--delay-enroll")
	}

	if fElasticSearchInsecure {
		args = append(args, "--fleet-server-es-insecure")
	}

	if skipDaemonReload {
		args = append(args, "--skip-daemon-reload")
	}
	for _, v := range fTags {
		args = append(args, "--tag", v)
	}
	return args
}

func enroll(streams *cli.IOStreams, cmd *cobra.Command) error {
	err := validateEnrollFlags(cmd)
	if err != nil {
		return err
	}

	fromInstall, _ := cmd.Flags().GetBool("from-install")

	pathConfigFile := paths.ConfigFile()
	rawConfig, err := config.LoadFile(pathConfigFile)
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("could not read configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	cfg, err := configuration.NewFromConfig(rawConfig)
	if err != nil {
		return errors.New(err,
			fmt.Sprintf("could not parse configuration file %s", pathConfigFile),
			errors.TypeFilesystem,
			errors.M(errors.MetaKeyPath, pathConfigFile))
	}

	staging, _ := cmd.Flags().GetString("staging")
	if staging != "" {
		if len(staging) < 8 {
			return errors.New(fmt.Errorf("invalid staging build hash; must be at least 8 characters"), "Error")
		}
	}

	force, _ := cmd.Flags().GetBool("force")
	if fromInstall {
		force = true
	}

	// prompt only when it is not forced and is already enrolled
	if !force && (cfg.Fleet != nil && cfg.Fleet.Enabled) {
		confirm, err := cli.Confirm("This will replace your current settings. Do you want to continue?", true)
		if err != nil {
			return errors.New(err, "problem reading prompt response")
		}
		if !confirm {
			fmt.Fprintln(streams.Out, "Enrollment was cancelled by the user")
			return nil
		}
	}

	// enroll is invoked either manually or from install with redirected IO
	// no need to log to file
	cfg.Settings.LoggingConfig.ToFiles = false
	cfg.Settings.LoggingConfig.ToStderr = true

	logger, err := logger.NewFromConfig("", cfg.Settings.LoggingConfig, false)
	if err != nil {
		return err
	}

	insecure, _ := cmd.Flags().GetBool("insecure")
	url, _ := cmd.Flags().GetString("url")
	enrollmentToken, _ := cmd.Flags().GetString("enrollment-token")
	fServer, _ := cmd.Flags().GetString("fleet-server-es")
	fElasticSearchCA, _ := cmd.Flags().GetString("fleet-server-es-ca")
	fElasticSearchCASHA256, _ := cmd.Flags().GetString("fleet-server-es-ca-trusted-fingerprint")
	fElasticSearchInsecure, _ := cmd.Flags().GetBool("fleet-server-es-insecure")
	fElasticSearchClientCert, _ := cmd.Flags().GetString("fleet-server-es-cert")
	fElasticSearchClientCertKey, _ := cmd.Flags().GetString("fleet-server-es-cert-key")
	fHeaders, _ := cmd.Flags().GetStringSlice("header")
	fServiceToken, _ := cmd.Flags().GetString("fleet-server-service-token")
	fServiceTokenPath, _ := cmd.Flags().GetString("fleet-server-service-token-path")
	fPolicy, _ := cmd.Flags().GetString("fleet-server-policy")
	fHost, _ := cmd.Flags().GetString("fleet-server-host")
	fPort, _ := cmd.Flags().GetUint16("fleet-server-port")
	fInternalPort, _ := cmd.Flags().GetUint16("fleet-server-internal-port")
	fCert, _ := cmd.Flags().GetString("fleet-server-cert")
	fCertKey, _ := cmd.Flags().GetString("fleet-server-cert-key")
	fPassphrase, _ := cmd.Flags().GetString("fleet-server-cert-key-passphrase")
	fClientAuth, _ := cmd.Flags().GetString("fleet-server-client-auth")
	fInsecure, _ := cmd.Flags().GetBool("fleet-server-insecure-http")
	proxyURL, _ := cmd.Flags().GetString("proxy-url")
	proxyDisabled, _ := cmd.Flags().GetBool("proxy-disabled")
	proxyHeaders, _ := cmd.Flags().GetStringSlice("proxy-header")
	delayEnroll, _ := cmd.Flags().GetBool("delay-enroll")
	daemonTimeout, _ := cmd.Flags().GetDuration("daemon-timeout")
	fTimeout, _ := cmd.Flags().GetDuration("fleet-server-timeout")
	skipDaemonReload, _ := cmd.Flags().GetBool("skip-daemon-reload")
	tags, _ := cmd.Flags().GetStringSlice("tag")

	caStr, _ := cmd.Flags().GetString("certificate-authorities")
	CAs := cli.StringToSlice(caStr)
	caSHA256str, _ := cmd.Flags().GetString("ca-sha256")
	caSHA256 := cli.StringToSlice(caSHA256str)
	cert, _ := cmd.Flags().GetString("elastic-agent-cert")
	key, _ := cmd.Flags().GetString("elastic-agent-cert-key")

	ctx := handleSignal(context.Background())

	// On MacOS Ventura and above, fixing the permissions on enrollment during installation fails with the error:
	//  Error: failed to fix permissions: chown /Library/Elastic/Agent/data/elastic-agent-c13f91/elastic-agent.app: operation not permitted
	// This is because we are fixing permissions twice, once during installation and again during the enrollment step.
	// When we are enrolling as part of installation on MacOS, skip the second attempt to fix permissions.
	fixPermissions := fromInstall
	if runtime.GOOS == "darwin" {
		fixPermissions = false
	}

	options := enrollCmdOption{
		EnrollAPIKey:         enrollmentToken,
		URL:                  url,
		CAs:                  CAs,
		CASha256:             caSHA256,
		Certificate:          cert,
		Key:                  key,
		Insecure:             insecure,
		UserProvidedMetadata: make(map[string]interface{}),
		Staging:              staging,
		FixPermissions:       fixPermissions,
		ProxyURL:             proxyURL,
		ProxyDisabled:        proxyDisabled,
		ProxyHeaders:         mapFromEnvList(proxyHeaders),
		DelayEnroll:          delayEnroll,
		DaemonTimeout:        daemonTimeout,
		SkipDaemonRestart:    skipDaemonReload,
		Tags:                 tags,
		FleetServer: enrollCmdFleetServerOption{
			ConnStr:               fServer,
			ElasticsearchCA:       fElasticSearchCA,
			ElasticsearchCASHA256: fElasticSearchCASHA256,
			ElasticsearchInsecure: fElasticSearchInsecure,
			ElasticsearchCert:     fElasticSearchClientCert,
			ElasticsearchCertKey:  fElasticSearchClientCertKey,
			ServiceToken:          fServiceToken,
			ServiceTokenPath:      fServiceTokenPath,
			PolicyID:              fPolicy,
			Host:                  fHost,
			Port:                  fPort,
			Cert:                  fCert,
			CertKey:               fCertKey,
			CertKeyPassphrasePath: fPassphrase,
			ClientAuth:            fClientAuth,
			Insecure:              fInsecure,
			SpawnAgent:            !fromInstall,
			Headers:               mapFromEnvList(fHeaders),
			Timeout:               fTimeout,
			InternalPort:          fInternalPort,
		},
	}

	c, err := newEnrollCmd(
		ctx,
		logger,
		&options,
		pathConfigFile,
	)

	if err != nil {
		return err
	}

	return c.Execute(ctx, streams)
}

func handleSignal(ctx context.Context) context.Context {
	ctx, cfunc := context.WithCancel(ctx)

	sigs := make(chan os.Signal, 1)
	signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)

	go func() {
		select {
		case <-sigs:
			cfunc()
		case <-ctx.Done():
		}

		signal.Stop(sigs)
		close(sigs)
	}()

	return ctx
}

func mapFromEnvList(envList []string) map[string]string {
	m := make(map[string]string)
	for _, kv := range envList {
		keyValue := strings.SplitN(kv, "=", 2)
		if len(keyValue) != 2 {
			continue
		}

		m[keyValue[0]] = keyValue[1]
	}
	return m
}
