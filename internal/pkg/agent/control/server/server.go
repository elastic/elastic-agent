// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"

	"go.elastic.co/apm"
	"go.elastic.co/apm/module/apmgrpc"
	"google.golang.org/grpc"

	"github.com/elastic/elastic-agent/internal/pkg/agent/application/coordinator"

	"github.com/elastic/elastic-agent/internal/pkg/agent/control"
	"github.com/elastic/elastic-agent/internal/pkg/agent/control/cproto"
	monitoringCfg "github.com/elastic/elastic-agent/internal/pkg/core/monitoring/config"
	"github.com/elastic/elastic-agent/internal/pkg/release"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// Server is the daemon side of the control protocol.
type Server struct {
	cproto.UnimplementedElasticAgentControlServer

	logger        *logger.Logger
	monitoringCfg *monitoringCfg.MonitoringConfig
	coord         *coordinator.Coordinator
	listener      net.Listener
	server        *grpc.Server
	tracer        *apm.Tracer
}

// New creates a new control protocol server.
func New(log *logger.Logger, cfg *monitoringCfg.MonitoringConfig, coord *coordinator.Coordinator, tracer *apm.Tracer) *Server {
	return &Server{
		logger:        log,
		monitoringCfg: cfg,
		coord:         coord,
		tracer:        tracer,
	}
}

// Start starts the GRPC endpoint and accepts new connections.
func (s *Server) Start() error {
	if s.server != nil {
		// already started
		return nil
	}

	lis, err := createListener(s.logger)
	if err != nil {
		s.logger.Errorf("unable to create listener: %s", err)
		return err
	}
	s.listener = lis
	if s.tracer != nil {
		apmInterceptor := apmgrpc.NewUnaryServerInterceptor(apmgrpc.WithRecovery(), apmgrpc.WithTracer(s.tracer))
		s.server = grpc.NewServer(grpc.UnaryInterceptor(apmInterceptor))
	} else {
		s.server = grpc.NewServer()
	}
	cproto.RegisterElasticAgentControlServer(s.server, s)

	// start serving GRPC connections
	go func() {
		err := s.server.Serve(lis)
		if err != nil {
			s.logger.Errorf("error listening for GRPC: %s", err)
		}
	}()

	return nil
}

// Stop stops the GRPC endpoint.
func (s *Server) Stop() {
	if s.server != nil {
		s.server.Stop()
		s.server = nil
		s.listener = nil
		cleanupListener(s.logger)
	}
}

// Version returns the currently running version.
func (s *Server) Version(_ context.Context, _ *cproto.Empty) (*cproto.VersionResponse, error) {
	return &cproto.VersionResponse{
		Version:   release.Version(),
		Commit:    release.Commit(),
		BuildTime: release.BuildTime().Format(control.TimeFormat()),
		Snapshot:  release.Snapshot(),
	}, nil
}

// State returns the overall state of the agent.
func (s *Server) State(_ context.Context, _ *cproto.Empty) (*cproto.StateResponse, error) {
	var err error

	state := s.coord.State(true)
	components := make([]*cproto.ComponentState, 0, len(state.Components))
	for _, comp := range state.Components {
		units := make([]*cproto.ComponentUnitState, 0, len(comp.State.Units))
		for key, unit := range comp.State.Units {
			payload := []byte("")
			if unit.Payload != nil {
				payload, err = json.Marshal(unit.Payload)
				if err != nil {
					return nil, fmt.Errorf("failed to marshal componend %s unit %s payload: %w", comp.Component.ID, key.UnitID, err)
				}
			}
			units = append(units, &cproto.ComponentUnitState{
				UnitType: cproto.UnitType(key.UnitType),
				UnitId:   key.UnitID,
				State:    cproto.State(unit.State),
				Message:  unit.Message,
				Payload:  string(payload),
			})
		}
		components = append(components, &cproto.ComponentState{
			Id:      comp.Component.ID,
			Name:    comp.Component.Spec.BinaryName,
			State:   cproto.State(comp.State.State),
			Message: comp.State.Message,
			Units:   units,
			VersionInfo: &cproto.ComponentVersionInfo{
				Name:    comp.State.VersionInfo.Name,
				Version: comp.State.VersionInfo.Version,
				Meta:    comp.State.VersionInfo.Meta,
			},
		})
	}
	return &cproto.StateResponse{
		State:      state.State,
		Message:    state.Message,
		Components: components,
	}, nil
}

// Restart performs re-exec.
func (s *Server) Restart(_ context.Context, _ *cproto.Empty) (*cproto.RestartResponse, error) {
	s.coord.ReExec(nil)
	return &cproto.RestartResponse{
		Status: cproto.ActionStatus_SUCCESS,
	}, nil
}

// Upgrade performs the upgrade operation.
func (s *Server) Upgrade(ctx context.Context, request *cproto.UpgradeRequest) (*cproto.UpgradeResponse, error) {
	err := s.coord.Upgrade(ctx, request.Version, request.SourceURI, nil)
	if err != nil {
		return &cproto.UpgradeResponse{ //nolint:nilerr // returns err as response
			Status: cproto.ActionStatus_FAILURE,
			Error:  err.Error(),
		}, nil
	}
	return &cproto.UpgradeResponse{
		Status:  cproto.ActionStatus_SUCCESS,
		Version: request.Version,
	}, nil
}

// BeatInfo is the metadata response a beat will provide when the root ("/") is queried.
type BeatInfo struct {
	Beat            string `json:"beat"`
	Name            string `json:"name"`
	Hostname        string `json:"hostname"`
	ID              string `json:"uuid"`
	EphemeralID     string `json:"ephemeral_id"`
	Version         string `json:"version"`
	Commit          string `json:"build_commit"`
	Time            string `json:"build_time"`
	Username        string `json:"username"`
	UserID          string `json:"uid"`
	GroupID         string `json:"gid"`
	BinaryArch      string `json:"binary_arch"`
	ElasticLicensed bool   `json:"elastic_licensed"`
}

// ProcMeta returns version and beat inforation for all running processes.
func (s *Server) ProcMeta(ctx context.Context, _ *cproto.Empty) (*cproto.ProcMetaResponse, error) {
	/*
		if s.routeFn == nil {
			return nil, errors.New("route function is nil")
		}

		resp := &cproto.ProcMetaResponse{
			Procs: []*cproto.ProcMeta{},
		}

		// gather spec data for all rk/apps running
		specs := s.getSpecInfo("", "")
		for _, si := range specs {
			endpoint := monitoring.MonitoringEndpoint(si.spec, runtime.GOOS, si.rk)
			client := newSocketRequester(si.app, si.rk, endpoint)

			procMeta := client.procMeta(ctx)
			resp.Procs = append(resp.Procs, procMeta)
		}

		return resp, nil
	*/
	return nil, nil
}

// Pprof returns /debug/pprof data for the requested applicaiont-route_key or all running applications.
func (s *Server) Pprof(ctx context.Context, req *cproto.PprofRequest) (*cproto.PprofResponse, error) {
	if s.monitoringCfg == nil || s.monitoringCfg.Pprof == nil || !s.monitoringCfg.Pprof.Enabled {
		return nil, fmt.Errorf("agent.monitoring.pprof disabled")
	}

	/*
		if s.routeFn == nil {
			return nil, errors.New("route function is nil")
		}

		dur, err := time.ParseDuration(req.TraceDuration)
		if err != nil {
			return nil, fmt.Errorf("unable to parse trace duration: %w", err)
		}

		resp := &cproto.PprofResponse{
			Results: []*cproto.PprofResult{},
		}

		var wg sync.WaitGroup
		ch := make(chan *cproto.PprofResult, 1)

		// retrieve elastic-agent pprof data if requested or application is unspecified.
		if req.AppName == "" || req.AppName == agentName {
			endpoint := monitoring.AgentMonitoringEndpoint(runtime.GOOS, s.monitoringCfg.HTTP)
			c := newSocketRequester(agentName, "", endpoint)
			for _, opt := range req.PprofType {
				wg.Add(1)
				go func(opt cproto.PprofOption) {
					res := c.getPprof(ctx, opt, dur)
					ch <- res
					wg.Done()
				}(opt)
			}
		}

		// get requested rk/appname spec or all specs
		var specs []specInfo
		if req.AppName != agentName {
			specs = s.getSpecInfo(req.RouteKey, req.AppName)
		}
		for _, si := range specs {
			endpoint := monitoring.MonitoringEndpoint(si.spec, runtime.GOOS, si.rk)
			c := newSocketRequester(si.app, si.rk, endpoint)
			// Launch a concurrent goroutine to gather all pprof endpoints from a socket.
			for _, opt := range req.PprofType {
				wg.Add(1)
				go func(opt cproto.PprofOption) {
					res := c.getPprof(ctx, opt, dur)
					ch <- res
					wg.Done()
				}(opt)
			}
		}

		// wait for the waitgroup to be done and close the channel
		go func() {
			wg.Wait()
			close(ch)
		}()

		// gather all results from channel until closed.
		for res := range ch {
			resp.Results = append(resp.Results, res)
		}
		return resp, nil
	*/
	return nil, nil
}

// ProcMetrics returns all buffered metrics data for the agent and running processes.
// If the agent.monitoring.http.buffer variable is not set, or set to false, a nil result attribute is returned
func (s *Server) ProcMetrics(ctx context.Context, _ *cproto.Empty) (*cproto.ProcMetricsResponse, error) {
	if s.monitoringCfg == nil || s.monitoringCfg.HTTP == nil || s.monitoringCfg.HTTP.Buffer == nil || !s.monitoringCfg.HTTP.Buffer.Enabled {
		return &cproto.ProcMetricsResponse{}, nil
	}

	/*
		if s.routeFn == nil {
			return nil, errors.New("route function is nil")
		}

		// gather metrics buffer data from the elastic-agent
		endpoint := monitoring.AgentMonitoringEndpoint(runtime.GOOS, s.monitoringCfg.HTTP)
		c := newSocketRequester(agentName, "", endpoint)
		metrics := c.procMetrics(ctx)

		resp := &cproto.ProcMetricsResponse{
			Result: []*cproto.MetricsResponse{metrics},
		}

		// gather metrics buffer data from all other processes
		specs := s.getSpecInfo("", "")
		for _, si := range specs {
			endpoint := monitoring.MonitoringEndpoint(si.spec, runtime.GOOS, si.rk)
			client := newSocketRequester(si.app, si.rk, endpoint)

			s.logger.Infof("gather metrics from %s", endpoint)
			metrics := client.procMetrics(ctx)
			resp.Result = append(resp.Result, metrics)
		}
		return resp, nil
	*/
	return nil, nil
}

/*
// getSpecs will return the specs for the program associated with the specified route key/app name, or all programs if no key(s) are specified.
// if matchRK or matchApp are empty all results will be returned.
func (s *Server) getSpecInfo(matchRK, matchApp string) []specInfo {
	routes := s.routeFn()

	// find specInfo for a specified rk/app
	if matchRK != "" && matchApp != "" {
		programs, ok := routes.Get(matchRK)
		if !ok {
			s.logger.With("route_key", matchRK).Debug("No matching route key found.")
			return []specInfo{}
		}
		sp, ok := programs.(specer)
		if !ok {
			s.logger.With("route_key", matchRK, "route", programs).Warn("Unable to cast route as specer.")
			return []specInfo{}
		}
		specs := sp.Specs()

		spec, ok := specs[matchApp]
		if !ok {
			s.logger.With("route_key", matchRK, "application_name", matchApp).Debug("No matching route key/application name found.")
			return []specInfo{}
		}
		return []specInfo{specInfo{spec: spec, app: matchApp, rk: matchRK}}
	}

	// gather specInfo for all rk/app values
	res := make([]specInfo, 0)
	for _, rk := range routes.Keys() {
		programs, ok := routes.Get(rk)
		if !ok {
			// we do not expect to ever hit this code path
			// if this log message occurs then the agent is unable to access one of the keys that is returned by the route function
			// might be a race condition if someone tries to update the policy to remove an output?
			s.logger.With("route_key", rk).Warn("Unable to retrieve route.")
			continue
		}
		sp, ok := programs.(specer)
		if !ok {
			s.logger.With("route_key", matchRK, "route", programs).Warn("Unable to cast route as specer.")
			continue
		}
		for n, spec := range sp.Specs() {
			res = append(res, specInfo{
				rk:   rk,
				app:  n,
				spec: spec,
			})
		}
	}
	return res
}

// socketRequester is a struct to gather (diagnostics) data from a socket opened by elastic-agent or one if it's processes
type socketRequester struct {
	c        http.Client
	endpoint string
	appName  string
	routeKey string
}

func newSocketRequester(appName, routeKey, endpoint string) *socketRequester {
	c := http.Client{}
	if strings.HasPrefix(endpoint, "unix://") {
		c.Transport = &http.Transport{
			Proxy:       nil,
			DialContext: socket.DialContext(strings.TrimPrefix(endpoint, "unix://")),
		}
		endpoint = "unix"
	} else if strings.HasPrefix(endpoint, "npipe://") {
		c.Transport = &http.Transport{
			Proxy:       nil,
			DialContext: socket.DialContext(strings.TrimPrefix(endpoint, "npipe:///")),
		}
		endpoint = "npipe"
	}
	return &socketRequester{
		c:        c,
		appName:  appName,
		routeKey: routeKey,
		endpoint: endpoint,
	}
}

// getPath creates a get request for the specified path.
// Will return an error if that status code is not 200.
func (r *socketRequester) getPath(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequest("GET", "http://"+r.endpoint+path, nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)
	res, err := r.c.Do(req)
	if err != nil {
		return nil, err
	}
	if res.StatusCode != 200 {
		res.Body.Close()
		return nil, fmt.Errorf("response status is %d", res.StatusCode)
	}
	return res, nil

}

// procMeta will return process metadata by querying the "/" path.
func (r *socketRequester) procMeta(ctx context.Context) *cproto.ProcMeta {
	pm := &cproto.ProcMeta{
		Name:     r.appName,
		RouteKey: r.routeKey,
	}

	res, err := r.getPath(ctx, "/")
	if err != nil {
		pm.Error = err.Error()
		return pm
	}
	defer res.Body.Close()

	bi := &BeatInfo{}
	dec := json.NewDecoder(res.Body)
	if err := dec.Decode(bi); err != nil {
		pm.Error = err.Error()
		return pm
	}

	pm.Process = bi.Beat
	pm.Hostname = bi.Hostname
	pm.Id = bi.ID
	pm.EphemeralId = bi.EphemeralID
	pm.Version = bi.Version
	pm.BuildCommit = bi.Commit
	pm.BuildTime = bi.Time
	pm.Username = bi.Username
	pm.UserId = bi.UserID
	pm.UserGid = bi.GroupID
	pm.Architecture = bi.BinaryArch
	pm.ElasticLicensed = bi.ElasticLicensed

	return pm
}

var pprofEndpoints = map[cproto.PprofOption]string{
	cproto.PprofOption_ALLOCS:       "/debug/pprof/allocs",
	cproto.PprofOption_BLOCK:        "/debug/pprof/block",
	cproto.PprofOption_CMDLINE:      "/debug/pprof/cmdline",
	cproto.PprofOption_GOROUTINE:    "/debug/pprof/goroutine",
	cproto.PprofOption_HEAP:         "/debug/pprof/heap",
	cproto.PprofOption_MUTEX:        "/debug/pprof/mutex",
	cproto.PprofOption_PROFILE:      "/debug/pprof/profile",
	cproto.PprofOption_THREADCREATE: "/debug/pprof/threadcreate",
	cproto.PprofOption_TRACE:        "/debug/pprof/trace",
}

// getProf will gather pprof data specified by the option.
func (r *socketRequester) getPprof(ctx context.Context, opt cproto.PprofOption, dur time.Duration) *cproto.PprofResult {
	res := &cproto.PprofResult{
		AppName:   r.appName,
		RouteKey:  r.routeKey,
		PprofType: opt,
	}

	path, ok := pprofEndpoints[opt]
	if !ok {
		res.Error = "unknown path for option"
		return res
	}

	if opt == cproto.PprofOption_PROFILE || opt == cproto.PprofOption_TRACE {
		path += fmt.Sprintf("?seconds=%0.f", dur.Seconds())
	}

	resp, err := r.getPath(ctx, path)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	p, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	res.Result = p
	return res
}

// procMetrics will gather metrics buffer data
func (r *socketRequester) procMetrics(ctx context.Context) *cproto.MetricsResponse {
	res := &cproto.MetricsResponse{
		AppName:  r.appName,
		RouteKey: r.routeKey,
	}

	resp, err := r.getPath(ctx, "/buffer")
	if err != nil {
		res.Error = err.Error()
		return res
	}
	defer resp.Body.Close()

	p, err := io.ReadAll(resp.Body)
	if err != nil {
		res.Error = err.Error()
		return res
	}

	if len(p) == 0 {
		res.Error = "no content"
		return res
	}
	res.Result = p
	return res
}
*/
