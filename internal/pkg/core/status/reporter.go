// Copyright Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
// or more contributor license agreements. Licensed under the Elastic License;
// you may not use this file except in compliance with the Elastic License.

// Package status handles process status reporting.
package status

import (
	"fmt"
	"net/http"
	"reflect"
	"sync"
	"time"

	"github.com/google/uuid"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"

	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/pkg/core/logger"
)

// AgentStatusCode is the status code for the Elastic Agent overall.
type AgentStatusCode int

const (
	// Healthy status means everything is fine.
	Healthy AgentStatusCode = iota
	// Degraded status means something minor is preventing agent to work properly.
	Degraded
	// Failed status means agent is unable to work properly.
	Failed
)

// String returns the string value for the agent code.
func (s AgentStatusCode) String() string {
	return []string{"online", "degraded", "error"}[s]
}

// AgentApplicationStatus returns the status of specific application.
type AgentApplicationStatus struct {
	ID      string
	Name    string
	Status  state.Status
	Message string
	Payload map[string]interface{}
}

// AgentStatus returns the overall status of the Elastic Agent.
type AgentStatus struct {
	Status       AgentStatusCode
	Message      string
	Applications []AgentApplicationStatus
	UpdateTime   time.Time
}

// Controller takes track of component statuses.
type Controller interface {
	SetAgentID(string)
	RegisterComponent(string) Reporter
	RegisterLocalComponent(string) Reporter
	RegisterComponentWithPersistance(string, bool) Reporter
	RegisterApp(id string, name string) Reporter
	Status() AgentStatus
	LocalStatus() AgentStatus
	StatusCode() AgentStatusCode
	StatusString() string
	UpdateStateID(string)
	ServeHTTP(http.ResponseWriter, *http.Request)
}

type controller struct {
	updateTime     time.Time
	log            *logger.Logger
	reporters      map[string]*reporter
	localReporters map[string]*reporter
	appReporters   map[string]*reporter
	stateID        string
	message        string
	agentID        string
	status         AgentStatusCode
	localStatus    AgentStatusCode
	localMessage   string
	localTime      time.Time
	mx             sync.Mutex
}

// NewController creates a new reporter.
func NewController(log *logger.Logger) Controller {
	return &controller{
		status:         Healthy,
		reporters:      make(map[string]*reporter),
		localReporters: make(map[string]*reporter),
		appReporters:   make(map[string]*reporter),
		log:            log,
	}
}

// SetAgentID sets the agentID of the controller
// The AgentID may be used in the handler output.
func (r *controller) SetAgentID(agentID string) {
	r.mx.Lock()
	defer r.mx.Unlock()
	r.agentID = agentID
}

// UpdateStateID cleans health when new configuration is received.
// To prevent reporting failures from previous configuration.
func (r *controller) UpdateStateID(stateID string) {
	if stateID == r.stateID {
		return
	}

	r.mx.Lock()

	r.stateID = stateID
	// cleanup status for component reporters
	// the status of app reports remain the same
	for _, rep := range r.reporters {
		if !rep.isRegistered {
			continue
		}

		rep.mx.Lock()
		if !rep.isPersistent {
			rep.status = state.Configuring
			rep.message = ""
		}
		rep.mx.Unlock()
	}
	r.mx.Unlock()

	r.updateStatus()
}

// RegisterLocalComponent registers new component for local-only status updates.
func (r *controller) RegisterLocalComponent(componentIdentifier string) Reporter {
	id := componentIdentifier + "-" + uuid.New().String()[:8]
	rep := &reporter{
		name:         componentIdentifier,
		isRegistered: true,
		unregisterFunc: func() {
			r.mx.Lock()
			delete(r.localReporters, id)
			r.mx.Unlock()
		},
		notifyChangeFunc: r.updateStatus,
		isPersistent:     false,
	}

	r.mx.Lock()
	r.localReporters[id] = rep
	r.mx.Unlock()

	return rep
}

// RegisterComponent registers new component for status updates.
func (r *controller) RegisterComponent(componentIdentifier string) Reporter {
	return r.RegisterComponentWithPersistance(componentIdentifier, false)
}

// RegisterComponentWithPersistance registers new component for status updates.
func (r *controller) RegisterComponentWithPersistance(componentIdentifier string, persistent bool) Reporter {
	id := componentIdentifier + "-" + uuid.New().String()[:8]
	rep := &reporter{
		name:         componentIdentifier,
		isRegistered: true,
		unregisterFunc: func() {
			r.mx.Lock()
			delete(r.reporters, id)
			r.mx.Unlock()
		},
		notifyChangeFunc: r.updateStatus,
		isPersistent:     persistent,
	}

	r.mx.Lock()
	r.reporters[id] = rep
	r.mx.Unlock()

	return rep
}

// RegisterApp registers new component for status updates.
func (r *controller) RegisterApp(componentIdentifier string, name string) Reporter {
	id := componentIdentifier + "-" + uuid.New().String()[:8]
	rep := &reporter{
		name:         name,
		status:       state.Stopped,
		isRegistered: true,
		unregisterFunc: func() {
			r.mx.Lock()
			delete(r.appReporters, id)
			r.mx.Unlock()
		},
		notifyChangeFunc: r.updateStatus,
	}

	r.mx.Lock()
	r.appReporters[id] = rep
	r.mx.Unlock()

	return rep
}

// Status retrieves current agent status.
func (r *controller) Status() AgentStatus {
	r.mx.Lock()
	defer r.mx.Unlock()
	apps := make([]AgentApplicationStatus, 0, len(r.appReporters))
	for key, rep := range r.appReporters {
		rep.mx.Lock()
		apps = append(apps, AgentApplicationStatus{
			ID:      key,
			Name:    rep.name,
			Status:  rep.status,
			Message: rep.message,
			Payload: rep.payload,
		})
		rep.mx.Unlock()
	}
	return AgentStatus{
		Status:       r.status,
		Message:      r.message,
		Applications: apps,
		UpdateTime:   r.updateTime,
	}
}

// LocalStatus returns the status from the local registered components if they are different from the agent status.
// If the agent status is more severe then the local status (failed vs degraded for example) agent status is used.
// If they are equal (healthy and healthy) agent status is used.
func (r *controller) LocalStatus() AgentStatus {
	status := r.Status()
	r.mx.Lock()
	defer r.mx.Unlock()

	if r.localStatus > status.Status {
		return AgentStatus{
			Status:     r.localStatus,
			Message:    r.localMessage,
			UpdateTime: r.localTime,
		}
	}
	return status

}

// StatusCode retrieves current agent status code.
func (r *controller) StatusCode() AgentStatusCode {
	r.mx.Lock()
	defer r.mx.Unlock()
	return r.status
}

func (r *controller) updateStatus() {
	status := Healthy
	lStatus := Healthy
	message := ""
	lMessage := ""

	r.mx.Lock()
	for id, rep := range r.localReporters {
		s := statusToAgentStatus(rep.status)
		if s > lStatus {
			lStatus = s
			lMessage = fmt.Sprintf("component %s: %s", id, rep.message)
		}
		r.log.Debugf("local component '%s' has status '%s'", id, s)
		if status == Failed {
			break
		}
	}

	for id, rep := range r.reporters {
		s := statusToAgentStatus(rep.status)
		if s > status {
			status = s
			message = fmt.Sprintf("component %s: %s", id, rep.message)
		}

		r.log.Debugf("'%s' has status '%s'", id, s)
		if status == Failed {
			break
		}
	}
	if status != Failed {
		for id, rep := range r.appReporters {
			s := statusToAgentStatus(rep.status)
			if s > status {
				status = s
				message = fmt.Sprintf("app %s: %s", id, rep.message)
			}

			r.log.Debugf("'%s' has status '%s'", id, s)
			if status == Failed {
				break
			}
		}
	}

	if r.status != status {
		r.logStatus(status, message)
		r.status = status
		r.message = message
		r.updateTime = time.Now().UTC()
	}
	if r.localStatus != lStatus {
		r.localStatus = lStatus
		r.localMessage = lMessage
		r.localTime = time.Now().UTC()
	}

	r.mx.Unlock()

}

func (r *controller) logStatus(status AgentStatusCode, message string) {
	// Use at least warning level log for all statuses to make sure they are visible in the logs
	logFn := r.log.Warnf
	if status == Failed {
		logFn = r.log.Errorf
	}

	logFn("Elastic Agent status changed to %q: %q", status, message)
}

// StatusString retrieves human readable string of current agent status.
func (r *controller) StatusString() string {
	return r.StatusCode().String()
}

// Reporter reports status of component
type Reporter interface {
	Update(state.Status, string, map[string]interface{})
	Unregister()
}

type reporter struct {
	name             string
	mx               sync.Mutex
	isPersistent     bool
	isRegistered     bool
	status           state.Status
	message          string
	payload          map[string]interface{}
	unregisterFunc   func()
	notifyChangeFunc func()
}

// Update updates the status of a component.
func (r *reporter) Update(s state.Status, message string, payload map[string]interface{}) {
	r.mx.Lock()
	defer r.mx.Unlock()

	if !r.isRegistered {
		return
	}
	if state.IsStateFiltered(message, payload) {
		return
	}

	if r.status != s || r.message != message || !reflect.DeepEqual(r.payload, payload) {
		r.status = s
		r.message = message
		r.payload = payload
		r.notifyChangeFunc()
	}
}

// Unregister unregisters status from reporter. Reporter will no longer be taken into consideration
// for overall status computation.
func (r *reporter) Unregister() {
	r.mx.Lock()
	defer r.mx.Unlock()

	r.isRegistered = false
	r.unregisterFunc()
	r.notifyChangeFunc()
}

func statusToAgentStatus(status state.Status) AgentStatusCode {
	s := status.ToProto()
	if s == proto.StateObserved_DEGRADED {
		return Degraded
	}
	if s == proto.StateObserved_FAILED {
		return Failed
	}
	return Healthy
}
