package testutils

import (
	"net/http"

	"github.com/elastic/elastic-agent/internal/pkg/core/state"
	"github.com/elastic/elastic-agent/internal/pkg/core/status"
	"github.com/stretchr/testify/mock"
)

type MockController struct {
	mock.Mock
}

func (m *MockController) SetAgentID(id string) {
	m.Called(id)
}

func (m *MockController) RegisterComponent(id string) status.Reporter {
	args := m.Called(id)
	return args.Get(0).(status.Reporter)
}

func (m *MockController) RegisterComponentWithPersistance(id string, b bool) status.Reporter {
	args := m.Called(id, b)
	return args.Get(0).(status.Reporter)
}

func (m *MockController) RegisterApp(id, name string) status.Reporter {
	args := m.Called(id, name)
	return args.Get(0).(status.Reporter)
}

func (m *MockController) Status() status.AgentStatus {
	args := m.Called()
	return args.Get(0).(status.AgentStatus)
}

func (m *MockController) StatusCode() status.AgentStatusCode {
	args := m.Called()
	return args.Get(0).(status.AgentStatusCode)
}

func (m *MockController) StatusString() string {
	args := m.Called()
	return args.String(0)
}

func (m *MockController) UpdateStateID(id string) {
	m.Called(id)
}

func (m *MockController) ServeHTTP(wr http.ResponseWriter, req *http.Request) {
	m.Called(wr, req)
}

type MockReporter struct {
	mock.Mock
}

func (m *MockReporter) Update(state state.Status, message string, meta map[string]interface{}) {
	m.Called(state, message, meta)
}

func (m *MockReporter) Unregister() {
	m.Called()
}
