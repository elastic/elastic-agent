package fleetservertest

import (
	"net/http"
	"sync"
	"time"
)

type ActionTmpl struct {
	AgentID  string
	ActionID string
	Data     string
	Type     string
}

type CheckinData struct {
	AckToken      string
	AckableAction []AckableAction
	Delay         time.Duration
}

type CheckinActionsWithAcker struct {
	mu sync.Mutex

	checkinsSent int
	checkinDatas []CheckinData
}

// NewCheckinActionsWithAcker returns a new CheckinActionsWithAcker.
// CheckinActionsWithAcker allows to add a set of action to be delivered in a
// checkin. Each call to CheckinActionsWithAcker.AddCheckin will add the actions
// to be returned in the "next" checkin. All checking must be added BEFORE any
// checkin happens!
// All actions can be acked only after they've been delivered.
// Use CheckinActionsWithAcker.ActionsGenerator and CheckinActionsWithAcker.Acker
// to get closures encapsulating calls to CheckinActionsWithAcker.NextAction and
// CheckinActionsWithAcker.Ack respectively.
//
// TODO: Make possible to add checkins on the fly.
func NewCheckinActionsWithAcker() CheckinActionsWithAcker {
	return CheckinActionsWithAcker{}
}

func (c *CheckinActionsWithAcker) ActionsGenerator() ActionsGenerator {
	return func() (CheckinAction, *HTTPError) { return c.NextAction() }
}

func (c *CheckinActionsWithAcker) Acker() Acker {
	return func(actionID string) (AckResponseItem, bool) { return c.Ack(actionID) }
}
func (c *CheckinActionsWithAcker) NextAction() (CheckinAction, *HTTPError) {
	c.mu.Lock()
	defer c.mu.Unlock()

	defer func() { c.checkinsSent++ }()

	// no more actions to send on checkin
	if c.checkinsSent >= len(c.checkinDatas) {
		return CheckinAction{}, nil
	}

	checkin := c.checkinDatas[c.checkinsSent]

	var actions []string
	for _, a := range checkin.AckableAction {
		actions = append(actions, a.data)
	}
	return CheckinAction{
		AckToken: checkin.AckToken,
		Actions:  actions,
		Delay:    0,
	}, nil
}

func (c *CheckinActionsWithAcker) Ack(actionID string) (AckResponseItem, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// acker was called before the 1st checkin, thus no actions to ack.
	if c.checkinsSent == 0 {
		return AckResponseItem{
			Status:  http.StatusNotFound,
			Message: "no checkin have happened yet",
		}, true
	}

	// all checkins with actions have happened and have been acked.
	if c.checkinsSent >= len(c.checkinDatas) {
		return AckResponseItem{
			Status:  http.StatusNotFound,
			Message: "no more actions to ack",
		}, true
	}

	for _, checkin := range c.checkinDatas[:c.checkinsSent] {
		for _, actionData := range checkin.AckableAction {
			if actionData.ActionID == actionID {
				return AckResponseItem{
					Status:  http.StatusOK,
					Message: http.StatusText(http.StatusOK),
				}, false
			}
		}
	}

	return AckResponseItem{
		Status:  http.StatusNotFound,
		Message: http.StatusText(http.StatusNotFound),
	}, false
}

func (c *CheckinActionsWithAcker) AddCheckin(
	ackToken string,
	delay time.Duration,
	actions ...AckableAction) {

	c.mu.Lock()
	defer c.mu.Unlock()

	c.checkinDatas = append(c.checkinDatas, CheckinData{
		AckToken:      ackToken,
		AckableAction: actions,
		Delay:         delay,
	})
}
