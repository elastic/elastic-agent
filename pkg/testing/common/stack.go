package common

import "context"

// Stack is a created stack.
type Stack struct {
	// ID is the identifier of the instance.
	//
	// This must be the same ID used for requesting a stack.
	ID string `yaml:"id"`

	// Provisioner is the stack provisioner. See STACK_PROVISIONER environment
	// variable for the supported provisioners.
	Provisioner string `yaml:"provisioner"`

	// Version is the version of the stack.
	Version string `yaml:"version"`

	// Ready determines if the stack is ready to be used.
	Ready bool `yaml:"ready"`

	// Elasticsearch is the URL to communicate with elasticsearch.
	Elasticsearch string `yaml:"elasticsearch"`

	// Kibana is the URL to communication with kibana.
	Kibana string `yaml:"kibana"`

	// Username is the username.
	Username string `yaml:"username"`

	// Password is the password.
	Password string `yaml:"password"`

	// Internal holds internal information used by the provisioner.
	// Best to not touch the contents of this, and leave it be for
	// the provisioner.
	Internal map[string]interface{} `yaml:"internal"`
}

// Same returns true if other is the same stack as this one.
// Two stacks are considered the same if their provisioner and ID are the same.
func (s Stack) Same(other Stack) bool {
	return s.Provisioner == other.Provisioner &&
		s.ID == other.ID
}

// StackRequest request for a new stack.
type StackRequest struct {
	// ID is the unique ID for the stack.
	ID string `yaml:"id"`

	// Version is the version of the stack.
	Version string `yaml:"version"`
}

// StackProvisioner performs the provisioning of stacks.
type StackProvisioner interface {
	// Name returns the name of the stack provisioner.
	Name() string

	// SetLogger sets the logger for it to use.
	SetLogger(l Logger)

	// Create creates a stack.
	Create(ctx context.Context, request StackRequest) (Stack, error)

	// WaitForReady should block until the stack is ready or the context is cancelled.
	WaitForReady(ctx context.Context, stack Stack) (Stack, error)

	// Delete deletes the stack.
	Delete(ctx context.Context, stack Stack) error
}
