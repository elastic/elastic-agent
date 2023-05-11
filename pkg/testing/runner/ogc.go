package runner

// OGCLayout definition required by OGC to import.
type OGCLayout struct {
	Name          string            `yaml:"name"`
	Provider      string            `yaml:"provider"`
	InstanceSize  string            `yaml:"instance_size"`
	RunsOn        string            `yaml:"runs_on"`
	RemotePath    string            `yaml:"remote_path"`
	Scale         int               `yaml:"scale"`
	Username      string            `yaml:"username"`
	SSHPrivateKey string            `yaml:"ssh_private_key"`
	SSHPublicKey  string            `yaml:"ssh_public_key"`
	Ports         []string          `yaml:"ports"`
	Tags          []string          `yaml:"tags"`
	Labels        map[string]string `yaml:"labels"`
	Scripts       string            `yaml:"scripts"`
}
