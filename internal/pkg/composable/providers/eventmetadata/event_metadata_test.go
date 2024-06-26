package eventmetadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/structpb"

	"github.com/elastic/elastic-agent-client/v7/pkg/proto"
	"github.com/elastic/elastic-agent/internal/pkg/config"
	"github.com/elastic/elastic-agent/pkg/component"
)

const (
	providerConfig1YAML = `
        providers:
             event_metadata:
                 # The default value would be true to avoid a breaking change when they aren't specified.
                 host: # controls add_host_metadata
                     enabled: true
                 kubernetes: # controls add_kubernetes_metadata
                     enabled: false
                 cloud: # controls add_cloud_metadata
                     enabled: true
                 docker: # controls add_docker_metadata 
                     enabled: false
`
	providerConfigWithConfigKeysYAML = `
        providers:
             event_metadata:
                 # The default value would be true to avoid a breaking change when they aren't specified.
                 host: # controls add_host_metadata
                     enabled: true
                     foo: bar
                     nestedkey:
                       nestedobj1:
                         key1: value1
                         list:
                         - val1
                         - val2
                 kubernetes: # controls add_kubernetes_metadata
                     enabled: false
`
)

func TestSetGlobalProcessorConfig(t *testing.T) {
	processorsConfig1 := &proto.GlobalProcessorsConfig{
		Configs: map[string]*proto.ProcessorConfig{
			"host": {
				Enabled: true,
				Config:  mustNewStructFromMap(t, nil),
			},
			"cloud": {
				Enabled: true,
				Config:  mustNewStructFromMap(t, nil),
			},
			"docker": {
				Enabled: false,
				Config:  mustNewStructFromMap(t, nil),
			},
			"kubernetes": {
				Enabled: false,
				Config:  mustNewStructFromMap(t, nil),
			},
		},
	}

	processorsWithConfigKeys := &proto.GlobalProcessorsConfig{
		Configs: map[string]*proto.ProcessorConfig{
			"host": {
				Enabled: true,
				Config: mustNewStructFromMap(t, map[string]any{
					"foo": "bar",
					"nestedkey": map[string]any{
						"nestedobj1": map[string]any{
							"key1": "value1",
							"list": []any{"val1", "val2"},
						},
					},
				}),
			},
			"kubernetes": {
				Enabled: false,
				Config:  mustNewStructFromMap(t, nil),
			},
		},
	}

	type args struct {
		comps []component.Component
		cfg   map[string]interface{}
	}
	tests := []struct {
		name    string
		args    args
		want    *proto.GlobalProcessorsConfig
		wantErr bool
	}{
		{
			name: "Empty config, no error, no change",
			args: args{
				comps: []component.Component{createEmptyComponent(t, "comp1")},
				cfg:   map[string]any{},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "other providers in config, no error, no change",
			args: args{
				comps: []component.Component{createEmptyComponent(t, "comp1")},
				cfg:   map[string]any{"providers": map[string]any{"foobar": "someconfig"}},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "event providers in config, no error, adding config1 to components",
			args: args{
				comps: []component.Component{createEmptyComponent(t, "comp1"), createEmptyComponent(t, "comp2")},
				cfg:   mustCreateConfigMap(t, providerConfig1YAML),
			},
			want:    processorsConfig1,
			wantErr: false,
		},
		{
			name: "event providers enabled/disabled in config, no error",
			args: args{
				comps: []component.Component{createEmptyComponent(t, "comp1"), createEmptyComponent(t, "comp2")},
				cfg:   mustCreateConfigMap(t, providerConfig1YAML),
			},
			want:    processorsConfig1,
			wantErr: false,
		},
		{
			name: "event providers with configuration, no error",
			args: args{
				comps: []component.Component{createEmptyComponent(t, "comp1"), createEmptyComponent(t, "comp2")},
				cfg:   mustCreateConfigMap(t, providerConfigWithConfigKeysYAML),
			},
			want:    processorsWithConfigKeys,
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := SetGlobalProcessorConfig(tt.args.comps, tt.args.cfg)
			if (err != nil) != tt.wantErr {
				t.Errorf("SetGlobalProcessorConfig() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			assert.Len(t, got, len(tt.args.comps), "number of components returned must be the same as input")

			for i := range got {
				// assert all components got the same provider config
				if tt.want == nil {
					// either Component or provider config should be nil
					assert.True(t, got[i].Component == nil || got[i].Component.Processors == nil)
				} else {
					// set source to nil for comparison of the rest
					got[i].Component.Processors.Source = nil
					assert.Equal(t, tt.want, got[i].Component.Processors)
				}
			}
		})
	}
}

func mustNewStructFromMap(t *testing.T, m map[string]any) *structpb.Struct {
	t.Helper()
	mStruct, err := structpb.NewStruct(m)
	require.NoError(t, err, "error creating empty pb struct")
	return mStruct
}

func mustCreateConfigMap(t *testing.T, configYAML string) map[string]interface{} {
	t.Helper()
	providerConfig, err := config.MustNewConfigFrom(configYAML).ToMapStr()
	require.NoError(t, err, "error parsing yaml and transforming into a map:\n%s\n", configYAML)
	return providerConfig
}

func createEmptyComponent(t *testing.T, compID string) component.Component {
	t.Helper()
	return component.Component{
		ID:        compID,
		Component: &proto.Component{},
	}
}
