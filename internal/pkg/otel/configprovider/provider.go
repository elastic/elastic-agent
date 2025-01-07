package configprovider

import (
	"context"
	"fmt"

	"github.com/elastic/elastic-agent/internal/pkg/config"
	"go.opentelemetry.io/collector/confmap"
)

type provider struct {
	otelConfProvider confmap.Provider
}

func NewFactory(otelPF func() confmap.ProviderFactory) confmap.ProviderFactory {
	providerFunc := func(set confmap.ProviderSettings) confmap.Provider {
		otelFactory := otelPF()
		return &provider{
			otelConfProvider: otelFactory.Create(set),
		}
	}

	return confmap.NewProviderFactory(providerFunc)
}

func removeElasticFields(conf any) (map[string]interface{}, error) {
	otelOnlyConf := map[string]interface{}{}
	mapRaw, ok := conf.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("provided hybrid configuration is of type %T, expected map[string]interface{}", conf)
	}

	for _, key := range config.OTelConfKeys {
		v, ok := mapRaw[key]
		if ok {
			otelOnlyConf[key] = v
		}
	}
	return otelOnlyConf, nil
}

func (p *provider) Retrieve(ctx context.Context, uri string, watcher confmap.WatcherFunc) (*confmap.Retrieved, error) {
	ret, err := p.otelConfProvider.Retrieve(ctx, uri, watcher)
	if err != nil {
		return nil, err
	}

	raw, err := ret.AsRaw()
	if err != nil {
		return nil, err
	}

	otelOnlyConf, err := removeElasticFields(raw)
	if err != nil {
		return nil, fmt.Errorf("error removing elastic fields: %w", err)
	}

	return confmap.NewRetrieved(otelOnlyConf)
}

func (p *provider) Scheme() string {
	return p.otelConfProvider.Scheme()
}

func (p *provider) Shutdown(ctx context.Context) error {
	return p.otelConfProvider.Shutdown(ctx)
}
