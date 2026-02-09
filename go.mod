module github.com/elastic/elastic-agent

go 1.24.12

replace github.com/elastic/beats/v7 => ./beats

require (
	github.com/Jeffail/gabs/v2 v2.6.0
	github.com/Microsoft/go-winio v0.6.2
	github.com/antlr4-go/antlr/v4 v4.13.1
	github.com/blakesmith/ar v0.0.0-20190502131153-809d4375e1fb
	github.com/cavaliergopher/rpm v1.2.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/cenkalti/backoff/v5 v5.0.3
	github.com/cespare/xxhash/v2 v2.3.0
	github.com/docker/docker v28.5.2+incompatible
	github.com/docker/go-units v0.5.0
	github.com/dolmen-go/contextio v0.0.0-20200217195037-68fc5150bcd5
	github.com/elastic/beats/v7 v7.0.0-alpha2.0.20260205201918-26c266b59ad8
	github.com/elastic/cloud-on-k8s/v2 v2.0.0-20250327073047-b624240832ae
	github.com/elastic/elastic-agent-autodiscover v0.10.0
	github.com/elastic/elastic-agent-client/v7 v7.17.2
	github.com/elastic/elastic-agent-libs v0.32.1
	github.com/elastic/elastic-agent-system-metrics v0.13.6
	github.com/elastic/elastic-transport-go/v8 v8.8.0
	github.com/elastic/go-elasticsearch/v8 v8.19.2
	github.com/elastic/go-licenser v0.4.2
	github.com/elastic/go-sysinfo v1.15.4
	github.com/elastic/go-ucfg v0.8.9-0.20250307075119-2a22403faaea
	github.com/elastic/mock-es v0.0.0-20250530054253-8c3b6053f9b6
	github.com/fatih/color v1.18.0
	github.com/fsnotify/fsnotify v1.9.0
	github.com/go-viper/mapstructure/v2 v2.5.0
	github.com/gofrs/flock v0.13.0
	github.com/gofrs/uuid/v5 v5.4.0
	github.com/google/go-cmp v0.7.0
	github.com/google/go-containerregistry v0.20.3
	github.com/google/pprof v0.0.0-20250923004556-9e5a51aed1e8
	github.com/gorilla/mux v1.8.1
	github.com/jaypipes/ghw v0.12.0
	github.com/jedib0t/go-pretty/v6 v6.4.6
	github.com/josephspurrier/goversioninfo v1.5.0
	github.com/kardianos/service v1.2.1-0.20210728001519-a323c3813bc7
	github.com/knadh/koanf/maps v0.1.2
	github.com/magefile/mage v1.15.0
	github.com/oklog/ulid/v2 v2.1.1
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter v0.144.0
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status v0.144.0
	github.com/otiai10/copy v1.14.0
	github.com/rednafi/link-patrol v0.0.0-20240826150821-057643e74d4d
	github.com/rs/zerolog v1.27.0
	github.com/sajari/regression v1.0.1
	github.com/schollz/progressbar/v3 v3.13.1
	github.com/spf13/cobra v1.10.2
	github.com/spf13/pflag v1.0.10
	github.com/stretchr/testify v1.11.1
	github.com/winlabs/gowin32 v0.0.0-20240930213947-f504d7e14639
	go.elastic.co/apm/module/apmgorilla/v2 v2.6.0
	go.elastic.co/apm/module/apmgrpc/v2 v2.6.0
	go.elastic.co/apm/v2 v2.7.2
	go.elastic.co/ecszap v1.0.3
	go.elastic.co/go-licence-detector v0.7.0
	go.opentelemetry.io/collector/component/componentstatus v0.144.0
	go.opentelemetry.io/collector/component/componenttest v0.144.0
	go.opentelemetry.io/collector/config/configtelemetry v0.144.0
	go.opentelemetry.io/collector/confmap/xconfmap v0.144.0
	go.opentelemetry.io/collector/consumer v1.50.0
	go.opentelemetry.io/collector/exporter/exportertest v0.144.0
	go.opentelemetry.io/collector/extension/extensiontest v0.144.0
	go.opentelemetry.io/collector/pdata v1.50.0
	go.opentelemetry.io/collector/pipeline v1.50.0
	go.opentelemetry.io/collector/service v0.144.0
	go.opentelemetry.io/contrib/otelconf v0.18.0
	go.opentelemetry.io/otel v1.39.0
	go.opentelemetry.io/otel/metric v1.39.0
	go.opentelemetry.io/otel/sdk v1.39.0
	go.opentelemetry.io/otel/sdk/metric v1.39.0
	go.uber.org/zap v1.27.1
	go.yaml.in/yaml/v3 v3.0.4
	golang.org/x/crypto v0.47.0
	golang.org/x/exp v0.0.0-20251219203646-944ab1f22d93
	golang.org/x/mod v0.31.0
	golang.org/x/net v0.49.0
	golang.org/x/sync v0.19.0
	golang.org/x/sys v0.40.0
	golang.org/x/term v0.39.0
	golang.org/x/text v0.33.0
	golang.org/x/time v0.14.0
	golang.org/x/tools v0.40.0
	google.golang.org/api v0.257.0
	google.golang.org/grpc v1.78.0
	google.golang.org/protobuf v1.36.11
	gopkg.in/ini.v1 v1.67.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	gotest.tools/gotestsum v1.13.0
	helm.sh/helm/v3 v3.19.5
	howett.net/plist v1.0.1
	k8s.io/api v0.34.3
	k8s.io/apimachinery v0.34.3
	k8s.io/cli-runtime v0.34.2
	k8s.io/client-go v0.34.3
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.70
	sigs.k8s.io/e2e-framework v0.4.0
	sigs.k8s.io/kustomize/api v0.20.1
	sigs.k8s.io/kustomize/kyaml v0.20.1
)

require (
	github.com/distribution/reference v0.6.0 // indirect
	go.opentelemetry.io/collector/component v1.50.0
	go.opentelemetry.io/collector/confmap v1.50.0
	go.opentelemetry.io/collector/connector v0.144.0 // indirect
	go.opentelemetry.io/collector/exporter v1.50.0
	go.opentelemetry.io/collector/extension v1.50.0
	go.opentelemetry.io/collector/featuregate v1.50.0 // indirect
	go.opentelemetry.io/collector/otelcol v0.144.0
	go.opentelemetry.io/collector/processor v1.50.0 // indirect
	go.opentelemetry.io/collector/receiver v1.50.0
)

require (
	cloud.google.com/go/auth v0.17.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20240806141605-e8a1dd7889d6 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20250102033503-faa5f7b0171c // indirect
	github.com/BurntSushi/toml v1.5.0 // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/Masterminds/sprig/v3 v3.3.0 // indirect
	github.com/Masterminds/squirrel v1.5.4 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/akavel/rsrc v0.10.2 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bitfield/gotestdox v0.2.2 // indirect
	github.com/blang/semver/v4 v4.0.0 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/cilium/ebpf v0.20.0 // indirect
	github.com/containerd/containerd v1.7.29 // indirect
	github.com/containerd/errdefs v1.0.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/containerd/platforms v0.2.1 // indirect
	github.com/containerd/stargz-snapshotter/estargz v0.16.3 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.6 // indirect
	github.com/cyphar/filepath-securejoin v0.6.1 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dnephin/pflag v1.0.7 // indirect
	github.com/docker/go-connections v0.6.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/ebitengine/purego v0.9.1 // indirect
	github.com/elastic/go-docappender/v2 v2.12.1 // indirect
	github.com/elastic/go-freelru v0.16.0 // indirect
	github.com/elastic/go-structform v0.0.12 // indirect
	github.com/elastic/go-windows v1.0.2 // indirect
	github.com/elastic/gokrb5/v8 v8.0.0-20251105095404-23cc45e6a102 // indirect
	github.com/elastic/gosigar v0.14.3 // indirect
	github.com/emicklei/go-restful/v3 v3.12.2 // indirect
	github.com/evanphx/json-patch v5.9.11+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.9.11 // indirect
	github.com/exponent-io/jsonpath v0.0.0-20210407135951-1de76d718b3f // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/foxboron/go-tpm-keyfiles v0.0.0-20251226215517-609e4778396f // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-logr/zapr v1.3.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.22.1 // indirect
	github.com/go-openapi/jsonreference v0.21.3 // indirect
	github.com/go-openapi/swag v0.25.4 // indirect
	github.com/go-openapi/swag/cmdutils v0.25.4 // indirect
	github.com/go-openapi/swag/conv v0.25.4 // indirect
	github.com/go-openapi/swag/fileutils v0.25.4 // indirect
	github.com/go-openapi/swag/jsonname v0.25.4 // indirect
	github.com/go-openapi/swag/jsonutils v0.25.4 // indirect
	github.com/go-openapi/swag/loading v0.25.4 // indirect
	github.com/go-openapi/swag/mangling v0.25.4 // indirect
	github.com/go-openapi/swag/netutils v0.25.4 // indirect
	github.com/go-openapi/swag/stringutils v0.25.4 // indirect
	github.com/go-openapi/swag/typeutils v0.25.4 // indirect
	github.com/go-openapi/swag/yamlutils v0.25.4 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/gohugoio/hashstructure v0.6.0 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/gnostic-models v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/licenseclassifier v0.0.0-20221004142553-c1ed8fcf4bab // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.7 // indirect
	github.com/googleapis/gax-go/v2 v2.15.0 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/gosuri/uitable v0.0.4 // indirect
	github.com/gregjones/httpcache v0.0.0-20190611155906-901d90724c79 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.27.4 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jaypipes/pcidb v1.0.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/goidentity/v6 v6.0.1 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jmoiron/sqlx v1.4.0 // indirect
	github.com/klauspost/compress v1.18.3 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/knadh/koanf/providers/confmap v1.0.0 // indirect
	github.com/knadh/koanf/v2 v2.3.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/lestrrat-go/strftime v1.1.1 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/lufia/plan9stats v0.0.0-20251013123823-9fd1530e3ec3 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.16 // indirect
	github.com/mileusna/useragent v1.3.5 // indirect
	github.com/minio/sha256-simd v1.0.1 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/spdystream v0.5.0 // indirect
	github.com/moby/term v0.5.2 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.3-0.20250322232337-35a7c28c31ee // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/common v0.144.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal v0.144.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.1 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.23 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20240221224432-82ca36839d55 // indirect
	github.com/prometheus/client_golang v1.23.2 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.67.4 // indirect
	github.com/prometheus/procfs v0.19.2 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20250401214520-65e299d6c5c9 // indirect
	github.com/rivo/uniseg v0.4.7 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/rubenv/sql-migrate v1.8.0 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/santhosh-tekuri/jsonschema/v6 v6.0.2 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/shirou/gopsutil/v4 v4.25.12 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/cast v1.10.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.16 // indirect
	github.com/tklauser/numcpus v0.11.0 // indirect
	github.com/urfave/cli/v2 v2.27.4 // indirect
	github.com/vbatts/tar-split v0.11.6 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/yuin/goldmark v1.7.13 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	go.elastic.co/apm/module/apmelasticsearch/v2 v2.7.2 // indirect
	go.elastic.co/apm/module/apmhttp/v2 v2.7.2 // indirect
	go.elastic.co/apm/module/apmzap/v2 v2.7.0 // indirect
	go.elastic.co/fastjson v1.5.1 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/collector/client v1.50.0 // indirect
	go.opentelemetry.io/collector/config/configauth v1.50.0 // indirect
	go.opentelemetry.io/collector/config/configcompression v1.50.0 // indirect
	go.opentelemetry.io/collector/config/confighttp v0.144.0 // indirect
	go.opentelemetry.io/collector/config/configmiddleware v1.50.0 // indirect
	go.opentelemetry.io/collector/config/confignet v1.50.0 // indirect
	go.opentelemetry.io/collector/config/configopaque v1.50.0 // indirect
	go.opentelemetry.io/collector/config/configoptional v1.50.0 // indirect
	go.opentelemetry.io/collector/config/configretry v1.50.0 // indirect
	go.opentelemetry.io/collector/config/configtls v1.50.0 // indirect
	go.opentelemetry.io/collector/connector/connectortest v0.144.0 // indirect
	go.opentelemetry.io/collector/connector/xconnector v0.144.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.144.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror/xconsumererror v0.144.0 // indirect
	go.opentelemetry.io/collector/consumer/consumertest v0.144.0 // indirect
	go.opentelemetry.io/collector/consumer/xconsumer v0.144.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterhelper v0.144.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterhelper/xexporterhelper v0.144.0 // indirect
	go.opentelemetry.io/collector/exporter/xexporter v0.144.0 // indirect
	go.opentelemetry.io/collector/extension/extensionauth v1.50.0 // indirect
	go.opentelemetry.io/collector/extension/extensioncapabilities v0.144.0 // indirect
	go.opentelemetry.io/collector/extension/extensionmiddleware v0.144.0 // indirect
	go.opentelemetry.io/collector/extension/xextension v0.144.0 // indirect
	go.opentelemetry.io/collector/internal/componentalias v0.144.0 // indirect
	go.opentelemetry.io/collector/internal/fanoutconsumer v0.144.0 // indirect
	go.opentelemetry.io/collector/internal/telemetry v0.144.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.144.0 // indirect
	go.opentelemetry.io/collector/pdata/testdata v0.144.0 // indirect
	go.opentelemetry.io/collector/pdata/xpdata v0.144.0 // indirect
	go.opentelemetry.io/collector/pipeline/xpipeline v0.144.0 // indirect
	go.opentelemetry.io/collector/processor/processortest v0.144.0 // indirect
	go.opentelemetry.io/collector/processor/xprocessor v0.144.0 // indirect
	go.opentelemetry.io/collector/receiver/receivertest v0.144.0 // indirect
	go.opentelemetry.io/collector/receiver/xreceiver v0.144.0 // indirect
	go.opentelemetry.io/collector/service/hostcapabilities v0.144.0 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.13.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.64.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.38.0 // indirect
	go.opentelemetry.io/ebpf-profiler v0.0.202601 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc v0.14.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.14.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.39.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.39.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.39.0 // indirect
	go.opentelemetry.io/otel/exporters/prometheus v0.60.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutlog v0.14.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutmetric v1.38.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.38.0 // indirect
	go.opentelemetry.io/otel/log v0.15.0 // indirect
	go.opentelemetry.io/otel/sdk/log v0.14.0 // indirect
	go.opentelemetry.io/otel/trace v1.39.0 // indirect
	go.opentelemetry.io/proto/otlp v1.9.0 // indirect
	go.uber.org/goleak v1.3.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.yaml.in/yaml/v2 v2.4.3 // indirect
	golang.org/x/oauth2 v0.34.0 // indirect
	golang.org/x/telemetry v0.0.0-20251203150158-8fff8a5912fc // indirect
	gonum.org/v1/gonum v0.17.0 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20251222181119-0a764e51fe1b // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251222181119-0a764e51fe1b // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	k8s.io/apiextensions-apiserver v0.34.2 // indirect
	k8s.io/apiserver v0.34.2 // indirect
	k8s.io/component-base v0.34.2 // indirect
	k8s.io/kube-openapi v0.0.0-20250710124328-f3f2b991d03b // indirect
	k8s.io/kubectl v0.34.2 // indirect
	k8s.io/utils v0.0.0-20250604170112-4c0f3b243397 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.70 // indirect
	oras.land/oras-go/v2 v2.6.0 // indirect
	sigs.k8s.io/controller-runtime v0.20.4 // indirect
	sigs.k8s.io/json v0.0.0-20241014173422-cfa47c3a1cc8 // indirect
	sigs.k8s.io/randfill v1.0.0 // indirect
	sigs.k8s.io/structured-merge-diff/v6 v6.3.0 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

require (
	github.com/hashicorp/go-version v1.8.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect; indirecthttps://github.com/elastic/ingest-dev/issues/3253
	k8s.io/klog/v2 v2.130.1 // indirect
)

replace (
	github.com/dop251/goja_nodejs => github.com/dop251/goja_nodejs v0.0.0-20171011081505-adff31b136e6
	// openshift removed all tags from their repo, use the pseudoversion from the release-3.9 branch HEAD
	// See https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/12d41f40b0d408b0167633d8095160d3343d46ac/go.mod#L38
	github.com/openshift/api v3.9.0+incompatible => github.com/openshift/api v0.0.0-20180801171038-322a19404e37
)

// Replace statements carried forward from Beats https://github.com/elastic/beats/blob/0678f4d96212ac968fc90596e60475ed2f3979e1/go.mod#L503
replace (
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/consumption/armconsumption => github.com/elastic/azure-sdk-for-go/sdk/resourcemanager/consumption/armconsumption v1.1.0-elastic
	github.com/apoydence/eachers => github.com/poy/eachers v0.0.0-20181020210610-23942921fe77 //indirect, see https://github.com/elastic/beats/pull/29780 for details.
	github.com/dop251/goja => github.com/elastic/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/fsnotify/fsevents => github.com/elastic/fsevents v0.0.0-20181029231046-e1d381a4d270
	github.com/fsnotify/fsnotify => github.com/elastic/fsnotify v1.6.1-0.20240920222514-49f82bdbc9e3
	github.com/google/gopacket => github.com/elastic/gopacket v1.1.20-0.20241002174017-e8c5fda595e6
	github.com/insomniacslk/dhcp => github.com/elastic/dhcp v0.0.0-20200227161230-57ec251c7eb3 // indirect
	github.com/meraki/dashboard-api-go/v3 => github.com/tommyers-elastic/dashboard-api-go/v3 v3.0.0-20250616163611-a325b49669a4
)

// Needed to prevent https://github.com/open-telemetry/opentelemetry-go/issues/7039
replace go.opentelemetry.io/otel/exporters/prometheus => go.opentelemetry.io/otel/exporters/prometheus v0.58.0

// The replaces below refer to the following branch: https://github.com/elastic/opentelemetry-collector-contrib/tree/v0144-healthcheck-patched
// They contain an additional patch created from the content of https://github.com/open-telemetry/opentelemetry-collector-contrib/pull/43744
// They should be removed after the above PR is merged and we upgrade to the respective otel contrib release.
replace github.com/open-telemetry/opentelemetry-collector-contrib/pkg/status => github.com/elastic/opentelemetry-collector-contrib/pkg/status v0.0.0-20260128133812-7296485a6185

tool golang.org/x/tools/cmd/deadcode
