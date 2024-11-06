module github.com/elastic/elastic-agent

go 1.22.8

require (
	github.com/Jeffail/gabs/v2 v2.6.0
	github.com/Microsoft/go-winio v0.6.2
	github.com/antlr4-go/antlr/v4 v4.13.0
	github.com/blakesmith/ar v0.0.0-20150311145944-8bd4349a67f2
	github.com/cavaliergopher/rpm v1.2.0
	github.com/cenkalti/backoff/v4 v4.3.0
	github.com/docker/docker v27.3.1+incompatible
	github.com/docker/go-units v0.5.0
	github.com/dolmen-go/contextio v0.0.0-20200217195037-68fc5150bcd5
	github.com/elastic/beats/v7 v7.0.0-alpha2.0.20241022170531-d2e6603d82fb
	github.com/elastic/elastic-agent-autodiscover v0.9.0
	github.com/elastic/elastic-agent-client/v7 v7.16.0
	github.com/elastic/elastic-agent-libs v0.17.0
	github.com/elastic/elastic-agent-system-metrics v0.11.3
	github.com/elastic/elastic-transport-go/v8 v8.6.0
	github.com/elastic/go-elasticsearch/v8 v8.15.0
	github.com/elastic/go-licenser v0.4.2
	github.com/elastic/go-sysinfo v1.15.0
	github.com/elastic/go-ucfg v0.8.8
	github.com/elastic/mock-es v0.0.0-20241101195702-0a41fa3d30d9
	github.com/elastic/opentelemetry-collector-components/connector/signaltometricsconnector v0.3.0
	github.com/elastic/opentelemetry-collector-components/processor/elasticinframetricsprocessor v0.13.0
	github.com/elastic/opentelemetry-collector-components/processor/elastictraceprocessor v0.3.0
	github.com/elastic/opentelemetry-collector-components/processor/lsmintervalprocessor v0.3.0
	github.com/fatih/color v1.17.0
	github.com/fsnotify/fsnotify v1.8.0
	github.com/go-viper/mapstructure/v2 v2.2.1
	github.com/gofrs/flock v0.12.1
	github.com/gofrs/uuid/v5 v5.2.0
	github.com/google/go-cmp v0.6.0
	github.com/google/pprof v0.0.0-20240727154555-813a5fbdbec8
	github.com/gorilla/mux v1.8.1
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95
	github.com/jaypipes/ghw v0.12.0
	github.com/jedib0t/go-pretty/v6 v6.4.6
	github.com/josephspurrier/goversioninfo v1.4.0
	github.com/kardianos/service v1.2.1-0.20210728001519-a323c3813bc7
	github.com/magefile/mage v1.15.0
	github.com/oklog/ulid/v2 v2.1.0
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/healthcheckextension v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/pprofextension v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/jaegerreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/prometheusreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/zipkinreceiver v0.113.0
	github.com/otiai10/copy v1.14.0
	github.com/rednafi/link-patrol v0.0.0-20240826150821-057643e74d4d
	github.com/rs/zerolog v1.27.0
	github.com/sajari/regression v1.0.1
	github.com/schollz/progressbar/v3 v3.13.1
	github.com/spf13/cobra v1.8.1
	github.com/spf13/pflag v1.0.5
	github.com/stretchr/testify v1.9.0
	github.com/tsg/go-daemon v0.0.0-20200207173439-e704b93fd89b
	github.com/winlabs/gowin32 v0.0.0-20240930213947-f504d7e14639
	go.elastic.co/apm/module/apmgorilla/v2 v2.6.0
	go.elastic.co/apm/module/apmgrpc/v2 v2.6.0
	go.elastic.co/apm/v2 v2.6.0
	go.elastic.co/ecszap v1.0.2
	go.elastic.co/go-licence-detector v0.7.0
	go.opentelemetry.io/collector/processor/memorylimiterprocessor v0.113.0
	go.uber.org/zap v1.27.0
	golang.org/x/crypto v0.28.0
	golang.org/x/exp v0.0.0-20240719175910-8a7402abbf56
	golang.org/x/sync v0.8.0
	golang.org/x/sys v0.26.0
	golang.org/x/term v0.25.0
	golang.org/x/text v0.19.0
	golang.org/x/time v0.6.0
	golang.org/x/tools v0.25.0
	google.golang.org/api v0.199.0
	google.golang.org/grpc v1.67.1
	google.golang.org/protobuf v1.35.1
	gopkg.in/ini.v1 v1.67.0
	gopkg.in/yaml.v2 v2.4.0
	gopkg.in/yaml.v3 v3.0.1
	gotest.tools/gotestsum v1.9.0
	helm.sh/helm/v3 v3.15.4
	k8s.io/api v0.31.2
	k8s.io/apimachinery v0.31.2
	k8s.io/client-go v0.31.2
	kernel.org/pub/linux/libs/security/libcap/cap v1.2.70
	sigs.k8s.io/e2e-framework v0.4.0
	sigs.k8s.io/kustomize/api v0.13.5-0.20230601165947-6ce0bf390ce3
	sigs.k8s.io/kustomize/kyaml v0.14.3-0.20230601165947-6ce0bf390ce3
)

require (
	github.com/distribution/reference v0.6.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/connector/spanmetricsconnector v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/elasticsearchexporter v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/exporter/fileexporter v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/extension/storage/filestorage v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/attributesprocessor v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/filterprocessor v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/k8sattributesprocessor v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourcedetectionprocessor v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/resourceprocessor v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/processor/transformprocessor v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/filelogreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/hostmetricsreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/httpcheckreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sclusterreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/k8sobjectsreceiver v0.113.0
	github.com/open-telemetry/opentelemetry-collector-contrib/receiver/kubeletstatsreceiver v0.113.0
	go.opentelemetry.io/collector/component v0.113.0
	go.opentelemetry.io/collector/confmap v1.19.0
	go.opentelemetry.io/collector/confmap/converter/expandconverter v0.113.0
	go.opentelemetry.io/collector/confmap/provider/envprovider v1.19.0
	go.opentelemetry.io/collector/confmap/provider/fileprovider v1.19.0
	go.opentelemetry.io/collector/confmap/provider/httpprovider v1.19.0
	go.opentelemetry.io/collector/confmap/provider/httpsprovider v1.19.0
	go.opentelemetry.io/collector/confmap/provider/yamlprovider v1.19.0
	go.opentelemetry.io/collector/connector v0.113.0
	go.opentelemetry.io/collector/exporter v0.113.0
	go.opentelemetry.io/collector/exporter/debugexporter v0.113.0
	go.opentelemetry.io/collector/exporter/otlpexporter v0.113.0
	go.opentelemetry.io/collector/exporter/otlphttpexporter v0.113.0
	go.opentelemetry.io/collector/extension v0.113.0
	go.opentelemetry.io/collector/extension/memorylimiterextension v0.113.0
	go.opentelemetry.io/collector/featuregate v1.19.0
	go.opentelemetry.io/collector/otelcol v0.113.0
	go.opentelemetry.io/collector/processor v0.113.0
	go.opentelemetry.io/collector/processor/batchprocessor v0.113.0
	go.opentelemetry.io/collector/receiver v0.113.0
	go.opentelemetry.io/collector/receiver/otlpreceiver v0.113.0
)

require (
	aqwari.net/xml v0.0.0-20210331023308-d9421b293817 // indirect
	cloud.google.com/go v0.115.1 // indirect
	cloud.google.com/go/auth v0.9.5 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.4 // indirect
	cloud.google.com/go/compute/metadata v0.5.2 // indirect
	cloud.google.com/go/iam v1.2.0 // indirect
	cloud.google.com/go/pubsub v1.42.0 // indirect
	cloud.google.com/go/storage v1.43.0 // indirect
	code.cloudfoundry.org/go-diodes v0.0.0-20190809170250-f77fb823c7ee // indirect
	code.cloudfoundry.org/go-loggregator v7.4.0+incompatible // indirect
	code.cloudfoundry.org/gofileutils v0.0.0-20170111115228-4d0c80011a0f // indirect
	code.cloudfoundry.org/rfc5424 v0.0.0-20180905210152-236a6d29298a // indirect
	github.com/AdaLogics/go-fuzz-headers v0.0.0-20230811130428-ced1acdcaa24 // indirect
	github.com/Azure/azure-amqp-common-go/v4 v4.2.0 // indirect
	github.com/Azure/azure-event-hubs-go/v3 v3.6.1 // indirect
	github.com/Azure/azure-pipeline-go v0.2.3 // indirect
	github.com/Azure/azure-sdk-for-go v65.0.0+incompatible // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.14.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/messaging/azeventhubs v1.2.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/compute/armcompute/v5 v5.7.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/containerservice/armcontainerservice/v4 v4.6.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/network/armnetwork/v4 v4.3.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/storage/azblob v1.4.0 // indirect
	github.com/Azure/azure-storage-blob-go v0.15.0 // indirect
	github.com/Azure/go-amqp v1.0.5 // indirect
	github.com/Azure/go-ansiterm v0.0.0-20230124172434-306776ec8161 // indirect
	github.com/Azure/go-autorest v14.2.0+incompatible // indirect
	github.com/Azure/go-autorest/autorest v0.11.29 // indirect
	github.com/Azure/go-autorest/autorest/adal v0.9.24 // indirect
	github.com/Azure/go-autorest/autorest/date v0.3.0 // indirect
	github.com/Azure/go-autorest/autorest/to v0.4.0 // indirect
	github.com/Azure/go-autorest/autorest/validation v0.3.1 // indirect
	github.com/Azure/go-autorest/logger v0.2.1 // indirect
	github.com/Azure/go-autorest/tracing v0.6.0 // indirect
	github.com/Azure/go-ntlmssp v0.0.0-20221128193559-754e69321358 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.2.2 // indirect
	github.com/BurntSushi/toml v1.4.1-0.20240526193622-a339e1f7089c // indirect
	github.com/Code-Hex/go-generics-cache v1.5.1 // indirect
	github.com/DataDog/zstd v1.4.5 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/detectors/gcp v1.25.0 // indirect
	github.com/JohnCGriffin/overflow v0.0.0-20211019200055-46fa312c352c // indirect
	github.com/MakeNowJust/heredoc v1.0.0 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver v1.5.0 // indirect
	github.com/Masterminds/semver/v3 v3.2.1 // indirect
	github.com/Masterminds/sprig/v3 v3.2.3 // indirect
	github.com/Masterminds/squirrel v1.5.4 // indirect
	github.com/Microsoft/hcsshim v0.12.5 // indirect
	github.com/PaesslerAG/gval v1.2.2 // indirect
	github.com/PaesslerAG/jsonpath v0.1.1 // indirect
	github.com/Shopify/sarama v1.37.2 // indirect
	github.com/Showmax/go-fqdn v1.0.0 // indirect
	github.com/StackExchange/wmi v1.2.1 // indirect
	github.com/akavel/rsrc v0.10.2 // indirect
	github.com/alecthomas/participle/v2 v2.1.1 // indirect
	github.com/alecthomas/units v0.0.0-20240626203959-61d1e3462e30 // indirect
	github.com/andybalholm/brotli v1.0.5 // indirect
	github.com/antchfx/xmlquery v1.4.2 // indirect
	github.com/antchfx/xpath v1.3.2 // indirect
	github.com/apache/arrow/go/v14 v14.0.2 // indirect
	github.com/apache/thrift v0.21.0 // indirect
	github.com/armon/go-metrics v0.4.1 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/asaskevich/govalidator v0.0.0-20230301143203-a9d515a09cc2 // indirect
	github.com/aws/aws-sdk-go v1.55.5 // indirect
	github.com/aws/aws-sdk-go-v2 v1.30.4 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.6.4 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.27.29 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.29 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.12 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.16 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.16 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.1 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.3.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.37.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.176.0 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.11.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.3.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.11.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.17.16 // indirect
	github.com/aws/aws-sdk-go-v2/service/s3 v1.60.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sqs v1.34.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.22.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.26.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.30.5 // indirect
	github.com/aws/smithy-go v1.20.4 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bmatcuk/doublestar/v4 v4.7.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chai2010/gettext-go v1.0.2 // indirect
	github.com/cloudfoundry-community/go-cfclient v0.0.0-20190808214049-35bcce23fc5f // indirect
	github.com/cloudfoundry/noaa v2.1.0+incompatible // indirect
	github.com/cloudfoundry/sonde-go v0.0.0-20171206171820-b33733203bb4 // indirect
	github.com/cncf/xds/go v0.0.0-20240723142845-024c85f92f20 // indirect
	github.com/cockroachdb/errors v1.11.3 // indirect
	github.com/cockroachdb/fifo v0.0.0-20240606204812-0bbfbd93a7ce // indirect
	github.com/cockroachdb/logtags v0.0.0-20230118201751-21c54148d20b // indirect
	github.com/cockroachdb/pebble v1.1.2 // indirect
	github.com/cockroachdb/redact v1.1.5 // indirect
	github.com/cockroachdb/tokenbucket v0.0.0-20230807174530-cc333fc44b06 // indirect
	github.com/containerd/containerd v1.7.18 // indirect
	github.com/containerd/errdefs v0.1.0 // indirect
	github.com/containerd/log v0.1.0 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.4 // indirect
	github.com/cyphar/filepath-securejoin v0.2.5 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/dennwc/varint v1.0.0 // indirect
	github.com/devigned/tab v0.1.2-0.20190607222403-0c15cf42f9a2 // indirect
	github.com/dgraph-io/badger/v4 v4.3.0 // indirect
	github.com/dgraph-io/ristretto v0.1.2-0.20240116140435-c67e07994f91 // indirect
	github.com/digitalocean/godo v1.122.0 // indirect
	github.com/dlclark/regexp2 v1.4.0 // indirect
	github.com/dnephin/pflag v1.0.7 // indirect
	github.com/docker/cli v25.0.1+incompatible // indirect
	github.com/docker/distribution v2.8.3+incompatible // indirect
	github.com/docker/docker-credential-helpers v0.7.0 // indirect
	github.com/docker/go-connections v0.5.0 // indirect
	github.com/docker/go-metrics v0.0.1 // indirect
	github.com/dop251/goja v0.0.0-20200831102558-9af81ddcf0e1 // indirect
	github.com/dop251/goja_nodejs v0.0.0-20171011081505-adff31b136e6 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/eapache/go-resiliency v1.7.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20230731223053-c322873962e3 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/ebitengine/purego v0.8.1 // indirect
	github.com/eclipse/paho.mqtt.golang v1.3.5 // indirect
	github.com/elastic/bayeux v1.0.5 // indirect
	github.com/elastic/go-concert v0.3.0 // indirect
	github.com/elastic/go-docappender/v2 v2.3.0 // indirect
	github.com/elastic/go-elasticsearch/v7 v7.17.10 // indirect
	github.com/elastic/go-grok v0.3.1 // indirect
	github.com/elastic/go-lumber v0.1.2-0.20220819171948-335fde24ea0f // indirect
	github.com/elastic/go-seccomp-bpf v1.4.0 // indirect
	github.com/elastic/go-sfdc v0.0.0-20241010131323-8e176480d727 // indirect
	github.com/elastic/go-structform v0.0.12 // indirect
	github.com/elastic/go-windows v1.0.2 // indirect
	github.com/elastic/gosigar v0.14.3 // indirect
	github.com/elastic/lunes v0.1.0 // indirect
	github.com/elastic/mito v1.15.0 // indirect
	github.com/elastic/opentelemetry-lib v0.13.0 // indirect
	github.com/elastic/pkcs8 v1.0.0 // indirect
	github.com/emicklei/go-restful/v3 v3.11.0 // indirect
	github.com/envoyproxy/go-control-plane v0.13.0 // indirect
	github.com/envoyproxy/protoc-gen-validate v1.1.0 // indirect
	github.com/evanphx/json-patch v5.7.0+incompatible // indirect
	github.com/evanphx/json-patch/v5 v5.9.0 // indirect
	github.com/exponent-io/jsonpath v0.0.0-20151013193312-d6023ce2651d // indirect
	github.com/expr-lang/expr v1.16.9 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/fxamacker/cbor/v2 v2.7.0 // indirect
	github.com/getsentry/sentry-go v0.27.0 // indirect
	github.com/ghodss/yaml v1.0.0 // indirect
	github.com/go-asn1-ber/asn1-ber v1.5.5 // indirect
	github.com/go-errors/errors v1.4.2 // indirect
	github.com/go-gorp/gorp/v3 v3.1.0 // indirect
	github.com/go-kit/log v0.2.1 // indirect
	github.com/go-ldap/ldap/v3 v3.4.6 // indirect
	github.com/go-logfmt/logfmt v0.6.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-openapi/jsonpointer v0.20.2 // indirect
	github.com/go-openapi/jsonreference v0.20.4 // indirect
	github.com/go-openapi/swag v0.22.9 // indirect
	github.com/go-resty/resty/v2 v2.13.1 // indirect
	github.com/go-sourcemap/sourcemap v2.1.2+incompatible // indirect
	github.com/go-zookeeper/zk v1.0.3 // indirect
	github.com/gobwas/glob v0.2.3 // indirect
	github.com/goccy/go-json v0.10.3 // indirect
	github.com/gogo/googleapis v1.4.1 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang-jwt/jwt/v4 v4.5.0 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v0.0.4 // indirect
	github.com/gomodule/redigo v1.8.3 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/cel-go v0.20.1 // indirect
	github.com/google/flatbuffers v23.5.26+incompatible // indirect
	github.com/google/gnostic-models v0.6.9-0.20230804172637-c7be7c783f49 // indirect
	github.com/google/go-querystring v1.1.0 // indirect
	github.com/google/gofuzz v1.2.0 // indirect
	github.com/google/licenseclassifier v0.0.0-20221004142553-c1ed8fcf4bab // indirect
	github.com/google/s2a-go v0.1.8 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.4 // indirect
	github.com/googleapis/gax-go/v2 v2.13.0 // indirect
	github.com/gophercloud/gophercloud v1.14.0 // indirect
	github.com/gorilla/handlers v1.5.2 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/gosuri/uitable v0.0.4 // indirect
	github.com/grafana/regexp v0.0.0-20240518133315-a468a5bfb3bc // indirect
	github.com/gregjones/httpcache v0.0.0-20180305231024-9cad4c3443a7 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.22.0 // indirect
	github.com/h2non/filetype v1.1.1 // indirect
	github.com/hashicorp/consul/api v1.30.0 // indirect
	github.com/hashicorp/cronexpr v1.1.2 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/golang-lru v1.0.2 // indirect
	github.com/hashicorp/golang-lru/v2 v2.0.7 // indirect
	github.com/hashicorp/nomad/api v0.0.0-20240717122358-3d93bd3778f3 // indirect
	github.com/hashicorp/serf v0.10.1 // indirect
	github.com/hetznercloud/hcloud-go/v2 v2.13.1 // indirect
	github.com/huandu/xstrings v1.4.0 // indirect
	github.com/iancoleman/strcase v0.3.0 // indirect
	github.com/icholy/digest v0.1.22 // indirect
	github.com/imdario/mergo v0.3.16 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/ionos-cloud/sdk-go/v6 v6.2.1 // indirect
	github.com/jaegertracing/jaeger v1.62.0 // indirect
	github.com/jaypipes/pcidb v1.0.0 // indirect
	github.com/jcmturner/aescts/v2 v2.0.0 // indirect
	github.com/jcmturner/dnsutils/v2 v2.0.0 // indirect
	github.com/jcmturner/gofork v1.7.6 // indirect
	github.com/jcmturner/gokrb5/v8 v8.4.4 // indirect
	github.com/jcmturner/rpc/v2 v2.0.3 // indirect
	github.com/jmespath/go-jmespath v0.4.0 // indirect
	github.com/jmoiron/sqlx v1.3.5 // indirect
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901 // indirect
	github.com/jonboulle/clockwork v0.4.0 // indirect
	github.com/josharian/intern v1.0.0 // indirect
	github.com/jpillora/backoff v1.0.0 // indirect
	github.com/karrick/godirwalk v1.17.0 // indirect
	github.com/klauspost/asmfmt v1.3.2 // indirect
	github.com/klauspost/compress v1.17.11 // indirect
	github.com/klauspost/cpuid/v2 v2.2.5 // indirect
	github.com/knadh/koanf/maps v0.1.1 // indirect
	github.com/knadh/koanf/providers/confmap v0.1.0 // indirect
	github.com/knadh/koanf/v2 v2.1.1 // indirect
	github.com/kolo/xmlrpc v0.0.0-20220921171641-a4b6fa1dd06b // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lann/builder v0.0.0-20180802200727-47ae307949d0 // indirect
	github.com/lann/ps v0.0.0-20150810152359-62de8c46ede0 // indirect
	github.com/leodido/go-syslog/v4 v4.2.0 // indirect
	github.com/leodido/ragel-machinery v0.0.0-20190525184631-5f46317e436b // indirect
	github.com/lestrrat-go/strftime v1.1.0 // indirect
	github.com/lib/pq v1.10.9 // indirect
	github.com/liggitt/tabwriter v0.0.0-20181228230101-89fcab3d43de // indirect
	github.com/lightstep/go-expohisto v1.0.0 // indirect
	github.com/linode/linodego v1.40.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20220913051719-115f729f3c8c // indirect
	github.com/mailru/easyjson v0.7.7 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-ieproxy v0.0.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mattn/go-runewidth v0.0.15 // indirect
	github.com/miekg/dns v1.1.62 // indirect
	github.com/mileusna/useragent v1.3.4 // indirect
	github.com/minio/asm2plan9s v0.0.0-20200509001527-cdd76441f9d8 // indirect
	github.com/minio/c2goasm v0.0.0-20190812172519-36a3d3bbc4f3 // indirect
	github.com/mitchellh/colorstring v0.0.0-20190213212951-d06e56a500db // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/go-wordwrap v1.0.1 // indirect
	github.com/mitchellh/hashstructure v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.1-0.20231216201459-8508981c8b6c // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/moby/docker-image-spec v1.3.1 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/spdystream v0.4.0 // indirect
	github.com/moby/term v0.5.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/monochromegane/go-gitignore v0.0.0-20200626010858-205db1a8cc00 // indirect
	github.com/mostynb/go-grpc-compression v1.2.3 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/mwitkow/go-conntrack v0.0.0-20190716064945-2f068394615f // indirect
	github.com/mxk/go-flowrate v0.0.0-20140419014527-cca7078d478f // indirect
	github.com/nxadm/tail v1.4.11 // indirect
	github.com/onsi/ginkgo/v2 v2.20.0 // indirect
	github.com/onsi/gomega v1.34.1 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/aws/ecsutil v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/common v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/coreinternal v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/filter v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/k8sconfig v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/kubelet v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/metadataproviders v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/pdatautil v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/internal/sharedcomponent v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/experimentalmetricmetadata v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/ottl v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatautil v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/sampling v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/stanza v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/jaeger v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/prometheus v0.113.0 // indirect
	github.com/open-telemetry/opentelemetry-collector-contrib/pkg/translator/zipkin v0.113.0 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.1.0 // indirect
	github.com/openshift/api v3.9.0+incompatible // indirect
	github.com/openshift/client-go v0.0.0-20210521082421-73d9475a9142 // indirect
	github.com/openzipkin/zipkin-go v0.4.3 // indirect
	github.com/ovh/go-ovh v1.6.0 // indirect
	github.com/peterbourgon/diskv v2.0.1+incompatible // indirect
	github.com/pierrec/lz4 v2.6.1+incompatible // indirect
	github.com/pierrec/lz4/v4 v4.1.21 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/planetscale/vtprotobuf v0.6.1-0.20240319094008-0393e58bdf10 // indirect
	github.com/pmezard/go-difflib v1.0.1-0.20181226105442-5d4384ee4fb2 // indirect
	github.com/power-devops/perfstat v0.0.0-20220216144756-c35f1ee13d7c // indirect
	github.com/prometheus-community/windows_exporter v0.27.2 // indirect
	github.com/prometheus/client_golang v1.20.5 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.60.1 // indirect
	github.com/prometheus/common/sigv4 v0.1.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/prometheus/prometheus v0.54.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20201227073835-cf1acfcdf475 // indirect
	github.com/rivo/uniseg v0.4.4 // indirect
	github.com/rogpeppe/go-internal v1.13.1 // indirect
	github.com/rs/cors v1.11.1 // indirect
	github.com/rubenv/sql-migrate v1.5.2 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/scaleway/scaleway-sdk-go v1.0.0-beta.30 // indirect
	github.com/sergi/go-diff v1.3.1 // indirect
	github.com/shirou/gopsutil/v3 v3.24.5 // indirect
	github.com/shirou/gopsutil/v4 v4.24.10 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/shopspring/decimal v1.3.1 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	github.com/spf13/cast v1.6.0 // indirect
	github.com/stoewer/go-strcase v1.2.0 // indirect
	github.com/stretchr/objx v0.5.2 // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/ua-parser/uap-go v0.0.0-20240611065828-3a4781585db6 // indirect
	github.com/ugorji/go/codec v1.2.7 // indirect
	github.com/urfave/cli/v2 v2.27.4 // indirect
	github.com/valyala/fastjson v1.6.4 // indirect
	github.com/vultr/govultr/v2 v2.17.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xdg-go/pbkdf2 v1.0.0 // indirect
	github.com/xdg-go/scram v1.1.2 // indirect
	github.com/xdg-go/stringprep v1.0.4 // indirect
	github.com/xeipuuv/gojsonpointer v0.0.0-20190905194746-02993c407bfb // indirect
	github.com/xeipuuv/gojsonreference v0.0.0-20180127040603-bd5ef7bd5415 // indirect
	github.com/xeipuuv/gojsonschema v1.2.0 // indirect
	github.com/xlab/treeprint v1.2.0 // indirect
	github.com/xrash/smetrics v0.0.0-20240521201337-686a1a2994c1 // indirect
	github.com/yuin/goldmark v1.7.4 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	github.com/zeebo/xxh3 v1.0.2 // indirect
	github.com/zyedidia/generic v1.2.1 // indirect
	go.elastic.co/apm/module/apmelasticsearch/v2 v2.6.0 // indirect
	go.elastic.co/apm/module/apmhttp/v2 v2.6.0 // indirect
	go.elastic.co/apm/module/apmzap/v2 v2.6.0 // indirect
	go.elastic.co/fastjson v1.3.0 // indirect
	go.etcd.io/bbolt v1.3.11 // indirect
	go.opencensus.io v0.24.0 // indirect
	go.opentelemetry.io/collector v0.113.0 // indirect
	go.opentelemetry.io/collector/client v1.19.0 // indirect
	go.opentelemetry.io/collector/component/componentstatus v0.113.0 // indirect
	go.opentelemetry.io/collector/config/configauth v0.113.0 // indirect
	go.opentelemetry.io/collector/config/configcompression v1.19.0 // indirect
	go.opentelemetry.io/collector/config/configgrpc v0.113.0 // indirect
	go.opentelemetry.io/collector/config/confighttp v0.113.0 // indirect
	go.opentelemetry.io/collector/config/confignet v1.19.0 // indirect
	go.opentelemetry.io/collector/config/configopaque v1.19.0 // indirect
	go.opentelemetry.io/collector/config/configretry v1.19.0 // indirect
	go.opentelemetry.io/collector/config/configtelemetry v0.113.0 // indirect
	go.opentelemetry.io/collector/config/configtls v1.19.0 // indirect
	go.opentelemetry.io/collector/config/internal v0.113.0 // indirect
	go.opentelemetry.io/collector/connector/connectorprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/connector/connectortest v0.113.0 // indirect
	go.opentelemetry.io/collector/consumer v0.113.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror v0.113.0 // indirect
	go.opentelemetry.io/collector/consumer/consumererror/consumererrorprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/consumer/consumerprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/consumer/consumertest v0.113.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterhelper/exporterhelperprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/exporter/exporterprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/exporter/exportertest v0.113.0 // indirect
	go.opentelemetry.io/collector/extension/auth v0.113.0 // indirect
	go.opentelemetry.io/collector/extension/experimental/storage v0.113.0 // indirect
	go.opentelemetry.io/collector/extension/extensioncapabilities v0.113.0 // indirect
	go.opentelemetry.io/collector/filter v0.113.0 // indirect
	go.opentelemetry.io/collector/internal/fanoutconsumer v0.113.0 // indirect
	go.opentelemetry.io/collector/internal/memorylimiter v0.113.0 // indirect
	go.opentelemetry.io/collector/internal/sharedcomponent v0.113.0 // indirect
	go.opentelemetry.io/collector/pdata v1.19.0 // indirect
	go.opentelemetry.io/collector/pdata/pprofile v0.113.0 // indirect
	go.opentelemetry.io/collector/pdata/testdata v0.113.0 // indirect
	go.opentelemetry.io/collector/pipeline v0.113.0 // indirect
	go.opentelemetry.io/collector/pipeline/pipelineprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/processor/processorprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/processor/processortest v0.113.0 // indirect
	go.opentelemetry.io/collector/receiver/receiverprofiles v0.113.0 // indirect
	go.opentelemetry.io/collector/receiver/receivertest v0.113.0 // indirect
	go.opentelemetry.io/collector/semconv v0.113.0 // indirect
	go.opentelemetry.io/collector/service v0.113.0 // indirect
	go.opentelemetry.io/contrib/bridges/otelzap v0.6.0 // indirect
	go.opentelemetry.io/contrib/config v0.10.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.56.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.56.0 // indirect
	go.opentelemetry.io/contrib/propagators/b3 v1.31.0 // indirect
	go.opentelemetry.io/otel v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp v0.7.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/prometheus v0.53.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutlog v0.7.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdoutmetric v1.31.0 // indirect
	go.opentelemetry.io/otel/exporters/stdout/stdouttrace v1.31.0 // indirect
	go.opentelemetry.io/otel/log v0.7.0 // indirect
	go.opentelemetry.io/otel/metric v1.31.0 // indirect
	go.opentelemetry.io/otel/sdk v1.31.0 // indirect
	go.opentelemetry.io/otel/sdk/log v0.7.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.31.0 // indirect
	go.opentelemetry.io/otel/trace v1.31.0 // indirect
	go.opentelemetry.io/proto/otlp v1.3.1 // indirect
	go.starlark.net v0.0.0-20230525235612-a134d8f9ddca // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	golang.org/x/mod v0.21.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/oauth2 v0.23.0 // indirect
	golang.org/x/xerrors v0.0.0-20231012003039-104605ab7028 // indirect
	gonum.org/v1/gonum v0.15.1 // indirect
	google.golang.org/genproto v0.0.0-20240903143218-8af14fe29dc1 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20241007155032-5fefd90f89a9 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20241007155032-5fefd90f89a9 // indirect
	gopkg.in/evanphx/json-patch.v4 v4.12.0 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/jcmturner/aescts.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/dnsutils.v1 v1.0.1 // indirect
	gopkg.in/jcmturner/goidentity.v3 v3.0.0 // indirect
	gopkg.in/jcmturner/gokrb5.v7 v7.5.0 // indirect
	gopkg.in/jcmturner/rpc.v1 v1.1.0 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	howett.net/plist v1.0.1 // indirect
	k8s.io/apiextensions-apiserver v0.30.3 // indirect
	k8s.io/apiserver v0.31.2 // indirect
	k8s.io/cli-runtime v0.30.3 // indirect
	k8s.io/component-base v0.31.2 // indirect
	k8s.io/kube-openapi v0.0.0-20240228011516-70dd3763d340 // indirect
	k8s.io/kubectl v0.30.3 // indirect
	k8s.io/kubelet v0.31.2 // indirect
	k8s.io/utils v0.0.0-20240711033017-18e509b52bc8 // indirect
	kernel.org/pub/linux/libs/security/libcap/psx v1.2.70 // indirect
	oras.land/oras-go v1.2.5 // indirect
	sigs.k8s.io/controller-runtime v0.18.2 // indirect
	sigs.k8s.io/json v0.0.0-20221116044647-bc3834ca7abd // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.4.1 // indirect
	sigs.k8s.io/yaml v1.4.0 // indirect
)

require (
	github.com/hashicorp/go-version v1.7.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect; indirecthttps://github.com/elastic/ingest-dev/issues/3253
	k8s.io/klog/v2 v2.130.1 // indirect
)

replace (
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20220310193331-ebc2b0d8eef3
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	// fsnotify and goja are required for beats import
	github.com/fsnotify/fsnotify => github.com/elastic/fsnotify v1.6.1-0.20240920222514-49f82bdbc9e3
	// openshift removed all tags from their repo, use the pseudoversion from the release-3.9 branch HEAD
	// See https://github.com/open-telemetry/opentelemetry-collector-contrib/blob/12d41f40b0d408b0167633d8095160d3343d46ac/go.mod#L38
	github.com/openshift/api v3.9.0+incompatible => github.com/openshift/api v0.0.0-20180801171038-322a19404e37
)
