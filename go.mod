module github.com/elastic/elastic-agent

go 1.19

require (
	github.com/Masterminds/semver v1.5.0
	github.com/Microsoft/go-winio v0.6.0
	github.com/antlr/antlr4/runtime/Go/antlr/v4 v4.0.0-20230321174746-8dcc6526cfb1
	github.com/billgraziano/dpapi v0.4.0
	github.com/blakesmith/ar v0.0.0-20150311145944-8bd4349a67f2
	github.com/cavaliercoder/go-rpm v0.0.0-20190131055624-7a9c54e3d83e
	github.com/coreos/go-systemd/v22 v22.3.3-0.20220203105225-a9a7ef127534
	github.com/docker/go-units v0.5.0
	github.com/dolmen-go/contextio v0.0.0-20200217195037-68fc5150bcd5
	github.com/elastic/e2e-testing v1.99.2-0.20221205111528-ade3c840d0c0
	github.com/elastic/elastic-agent-autodiscover v0.6.0
	github.com/elastic/elastic-agent-client/v7 v7.1.0
	github.com/elastic/elastic-agent-libs v0.3.8-0.20230512004837-d6a37d929cd6
	github.com/elastic/elastic-agent-system-metrics v0.6.0
	github.com/elastic/go-elasticsearch/v8 v8.0.0-20210317102009-a9d74cec0186
	github.com/elastic/go-licenser v0.4.0
	github.com/elastic/go-sysinfo v1.10.0
	github.com/elastic/go-ucfg v0.8.6
	github.com/gofrs/flock v0.8.1
	github.com/gofrs/uuid v4.2.0+incompatible
	github.com/google/go-cmp v0.5.9
	github.com/google/pprof v0.0.0-20230406165453-00490a63f317
	github.com/google/uuid v1.3.0
	github.com/gorilla/mux v1.8.0
	github.com/hashicorp/go-multierror v1.1.1
	github.com/hectane/go-acl v0.0.0-20190604041725-da78bae5fc95
	github.com/joeshaw/multierror v0.0.0-20140124173710-69b34d4ec901
	github.com/josephspurrier/goversioninfo v0.0.0-20190209210621-63e6d1acd3dd
	github.com/kardianos/service v1.2.1-0.20210728001519-a323c3813bc7
	github.com/magefile/mage v1.14.0
	github.com/mitchellh/gox v1.0.1
	github.com/mitchellh/hashstructure v1.1.0
	github.com/mitchellh/mapstructure v1.5.0
	github.com/oklog/ulid v1.3.1
	github.com/otiai10/copy v1.11.0
	github.com/pierrre/gotestcover v0.0.0-20160517101806-924dca7d15f0
	github.com/pkg/errors v0.9.1
	github.com/rs/zerolog v1.27.0
	github.com/shirou/gopsutil/v3 v3.21.12
	github.com/sirupsen/logrus v1.9.0
	github.com/spf13/cobra v1.3.0
	github.com/stretchr/testify v1.8.2
	github.com/tsg/go-daemon v0.0.0-20200207173439-e704b93fd89b
	go.elastic.co/apm/module/apmgorilla v1.15.0
	go.elastic.co/ecszap v1.0.1
	go.elastic.co/go-licence-detector v0.5.0
	go.uber.org/zap v1.21.0
	golang.org/x/crypto v0.5.0
	golang.org/x/lint v0.0.0-20210508222113-6edffad5e616
	golang.org/x/sync v0.1.0
	golang.org/x/sys v0.6.0
	golang.org/x/text v0.8.0
	golang.org/x/time v0.3.0
	golang.org/x/tools v0.7.0
	google.golang.org/grpc v1.46.0
	google.golang.org/protobuf v1.28.0
	gopkg.in/yaml.v2 v2.4.0
	gotest.tools v2.2.0+incompatible
	gotest.tools/gotestsum v1.7.0
	k8s.io/api v0.23.4
	k8s.io/apimachinery v0.23.4
	k8s.io/client-go v0.23.4
)

require (
	github.com/Jeffail/gabs/v2 v2.6.0 // indirect
	github.com/akavel/rsrc v0.8.0 // indirect
	github.com/armon/go-radix v1.0.0 // indirect
	github.com/cavaliercoder/badio v0.0.0-20160213150051-ce5280129e9e // indirect
	github.com/cenkalti/backoff/v4 v4.1.2 // indirect
	github.com/cyphar/filepath-securejoin v0.2.3 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dnephin/pflag v1.0.7 // indirect
	github.com/docker/distribution v2.8.1+incompatible // indirect
	github.com/docker/docker v20.10.24+incompatible // indirect
	github.com/docker/go-connections v0.4.0 // indirect
	github.com/elastic/go-structform v0.0.9 // indirect
	github.com/elastic/go-windows v1.0.1 // indirect
	github.com/elastic/gosigar v0.14.2 // indirect
	github.com/evanphx/json-patch v4.12.0+incompatible // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/go-logr/logr v1.2.3 // indirect
	github.com/go-ole/go-ole v1.2.6 // indirect
	github.com/gobuffalo/here v0.6.0 // indirect
	github.com/godbus/dbus/v5 v5.0.5 // indirect
	github.com/gogo/protobuf v1.3.2 // indirect
	github.com/golang/protobuf v1.5.3 // indirect
	github.com/google/gofuzz v1.1.0 // indirect
	github.com/google/licenseclassifier v0.0.0-20200402202327-879cb1424de0 // indirect
	github.com/google/shlex v0.0.0-20191202100458-e7afc7fbc510 // indirect
	github.com/googleapis/gnostic v0.5.5 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/imdario/mergo v0.3.12 // indirect
	github.com/inconshreveable/mousetrap v1.0.0 // indirect
	github.com/jcchavezs/porto v0.1.0 // indirect
	github.com/jonboulle/clockwork v0.2.2 // indirect
	github.com/karrick/godirwalk v1.15.8 // indirect
	github.com/kr/pretty v0.3.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/markbates/pkger v0.17.0 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/mitchellh/iochan v1.0.0 // indirect
	github.com/moby/spdystream v0.2.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/onsi/ginkgo v1.16.5 // indirect
	github.com/opencontainers/go-digest v1.0.0 // indirect
	github.com/opencontainers/image-spec v1.0.2 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/procfs v0.9.0 // indirect
	github.com/rogpeppe/go-internal v1.8.1 // indirect
	github.com/santhosh-tekuri/jsonschema v1.2.4 // indirect
	github.com/sergi/go-diff v1.1.0 // indirect
	github.com/shirou/gopsutil v3.21.11+incompatible // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/stretchr/objx v0.5.0 // indirect
	github.com/tklauser/go-sysconf v0.3.9 // indirect
	github.com/tklauser/numcpus v0.3.0 // indirect
	github.com/yusufpapurcu/wmi v1.2.2 // indirect
	go.elastic.co/apm/module/apmhttp v1.15.0 // indirect
	go.elastic.co/apm/module/apmhttp/v2 v2.0.0 // indirect
	go.elastic.co/apm/v2 v2.0.0 // indirect
	go.elastic.co/fastjson v1.1.0 // indirect
	go.uber.org/atomic v1.9.0 // indirect
	go.uber.org/multierr v1.8.0 // indirect
	golang.org/x/exp v0.0.0-20220722155223-a9213eeb770e // indirect
	golang.org/x/mod v0.9.0 // indirect
	golang.org/x/net v0.8.0 // indirect
	golang.org/x/oauth2 v0.0.0-20211104180415-d3ed0bb246c8 // indirect
	golang.org/x/term v0.6.0 // indirect
	google.golang.org/appengine v1.6.7 // indirect
	google.golang.org/genproto v0.0.0-20220426171045-31bebdecfb46 // indirect
	google.golang.org/grpc/examples v0.0.0-20220304170021-431ea809a767 // indirect
	gopkg.in/inf.v0 v0.9.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	howett.net/plist v1.0.0 // indirect
	k8s.io/kube-openapi v0.0.0-20211115234752-e816edb12b65 // indirect
	k8s.io/utils v0.0.0-20211116205334-6203023598ed // indirect
	sigs.k8s.io/json v0.0.0-20211020170558-c049b76a60c6 // indirect
	sigs.k8s.io/structured-merge-diff/v4 v4.2.1 // indirect
	sigs.k8s.io/yaml v1.3.0 // indirect
)

require (
	github.com/hashicorp/go-version v1.2.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/onsi/gomega v1.27.3 // indirect
	go.elastic.co/apm v1.15.0
	go.elastic.co/apm/module/apmgrpc v1.15.0
	k8s.io/klog/v2 v2.30.0 // indirect
)

replace (
	github.com/Microsoft/go-winio => github.com/bi-zone/go-winio v0.4.15
	github.com/Shopify/sarama => github.com/elastic/sarama v1.19.1-0.20220310193331-ebc2b0d8eef3
	github.com/dop251/goja => github.com/andrewkroh/goja v0.0.0-20190128172624-dd2ac4456e20
	github.com/dop251/goja_nodejs => github.com/dop251/goja_nodejs v0.0.0-20171011081505-adff31b136e6
	github.com/fsnotify/fsnotify => github.com/adriansr/fsnotify v1.4.8-0.20211018144411-a81f2b630e7c
	github.com/tonistiigi/fifo => github.com/containerd/fifo v0.0.0-20190816180239-bda0ff6ed73c
)

// Exclude this version because the version has an invalid checksum.
exclude github.com/docker/distribution v2.8.0+incompatible
