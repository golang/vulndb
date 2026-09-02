module golang.org/x/vulndb

go 1.26.0

// 'default=go1.26.2' is here because this module started already using godebug setting values
// from Go 1.26.2 in CL 763841, before the go directive was lowered to 1.25.0 in CL 771620, to
// avoid going back to 1.25 godebug setting values unnecessarily. It can be dropped after this
// module's go directive reaches 1.26.2 or higher.
godebug default=go1.26.2

// 'godebug default=go1.26.2' requires a go1.26.2 or newer to be used inside this module, else
// the go command fails with a "go: error loading go.mod: default=go1.26.2 too new" error. The
// toolchain directive here is used to make that requirement explicit. It will be dropped when
// this module's go directive reaches 1.26.2 or higher (by go mod tidy).
toolchain go1.26.2

require (
	cloud.google.com/go/errorreporting v0.4.0
	cloud.google.com/go/firestore v1.21.0
	cloud.google.com/go/secretmanager v1.16.0
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/metric v0.53.0
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/exporter/trace v1.21.0
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/propagator v0.45.0
	github.com/client9/misspell v0.3.4
	github.com/go-git/go-billy/v5 v5.9.1
	github.com/go-git/go-git/v5 v5.19.2
	github.com/google/generative-ai-go v0.5.0
	github.com/google/go-cmp v0.7.0
	github.com/google/go-github/v89 v89.0.0
	github.com/google/safehtml v0.1.0
	github.com/jba/metrics v0.1.1
	github.com/jba/metrics/otel v0.1.1
	github.com/jba/templatecheck v0.7.0
	github.com/lib/pq v1.10.9
	github.com/shurcooL/githubv4 v0.0.0-20231126234147-1cffa1f02456
	go.opentelemetry.io/otel v1.44.0
	go.opentelemetry.io/otel/sdk v1.44.0
	go.opentelemetry.io/otel/trace v1.44.0
	golang.org/x/exp v0.0.0-20260812173653-3d80eb74bc5b
	golang.org/x/mod v0.39.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.22.0
	golang.org/x/time v0.15.0
	golang.org/x/tools v0.49.0
	golang.org/x/tools/go/packages/packagestest v0.1.1-deprecated
	google.golang.org/api v0.290.0
	google.golang.org/grpc v1.83.1
	gopkg.in/yaml.v3 v3.0.1
	honnef.co/go/tools v0.4.6
	mvdan.cc/unparam v0.0.0-20230917202934-3ee2d22f45fb
)

require (
	cloud.google.com/go v0.123.0 // indirect
	cloud.google.com/go/ai v0.3.0 // indirect
	cloud.google.com/go/auth v0.20.0 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	cloud.google.com/go/iam v1.5.3 // indirect
	cloud.google.com/go/longrunning v0.8.0 // indirect
	cloud.google.com/go/monitoring v1.24.3 // indirect
	cloud.google.com/go/trace v1.11.7 // indirect
	dario.cat/mergo v1.0.2 // indirect
	github.com/BurntSushi/toml v1.3.2 // indirect
	github.com/GoogleCloudPlatform/opentelemetry-operations-go/internal/resourcemapping v0.53.0 // indirect
	github.com/Microsoft/go-winio v0.6.2 // indirect
	github.com/ProtonMail/go-crypto v1.4.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.5 // indirect
	github.com/cyphar/filepath-securejoin v0.7.0 // indirect
	github.com/emirpasic/gods v1.18.1 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-git/gcfg v1.5.1-0.20230307220236-3a3c6141e376 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/go-querystring v1.2.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.18 // indirect
	github.com/googleapis/gax-go/v2 v2.23.0 // indirect
	github.com/jbenet/go-context v0.0.0-20150711004518-d14ea06fba99 // indirect
	github.com/kevinburke/ssh_config v1.6.0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.0 // indirect
	github.com/pjbgf/sha1cd v0.6.0 // indirect
	github.com/sergi/go-diff v1.4.0 // indirect
	github.com/shurcooL/graphql v0.0.0-20200928012149-18c5c3165e3a // indirect
	github.com/skeema/knownhosts v1.3.2 // indirect
	github.com/xanzy/ssh-agent v0.3.3 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.67.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.67.0 // indirect
	go.opentelemetry.io/otel/metric v1.44.0 // indirect
	go.opentelemetry.io/otel/sdk/metric v1.44.0 // indirect
	golang.org/x/crypto v0.55.0 // indirect
	golang.org/x/exp/typeparams v0.0.0-20260812173653-3d80eb74bc5b // indirect
	golang.org/x/net v0.58.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/text v0.41.0 // indirect
	golang.org/x/tools/go/expect v0.1.1-deprecated // indirect
	google.golang.org/genproto v0.0.0-20260319201613-d00831a3d3e7 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260630182238-925bb5da69e7 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260727163830-6c54dddc4772 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	gopkg.in/warnings.v0 v0.1.2 // indirect
)
