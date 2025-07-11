module github.com/smallstep/certificates

go 1.24

toolchain go1.24.2

require (
	cloud.google.com/go/longrunning v0.6.7
	cloud.google.com/go/security v1.18.5
	github.com/Masterminds/sprig/v3 v3.3.0
	github.com/ThalesIgnite/crypto11 v1.2.5 // indirect
	github.com/ccoveille/go-safecast v1.6.1
	github.com/coreos/go-oidc/v3 v3.14.1
	github.com/dgraph-io/badger v1.6.2
	github.com/dgraph-io/badger/v2 v2.2007.4
	github.com/dgraph-io/ristretto v0.2.0 // indirect
	github.com/fxamacker/cbor/v2 v2.8.0
	github.com/go-chi/chi/v5 v5.2.1
	github.com/go-jose/go-jose/v3 v3.0.4
	github.com/google/go-cmp v0.7.0
	github.com/google/go-tpm v0.9.5
	github.com/google/uuid v1.6.0
	github.com/googleapis/gax-go/v2 v2.14.2
	github.com/hashicorp/vault/api v1.16.0
	github.com/hashicorp/vault/api/auth/approle v0.9.0
	github.com/hashicorp/vault/api/auth/aws v0.9.0
	github.com/hashicorp/vault/api/auth/kubernetes v0.9.0
	github.com/hm-edu/portal-apis v0.0.0-20250102083103-f7750f2a7776
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/newrelic/go-agent/v3 v3.39.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/client_golang v1.22.0
	github.com/rs/xid v1.6.0
	github.com/sirupsen/logrus v1.9.3
	github.com/slackhq/nebula v1.9.5
	github.com/smallstep/assert v0.0.0-20200723003110-82e2b9b3b262
	github.com/smallstep/cli-utils v0.12.1
	github.com/smallstep/go-attestation v0.4.4-0.20240109183208-413678f90935
	github.com/smallstep/linkedca v0.23.0
	github.com/smallstep/nosql v0.7.0
	github.com/smallstep/pkcs7 v0.2.1
	github.com/smallstep/scep v0.0.0-20250318231241-a25cabb69492
	github.com/stretchr/testify v1.10.0
	github.com/urfave/cli v1.22.16
	go.step.sm/cli-utils v0.9.0
	go.step.sm/crypto v0.64.0
	go.uber.org/mock v0.5.2
	golang.org/x/crypto v0.38.0
	golang.org/x/exp v0.0.0-20250506013437-ce4c2cf36ca6
	golang.org/x/net v0.40.0
	google.golang.org/api v0.234.0
	google.golang.org/grpc v1.72.1
	google.golang.org/protobuf v1.36.6
)

require github.com/getsentry/sentry-go v0.33.0

require (
	cloud.google.com/go v0.121.2 // indirect
	cloud.google.com/go/auth v0.16.1 // indirect
	cloud.google.com/go/auth/oauth2adapt v0.2.8 // indirect
	cloud.google.com/go/compute/metadata v0.7.0 // indirect
	cloud.google.com/go/iam v1.5.2 // indirect
	cloud.google.com/go/kms v1.22.0 // indirect
	dario.cat/mergo v1.0.2 // indirect
	filippo.io/edwards25519 v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.61.0
	go.opentelemetry.io/otel v1.36.0 // indirect
)

require (
	github.com/AndreasBriese/bbloom v0.0.0-20190825152654-46b345b51c96 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azcore v1.18.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/azidentity v1.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/internal v1.11.1 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/azkeys v0.10.0 // indirect
	github.com/Azure/azure-sdk-for-go/sdk/keyvault/internal v0.7.1 // indirect
	github.com/AzureAD/microsoft-authentication-library-for-go v1.4.2 // indirect
	github.com/Masterminds/goutils v1.1.1 // indirect
	github.com/Masterminds/semver/v3 v3.3.1 // indirect
	github.com/aws/aws-sdk-go v1.55.7 // indirect
	github.com/aws/aws-sdk-go-v2 v1.36.3 // indirect
	github.com/aws/aws-sdk-go-v2/config v1.29.14 // indirect
	github.com/aws/aws-sdk-go-v2/credentials v1.17.67 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.16.30 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.3.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.6.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/ini v1.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.12.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.12.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/kms v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.25.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.30.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.33.19 // indirect
	github.com/aws/smithy-go v1.22.3 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cespare/xxhash v1.1.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/chzyer/readline v1.5.1 // indirect
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dgryski/go-farm v0.0.0-20240924180020-3414d57e47da // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.18.0 // indirect
	github.com/felixge/httpsnoop v1.0.4 // indirect
	github.com/go-jose/go-jose/v4 v4.1.0 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/go-piv/piv-go/v2 v2.3.0 // indirect
	github.com/go-sql-driver/mysql v1.9.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.2.2 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/golang/snappy v1.0.0 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/certificate-transparency-go v1.3.1 // indirect
	github.com/google/go-tpm-tools v0.4.5 // indirect
	github.com/google/go-tspi v0.3.0 // indirect
	github.com/google/s2a-go v0.1.9 // indirect
	github.com/googleapis/enterprise-certificate-proxy v0.3.6 // indirect
	github.com/hashicorp/errwrap v1.1.0 // indirect
	github.com/hashicorp/go-cleanhttp v0.5.2 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-multierror v1.1.1 // indirect
	github.com/hashicorp/go-retryablehttp v0.7.7 // indirect
	github.com/hashicorp/go-rootcerts v1.0.2 // indirect
	github.com/hashicorp/go-secure-stdlib/awsutil v0.3.0 // indirect
	github.com/hashicorp/go-secure-stdlib/parseutil v0.2.0 // indirect
	github.com/hashicorp/go-secure-stdlib/strutil v0.1.2 // indirect
	github.com/hashicorp/go-sockaddr v1.0.7 // indirect
	github.com/hashicorp/go-uuid v1.0.3 // indirect
	github.com/hashicorp/hcl v1.0.0 // indirect
	github.com/huandu/xstrings v1.5.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgconn v1.14.3 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgtype v1.14.4 // indirect
	github.com/jackc/pgx/v4 v4.18.3 // indirect
	github.com/jmespath/go-jmespath v0.4.1-0.20220621161143-b0104c826a24 // indirect
	github.com/klauspost/compress v1.18.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/manifoldco/promptui v0.9.0 // indirect
	github.com/mgutz/ansi v0.0.0-20200706080929-d51e80ef957d // indirect
	github.com/miekg/pkcs11 v1.1.1 // indirect
	github.com/mitchellh/copystructure v1.2.0 // indirect
	github.com/mitchellh/go-homedir v1.1.0 // indirect
	github.com/mitchellh/mapstructure v1.5.0 // indirect
	github.com/mitchellh/reflectwalk v1.0.2 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/peterbourgon/diskv/v3 v3.0.1 // indirect
	github.com/pkg/browser v0.0.0-20240102092130-5ac0b6a4141c // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.64.0 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/ryanuber/go-glob v1.0.0 // indirect
	github.com/schollz/jsonstore v1.1.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	github.com/shurcooL/sanitized_anchor_name v1.0.0 // indirect
	github.com/spf13/cast v1.8.0 // indirect
	github.com/thales-e-security/pool v0.0.2 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	go.etcd.io/bbolt v1.4.0 // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.61.0 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	go.opentelemetry.io/otel/trace v1.36.0 // indirect
	golang.org/x/mod v0.24.0 // indirect
	golang.org/x/oauth2 v0.30.0 // indirect
	golang.org/x/sync v0.14.0 // indirect
	golang.org/x/sys v0.33.0 // indirect
	golang.org/x/text v0.25.0 // indirect
	golang.org/x/time v0.11.0 // indirect
	golang.org/x/tools v0.33.0 // indirect
	google.golang.org/genproto v0.0.0-20250519155744-55703ea1f237 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20250519155744-55703ea1f237 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20250519155744-55703ea1f237 // indirect
	google.golang.org/grpc/cmd/protoc-gen-go-grpc v1.5.1 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/smallstep/nosql => github.com/hm-edu/nosql v0.4.1-0.20240506195746-2ea82a22279f

require (
	github.com/eclipse/paho.mqtt.golang v1.5.0
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/miekg/dns v1.1.66
)
