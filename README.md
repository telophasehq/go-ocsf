<div align="center">
<img src="https://github.com/user-attachments/assets/c4217cad-018c-4550-8ac5-8958d5888c54" height= "auto" width="200" />
<br />
<h1>telophasehq/go-ocsf </h1>
<h3>
Convert data from any of your security tools to OCSF. Developed by <a href="https://telophase.dev">
Telophase</a>.
</h3>
<a href="https://github.com/telophasehq/go-ocsf/actions/workflows/ci.yml"><img src="https://github.com/telophasehq/go-ocsf/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
<a href="https://goreportcard.com/report/github.com/telophasehq/go-ocsf"><img src="https://goreportcard.com/badge/github.com/telophasehq/go-ocsf" alt="Go Report Card"></a>
<a href="https://pkg.go.dev/github.com/telophasehq/go-ocsf"><img src="https://pkg.go.dev/badge/github.com/telophasehq/go-ocsf.svg" alt="Go Reference"></a>
<a href="LICENSE"><img src="https://img.shields.io/github/license/telophasehq/go-ocsf" alt="License"></a>
</div>

`go-ocsf` is a Go library and CLI tool for converting security findings and events from your security tools (e.g., Snyk) into the [Open Cybersecurity Schema Framework (OCSF)](https://schema.ocsf.io/) format, with output options in JSON or Parquet formats. Data can be stored locally or seamlessly uploaded to AWS S3.

Just plug in your API keys, and you're ready to go.

## Features

- 🔑 Pre-built integrations with security tools.
- 🚀 Converts data from your security tools into OCSF-compliant format.
- 📦 Output in JSON and Parquet formats.
- ☁️ Direct integration with AWS S3 for cloud storage.
- 🖥️ Use as a CLI tool or Go library.

## Installation

```bash
go get github.com/telophasehq/go-ocsf
```

## Quick Start

Set environment variables required for your data source (e.g., Snyk):

```bash
export SNYK_API_KEY="your-snyk-api-key"
export SNYK_ORGANIZATION_ID="your-snyk-org-id"
```

Run the CLI to convert data and store locally as Parquet:

```bash
go run main.go --parquet
```

Store data directly in AWS S3:

```bash
export AWS_ACCESS_KEY_ID="your-aws-access-key-id"
export AWS_SECRET_ACCESS_KEY="your-aws-secret-access-key"
export AWS_REGION="your-aws-region"

go run main.go --parquet --bucket-name="your-s3-bucket-name"
```

## Library Usage

You can embed the functionality directly in your Go code:

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/telophasehq/go-ocsf/clients/snyk"
	"github.com/telophasehq/go-ocsf/datastore"
	"github.com/telophasehq/go-ocsf/syncers"
)

func main() {
	ctx := context.Background()

	snykClient, err := snyk.NewClient(ctx, os.Getenv("SNYK_API_KEY"), os.Getenv("SNYK_ORGANIZATION_ID"))
	if err != nil {
		log.Fatal(err)
	}

	storage, err := datastore.NewLocalParquetDatastore()
	if err != nil {
		log.Fatal(err)
	}

	syncer, err := syncers.NewSnykOCSFSyncer(ctx, snykClient, storage)
	if err != nil {
		log.Fatal(err)
	}

	if err := syncer.Sync(ctx); err != nil {
		log.Fatal(err)
	}
}
```

## Supported Integrations

- Snyk
- AWS Inspector
- Tenable
- AWS GuardDuty (coming soon)
– AWS Security Hub (coming soon)
- Crowdstrike Spotlight (coming soon)
- Google Workspace Logs (coming soon)
- AWS CloudTrail (coming soon)

## Testing

Run all tests:

```bash
go test ./...
```

Run generator tests only:

```bash
go test ./scripts -run Test -count=1
```

Run the v1.7.0 observable validation tests only:

```bash
go test . -run TestValidateObservablesV170 -count=1
```

Notes:

- `scripts/model_gen_test.go` includes compatibility tests for schema sanitization and `object_t` generation behavior.
- It also includes formatter fallback tests that simulate `goimports` failure and verify fallback to `gofmt`.
- `observables_v1_7_0_test.go` validates generated `ValidateObservables()` behavior for representative v1.7.0 models.

## Contributing

We welcome contributions to improve or expand functionality.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -am 'Add my feature'`)
4. Push to your branch (`git push origin feature/my-feature`)
5. Open a pull request

## License

`go-ocsf` is licensed under the [MIT License](LICENSE).
