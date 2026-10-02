# zixcel-owner-recovery

Coordinate explicit owner-recovery and device-transfer steps without taking ownership of account records.

## What you can do

- Represent recovery choices and retained evidence.
- Connect declared recovery and identity interfaces.

## Current scope

Recovery requires the configured proof provider and authority approval. The workflow does not infer ownership or bypass verification.

Package distribution is not activated by this documentation. Use the checked-in source and the declared dependency versions; published availability must be verified separately.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Use the configured private registry when a dependency is not distributed publicly. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)
