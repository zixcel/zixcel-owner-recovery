# zixcel-owner-recovery

Coordinate explicit owner-recovery and device-transfer steps without taking ownership of account records.

## What you can do

- Represent recovery choices and retained evidence.
- Connect declared recovery and identity interfaces.

## Current scope

Recovery requires the configured proof provider and authority approval. The workflow does not infer ownership or bypass verification.

This is an independently packaged Rust library. Cargo dependencies are resolved from crates.io; runtime authority, network and storage configuration remain caller-owned.

## Getting started

Install Rust 1.97 or newer and make the declared dependencies available. Resolve the declared dependencies from crates.io. Run from this repository:

```sh
cargo test --locked
```

## Documentation and source

[Usage guide](docs/getting-started.md)

[Implementation and public interfaces](src) · [Contributing](CONTRIBUTING.md) · [Security reporting](SECURITY.md) · [License](LICENSE) · [Attribution notices](NOTICE)

`zixcel-contracts` resolves version `0.10.1` from crates.io. The credential-authority contracts also resolve version `0.10.0` from crates.io. No private registry is needed for these dependencies.
