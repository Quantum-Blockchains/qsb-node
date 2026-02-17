# Quantum Secured Blockchain (QSB)

This repository contains Quantum Secured Blockchain (QSB), a Substrate-based node implementation focused on quantum and post-quantum security.

## Table of contents
- [1. Quick Start](#1-quick-start)
- [2. Setup](#2-setup)
  - [2.1. Prerequisites](#21-prerequisites)
- [3. Build](#3-build)
  - [3.1. Using `cargo`](#31-using-cargo)
  - [3.2. Using Docker](#32-using-docker)
- [4. Running](#4-running)
- [5. Testing](#5-testing)
  - [5.1. Full workspace tests](#51-full-workspace-tests)
  - [5.2. DID pallet tests only](#52-did-pallet-tests-only)
  - [5.3. Benchmarking and weight generation](#53-benchmarking-and-weight-generation)
- [6. Documentation](#6-documentation)
- [7. Whitepaper](#7-whitepaper)

## 1. Quick Start

1. Install dependencies from [Setup](#2-setup).
2. Build the node:
```bash
cargo build --release
```
3. Start PQKD service/simulator and make sure it is reachable (for example `http://localhost:8182/`).
4. Run the node:
```bash
./target/release/qsb-node \
  --sae-id <SAE_ID> \
  --addr-pqkd <URL>
```
5. Run tests:
```bash
cargo test -p did --lib
```

## 2. Setup

### 2.1. Prerequisites

To work with this repository, install:
- [Rust](https://www.rust-lang.org/tools/install)
- Rust toolchain pinned via `rust-toolchain.toml` (required: `1.75.0`)
- [Docker](https://docs.docker.com/engine/install/) (optional)
- PQKD/QKD simulator (available from Quantum Blockchains: https://www.quantumblockchains.io/pqkd/)
- Certificate required by your PQKD simulator setup

Because this project is based on Substrate, complete the additional Substrate environment setup as described here:
- https://docs.substrate.io/install/

## 3. Build

You can build the project in two ways.

### 3.1. Using `cargo`

```bash
cargo build --release
```
This produces the `qsb-node` binary in `./target/release`.

### 3.2. Using Docker

Build a Docker image:
```bash
docker build -t qsb-node .
```
This creates the `qsb-node` image.

## 4. Running

Using built binary:
```bash
./target/release/qsb-node \
  --sae-id <SAE_ID>
  --addr-pqkd <URL>
```

Using Cargo:
```bash
cargo run --release --bin qsb-node -- \
  --sae-id <SAE_ID> \
  --addr-pqkd <URL>
```

- `sae-id`: identifier of the SAE (node) used by the PQKD service
- `addr-pqkd`: base URL of the PQKD service (for example `http://localhost:8182/`)

You can also pass standard Substrate CLI options (for example `--base-path`, `--chain`, `--port`, `--ws-port`, `--rpc-port`, `--name`).

## 5. Testing

Current automated coverage in this repository is focused on Rust unit tests (including pallet behavior tests on mock runtime).

### 5.1. Full workspace tests

```bash
cargo test
```

### 5.2. DID pallet tests only

```bash
cargo test -p did --lib
```

### 5.3. Benchmarking and weight generation

Runtime benchmarks are used to generate pallet weights (for example `pallets/did/src/default_weights.rs`).

Example command:
```bash
target/release/qsb-node benchmark pallet \
  --chain dev \
  --pallet did \
  --extrinsic '*' \
  --steps 20 \
  --repeat 10 \
  --output pallets/did/src/default_weights.rs
```

## 6. Documentation

Generate Rust docs:
```bash
cargo doc
```

Open docs for a crate (examples):

macOS:
```bash
cd target/doc/qsb_node
open -a "Google Chrome" index.html
```

Linux:
```bash
cd target/doc/qsb_node
firefox index.html
```

## 7. Whitepaper

[QSB Whitepaper](https://www.quantumblockchains.io/wp-content/uploads/2023/06/QBCK_WhitePaper.pdf)
