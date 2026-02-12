# Quantum Secured Blockchain (QSB)

This is a repository for Quantum Secured Blockchain, an implementation of a quantum node using quantum 
and post-quantum security. It is a fork of a rust-based repository, [Substrate](https://github.com/paritytech/substrate).

## Table of contents
- [1. Setup](#1-setup)
  - [1.1. Prerequisites](#11-prerequisites)
- [2. Build](#2-build)
  - [2.1. Using `cargo`](#21-using-cargo)
  - [2.2. Using Docker](#22-using-docker)
- [3. Running](#3-running)
- [4. Testing](#4-testing)
  - [4.1 Rust unit tests](#41-rust-unit-tests)
- [5. Documentation](#5-documentation)
- [6. The whitepaper](#6-the-whitepaper)

## 1. Setup
### 1.1. Prerequisites 
To begin working with this repository you will need the following dependencies:
- [Rust](https://www.rust-lang.org/tools/install)
- Rust toolchain pinned via `rust-toolchain.toml` (required: `1.75.0`)
- [Docker](https://docs.docker.com/engine/install/) (optional)
- QKD-simulator
- Certificate for QKD-simulator

After downloading your dependencies you need to make sure to continue with these steps:
- Because this is a Substrate fork you will also need to configure Rust with a few additional steps, listed [here](https://docs.substrate.io/install/)
by substrate team.

## 2. Build
There are few ways to build this repository before running, listed below.

### 2.1. Using `cargo` 
Cargo is a tool provided by Rust to easily manage building, running and testing Rust code.
You can use it to build quantum node code with command:
```bash
cargo build --release
```
This will create a binary file in `./target/release`, called `qsb-node`.

### 2.2. Using Docker
Alternate way of building this repository uses Docker. To build a node use command:

```bash
docker build -t qsb-node .
```
This will create a `qsb-node` docker image.

## 3. Running

```bash
qsb-node 
  --sae-id <SAE_ID>
  --addr-pqkd <URL>
```

- **sae-id** - identifier of the SAE (node) used by the PQKD service;
- **addr-pqkd** - base URL of the PQKD service (e.g. `http://localhost:8182/`);

You can also pass any other Substrate-supported CLI arguments when starting the node (e.g. `--base-path`, `--chain`, `--port`, `--ws-port`, `--rpc-port`, `--name`).

## 4. Testing
Currently covered:
- QSB code (Rust unit tests)

### 4.1 Rust unit tests
To run QSB unit tests:
```bash
cargo test
```

## 5. Documentation
To generate documentation run:
```bash
cargo doc
```

## 6. The whitepaper
[QSB Whitepaper](https://www.quantumblockchains.io/wp-content/uploads/2023/06/QBCK_WhitePaper.pdf)

In order to display documentation go to `target/doc/<crate you want to see>` and open `index.html` file in the browser that you want to, e.g.
#### MAC

```bash
cd target/doc/qsb_node
open -a "Google Chrome" index.html
```

#### Linux

```bash
cd target/doc/qsb_node
firefox index.html
```
