# HELM — The Next Generation UTXO Ledger

## Introduction
HELM is a compact UTXO ledger that ties transaction semantics to consensus via the Lead UTXO model. It includes a stack-based VM for programmable spending conditions and a Chained Mask Proof-of-Work for block production.

See [WHITEPAPER.md](./WHITEPAPER.md) for the full protocol rationale and design details.

> [!NOTE]
> AI is used in the development and coding of this project.

## Components
- [helm](./) — Node binary. Boots and runs a local node, orchestrates networking, mempool, block assembly, consensus validation, and persistence.
- [helm-core](./helm-core) — Core library. Defines blocks, transactions, the UTXO model, validation rules, and the VM used to enforce spending conditions.
- [helm-net](./helm-net) — Networking layer. Implements libp2p-based peer discovery, gossip, mempool sync, and RPC endpoints consumed by the node.
- [helm-db](./helm-db) — Storage backend. Durable store for blocks, indices, and UTXO state; intended to be the node's pluggable persistence layer.
- [helm-cli](./helm-cli) — Command-line tools. Small utilities to inspect peers/state, construct and sign transactions, and broadcast them to a running node.


## Requirements
- Rust (stable) + Cargo
- `gcc` (for some deps)

## Quick start

Clone:
```sh
git clone https://github.com/snakedye/helm.git
cd helm
```

## Build
```sh
cargo build --workspace --release
```

Build one crate:
```sh
cargo build -p helm --release
```

## Run (single node)
1. Create a 32-byte secret (hex, 64 chars), e.g.:
```sh
openssl rand -hex 32
```
2. Export and run:
```sh
export HELM_SECRET_KEY=<your-64-hex>
cargo run -p helm --release
```

## Docker

Build the image:
```
docker build -t helm .
```

Run a node:
```
docker run -d --name helm-node \
  -e HELM_SECRET_KEY=$(openssl rand -hex 32) \
  -e HELM_MINING=true \
  -p 3333:3333 \
  helm
```

Override any configuration via environment variables or an env file:
```
docker run -d --name helm-node --env-file .env -p 3333:3333 helm
```

Persist chain data across restarts with a volume:
```
docker run -d --name helm-node \
  -e HELM_SECRET_KEY=<your-64-hex> \
  -p 3333:3333 \
  -v helm-data:/home/helm \
  helm
```

## Notes
- The node reads configuration from [.env](./.env.template) or environment variables.
- Use `helm-cli` to inspect peers, construct and broadcast transactions:
```sh
cargo run -p helm-cli -- --help
```

## Resources
- [Bitcoin Whitepaper](https://bitcoin.org/bitcoin.pdf)
- [HELM Whitepaper](./WHITEPAPER.md)
