# superscalar-cln

SuperScalar channel factory plugin for Core Lightning.

Implements the factory protocol side of [bLIP-56](https://github.com/lightning/blips/pull/56) (pluggable channel factories) using Decker-Wattenhofer state trees with MuSig2.

## Requirements

- [Core Lightning](https://github.com/8144225309/lightning/tree/blip-56) with bLIP-56 support (branch `blip-56`)
- Bitcoin Core 28+

## Building

The plugin builds inside the CLN source tree:

```bash
# Clone CLN with bLIP-56 support
git clone --branch blip-56 https://github.com/8144225309/lightning.git cln-blip56
cd cln-blip56
./configure && make -j$(nproc)

# Copy plugin source and build
cp /path/to/superscalar-cln/superscalar.c plugins/
make plugins/superscalar
```

## Running

```bash
lightningd --plugin=/path/to/cln-blip56/plugins/superscalar
```

## Architecture

CLN handles channels. The plugin handles the factory.

The plugin receives factory protocol messages from peers via the `custommsg` hook and sends responses via the `factory-send` RPC. Factory state changes (rotation, rebalance) are triggered via the `factory-change` RPC.

## Status

Early development. The plugin skeleton registers hooks and receives messages. The factory protocol logic (DW tree construction, MuSig2 signing, state changes) is being ported from the [SuperScalar](https://github.com/8144225309/SuperScalar) implementation.
