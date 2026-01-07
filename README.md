# BIP-375 Test PSBT Generator

Generate valid BIP-375 PSBTs for testing Silent Payment (BIP-352) verification in hardware wallets and coordinators.

## What is BIP-375?

[BIP-375](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki) defines how to embed Silent Payment information into PSBTs, allowing hardware signers to verify that outputs are correctly derived for a given Silent Payment address.

This tool generates test PSBTs with:
- `PSBT_OUT_SP_V0_INFO` (0x09) - Per-output B_scan and B_spend keys
- `PSBT_GLOBAL_SP_ECDH_SHARE` (0x07) - ECDH shared point
- `PSBT_GLOBAL_SP_DLEQ` (0x08) - BIP-374 DLEQ proof

## Installation

```bash
pip install -r requirements.txt
```

## Usage

### Command Line

```bash
# Generate PSBT for mainnet SP address
python generate_psbt.py --sp-address sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv --amount 100000

# Generate PSBT for testnet SP address with verbose output
python generate_psbt.py --sp-address tsp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgq8dv6yl92gtg66u5220sfrqlxrjkqlq4rk79d6y7vvgcf8p8hxq5k8kf6 --amount 50000 --verbose

# Save to file
python generate_psbt.py --sp-address sp1q... --amount 100000 --output test.psbt

# Use custom mnemonic for input key
python generate_psbt.py --sp-address sp1q... --amount 100000 --mnemonic "your twelve word mnemonic phrase here"
```

### As a Module

```python
from generate_psbt import create_bip375_psbt

psbt_base64, psbt_obj, output_xonly = create_bip375_psbt(
    sp_address="sp1qqgste7k9hx0qftg6qmwlkqtwuy6cycyavzmzj85c6qdfhjdpdjtdgqjuexzk6murw56suy3e0rd2cgqvycxttddwsvgxe2usfpxumr70xc9pkqwv",
    amount_sats=100000,
    mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
)

print(f"PSBT: {psbt_base64}")
print(f"Derived output: {output_xonly.hex()}")
```

## Options

| Option | Short | Description |
|--------|-------|-------------|
| `--sp-address` | `-a` | Silent Payment address (required) |
| `--amount` | `-n` | Amount in satoshis (default: 100000) |
| `--mnemonic` | `-m` | BIP-39 mnemonic for input key |
| `--output` | `-o` | Output file path |
| `--verbose` | `-v` | Print additional info to stderr |

## How It Works

1. **Parses SP address** - Extracts B_scan and B_spend public keys
2. **Generates input key** - Derives Taproot key from mnemonic at m/86'/0'/0'/0/0
3. **Computes SP output** - Derives the expected Taproot output per BIP-352
4. **Generates DLEQ proof** - Creates BIP-374 proof that ECDH was computed correctly
5. **Builds PSBT** - Creates transaction with all BIP-375 fields populated

## Testing With Hardware Wallets

The generated PSBTs can be used to test Silent Payment verification in:
- SeedSigner (with BIP-352/375 support)
- Other hardware signers implementing BIP-375

## Related BIPs

- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP-374: DLEQ Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP-375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)

## License

MIT
