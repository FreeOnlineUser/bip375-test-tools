# BIP-375 Test PSBT Generator

Generate valid BIP-375 PSBTs for testing Silent Payment (BIP-352) verification in hardware wallets and coordinators.

> **FOR TESTING ONLY**
>
> These PSBTs reference **non-existent inputs** (randomly generated txids). They are designed purely for testing BIP-375 verification logic in hardware wallets. The Bitcoin network will reject any attempt to broadcast them since the inputs don't exist.

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

### GUI (Recommended for SeedSigner Testing)

```bash
python gui.py
```

The GUI provides:

- Generate SP addresses from any mnemonic (mainnet or testnet)
- Generate BIP-375 PSBTs with all required fields
- Animated UR QR codes for easy scanning
- Seed QR export for loading sender key into SeedSigner
- Camera scanning to verify signed PSBTs
- Transaction details display after verification

**Workflow:**

1. **Recipient SP Address** (left panel):
   - Enter recipient mnemonic or use default
   - Click "Generate SP Address" - QR code appears

2. **Sender PSBT** (right panel):
   - Enter sender mnemonic (different from recipient)
   - Click "Seed QR" to display the sender seed for SeedSigner
   - Load the seed into SeedSigner via Scan > Scan a SeedQR

3. **Generate and Sign:**
   - Set amount and click "Generate PSBT"
   - Scan the animated PSBT QR with SeedSigner
   - SeedSigner verifies BIP-375 and shows the SP address
   - Approve and sign on SeedSigner

4. **Verify Signature:**
   - Click "Use Camera to Verify Signed Transaction"
   - Point webcam at SeedSigner's animated QR code
   - Tool verifies signature and displays transaction details

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

In a real Silent Payment workflow, your coordinator wallet (Sparrow, BlueWallet, etc.) would:

1. Take the recipient's `sp1...` address
2. Select UTXOs to spend from your wallet
3. Derive the unique output address using BIP-352
4. Build a PSBT with BIP-375 fields so your signing device can verify the derivation
5. Send the PSBT to your hardware signer for approval

**This tool simulates step 4** - it generates the same BIP-375 PSBT that a coordinator wallet would create, allowing you to test hardware signer verification without needing a full wallet setup or real UTXOs.

**PSBT generation steps:**

1. **Parses SP address** - Extracts B_scan and B_spend public keys
2. **Generates input key** - Derives Taproot key from mnemonic at m/86'/0'/0'/0/0
3. **Computes SP output** - Derives the unique Taproot output address per BIP-352
4. **Generates DLEQ proof** - Creates BIP-374 proof that the ECDH was computed correctly
5. **Builds PSBT** - Embeds BIP-375 fields so the signer can independently verify the output

## Why is the SP Address Always the Same?

The SP address is derived deterministically from the mnemonic at fixed BIP-352 paths:

- `m/352'/0'/0'/0'/0` → spend key (B_spend)
- `m/352'/0'/0'/1'/0` → scan key (B_scan)

**Same mnemonic + same network = same SP address every time.**

This is intentional - a recipient's SP address is like their "permanent" receiving address. They share it publicly and can receive unlimited payments to it. The privacy magic happens on the *sender's* side.

## Why is the PSBT Different Each Time?

Each time you click "Generate PSBT", you'll get a different PSBT even for the same SP address and amount. This is expected and happens because:

1. **Random input txid** - Each PSBT uses a newly generated random fake txid as its input. Since the Silent Payment output derivation depends on the input outpoints, different txids produce different SP outputs.

2. **Random DLEQ nonce** - The BIP-374 DLEQ proof uses a random nonce `k` for security. This makes each proof unique while still being valid.

This is the core privacy feature of Silent Payments: **every payment to the same SP address produces a different on-chain output address**. An observer cannot link multiple payments to the same recipient by looking at the blockchain.

## Testing With Hardware Wallets

The generated PSBTs can be used to test Silent Payment verification in:
- SeedSigner (with BIP-352/375 support)
- Other hardware signers implementing BIP-375

## Dependencies

**Required:**

- `embit` - Bitcoin library for PSBT/transaction handling
- `qrcode[pil]` - QR code generation
- `Pillow` - Image processing
- `urtypes` - Uniform Resources (UR) encoding for animated QR codes

**Optional (for camera scanning):**

- `opencv-python` - Webcam capture
- `pyzbar` - QR code decoding

## Related BIPs

- [BIP-352: Silent Payments](https://github.com/bitcoin/bips/blob/master/bip-0352.mediawiki)
- [BIP-374: DLEQ Proofs](https://github.com/bitcoin/bips/blob/master/bip-0374.mediawiki)
- [BIP-375: Sending Silent Payments with PSBTs](https://github.com/bitcoin/bips/blob/master/bip-0375.mediawiki)

## License

MIT
