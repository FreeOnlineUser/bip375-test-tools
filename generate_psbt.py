#!/usr/bin/env python3
"""
BIP-375 Test PSBT Generator

Generate valid BIP-375 PSBTs for testing Silent Payment verification.

Usage:
    python generate_psbt.py --sp-address sp1q... --amount 100000
    python generate_psbt.py --sp-address tsp1q... --amount 50000 --output test.psbt

Or import as module:
    from generate_psbt import create_bip375_psbt
"""

import argparse
import sys
from hashlib import sha256
from binascii import hexlify, unhexlify

from embit import bip32, bip39, ec, script
from embit.psbt import PSBT, InputScope, OutputScope
from embit.transaction import Transaction, TransactionInput, TransactionOutput
from embit.networks import NETWORKS
from embit.util import secp256k1


# ============================================================================
# Constants
# ============================================================================

# secp256k1 curve order
SECP256K1_ORDER = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

# BIP-375 PSBT field types
PSBT_GLOBAL_SP_ECDH_SHARE = 0x07
PSBT_GLOBAL_SP_DLEQ = 0x08
PSBT_OUT_SP_V0_INFO = 0x09

# Standard BIP-39 test mnemonic
DEFAULT_MNEMONIC = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

# Bech32m constants
BECH32M_CONST = 0x2bc830a3
CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


# ============================================================================
# Bech32m Implementation (for SP address parsing)
# ============================================================================

def bech32_polymod(values):
    """Internal function that computes the Bech32 checksum."""
    generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for value in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ value
        for i in range(5):
            chk ^= generator[i] if ((top >> i) & 1) else 0
    return chk


def bech32_hrp_expand(hrp):
    """Expand the HRP into values for checksum computation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def bech32m_verify_checksum(hrp, data):
    """Verify a Bech32m checksum."""
    return bech32_polymod(bech32_hrp_expand(hrp) + data) == BECH32M_CONST


def bech32m_create_checksum(hrp, data):
    """Compute the Bech32m checksum."""
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def bech32m_decode(bech):
    """Decode a Bech32m string."""
    if any(ord(x) < 33 or ord(x) > 126 for x in bech):
        return None, None
    if bech.lower() != bech and bech.upper() != bech:
        return None, None
    bech = bech.lower()
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech) or len(bech) > 90:
        return None, None
    if not all(x in CHARSET for x in bech[pos+1:]):
        return None, None
    hrp = bech[:pos]
    data = [CHARSET.find(x) for x in bech[pos+1:]]
    if not bech32m_verify_checksum(hrp, data):
        return None, None
    return hrp, data[:-6]


def bech32m_encode(hrp, data):
    """Encode data as Bech32m string."""
    combined = data + bech32m_create_checksum(hrp, data)
    return hrp + '1' + ''.join([CHARSET[d] for d in combined])


def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    max_acc = (1 << (frombits + tobits - 1)) - 1
    for value in data:
        if value < 0 or (value >> frombits):
            return None
        acc = ((acc << frombits) | value) & max_acc
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret


# ============================================================================
# Silent Payment Address Parsing
# ============================================================================

def parse_silent_payment_address(address: str) -> tuple:
    """
    Parse a Silent Payment address and extract the scan and spend pubkeys.

    Args:
        address: Silent Payment address (sp1... or tsp1...)

    Returns:
        (B_scan, B_spend, network) where pubkeys are 33-byte compressed format
    """
    hrp, data = bech32m_decode(address)
    if hrp is None:
        raise ValueError("Invalid bech32m encoding")

    if hrp == "sp":
        network = "mainnet"
    elif hrp == "tsp":
        network = "testnet"
    else:
        raise ValueError(f"Unknown HRP: {hrp}")

    if len(data) < 1:
        raise ValueError("Missing version byte")

    version = data[0]
    if version != 0:
        raise ValueError(f"Unsupported SP version: {version}")

    # Convert from 5-bit to 8-bit
    payload = convertbits(data[1:], 5, 8, False)
    if payload is None:
        raise ValueError("Invalid payload encoding")

    payload_bytes = bytes(payload)

    # Should be 66 bytes: 33-byte scan pubkey + 33-byte spend pubkey
    if len(payload_bytes) != 66:
        raise ValueError(f"Invalid payload length: {len(payload_bytes)}, expected 66")

    B_scan = payload_bytes[:33]
    B_spend = payload_bytes[33:66]

    # Validate pubkey prefixes
    if B_scan[0] not in (0x02, 0x03):
        raise ValueError("Invalid scan pubkey prefix")
    if B_spend[0] not in (0x02, 0x03):
        raise ValueError("Invalid spend pubkey prefix")

    return B_scan, B_spend, network


# ============================================================================
# Cryptographic Functions
# ============================================================================

def tagged_hash(tag: str, data: bytes) -> bytes:
    """BIP-340 tagged hash."""
    tag_hash = sha256(tag.encode()).digest()
    return sha256(tag_hash + tag_hash + data).digest()


def compute_sp_output_pubkey(
    input_privkeys: list,
    input_pubkeys: list,
    outpoints: list,
    B_scan: bytes,
    B_spend: bytes,
    k: int = 0
) -> bytes:
    """
    Compute the Silent Payment output x-only public key.

    Args:
        input_privkeys: List of 32-byte private keys
        input_pubkeys: List of 33-byte compressed public keys
        outpoints: List of (txid_bytes, vout) tuples
        B_scan: Recipient's scan public key (33 bytes)
        B_spend: Recipient's spend public key (33 bytes)
        k: Output index for this recipient (default 0)

    Returns:
        32-byte x-only public key for the Taproot output
    """
    # Sum input private keys (for ECDH)
    a_sum = 0
    for privkey in input_privkeys:
        a_sum = (a_sum + int.from_bytes(privkey, 'big')) % SECP256K1_ORDER

    # Compute input hash
    # Sort outpoints lexicographically: (txid || vout)
    outpoint_data = []
    for txid, vout in outpoints:
        outpoint_data.append(txid + vout.to_bytes(4, 'little'))
    outpoint_data.sort()

    # Sum of input pubkeys (x-only, for input hash)
    A_sum_point = None
    for pubkey in input_pubkeys:
        point = secp256k1.ec_pubkey_parse(pubkey)
        if A_sum_point is None:
            A_sum_point = point
        else:
            A_sum_point = secp256k1.ec_pubkey_combine([A_sum_point, point])

    A_sum = secp256k1.ec_pubkey_serialize(A_sum_point, secp256k1.EC_COMPRESSED)
    A_sum_xonly = A_sum[1:] if A_sum[0] == 0x02 else A_sum[1:]  # x-coordinate

    # input_hash = hash(outpoints || A_sum)
    input_hash_preimage = b''.join(outpoint_data) + A_sum_xonly
    input_hash = tagged_hash("BIP0352/Inputs", input_hash_preimage)

    # Compute ECDH: a_sum * input_hash * B_scan
    a_tweaked = (a_sum * int.from_bytes(input_hash, 'big')) % SECP256K1_ORDER

    B_scan_point = secp256k1.ec_pubkey_parse(B_scan)
    ecdh_point = secp256k1.ec_pubkey_tweak_mul(B_scan_point, a_tweaked.to_bytes(32, 'big'))
    ecdh_secret = secp256k1.ec_pubkey_serialize(ecdh_point, secp256k1.EC_COMPRESSED)

    # t_k = hash("BIP0352/SharedSecret" || ecdh_x || k)
    ecdh_x = ecdh_secret[1:33]  # x-coordinate only
    t_k = tagged_hash("BIP0352/SharedSecret", ecdh_x + k.to_bytes(4, 'little'))
    t_k_int = int.from_bytes(t_k, 'big') % SECP256K1_ORDER

    # P_k = B_spend + t_k * G
    B_spend_point = secp256k1.ec_pubkey_parse(B_spend)
    G = secp256k1.ec_pubkey_parse(unhexlify("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
    t_k_G = secp256k1.ec_pubkey_tweak_mul(G, t_k_int.to_bytes(32, 'big'))
    P_k = secp256k1.ec_pubkey_combine([B_spend_point, t_k_G])

    P_k_full = secp256k1.ec_pubkey_serialize(P_k, secp256k1.EC_COMPRESSED)

    # Return x-only (32 bytes)
    return P_k_full[1:33]


def generate_dleq_proof(a: int, A: bytes, B_scan: bytes) -> tuple:
    """
    Generate a BIP-374 DLEQ proof.

    Proves that C = a * B_scan where A = a * G, without revealing 'a'.

    Args:
        a: Private key scalar
        A: Public key A = a * G (33 bytes compressed)
        B_scan: Recipient's scan pubkey (33 bytes compressed)

    Returns:
        (C, proof) where C is the ECDH result and proof is 64 bytes
    """
    # C = a * B_scan
    B_scan_point = secp256k1.ec_pubkey_parse(B_scan)
    C_point = secp256k1.ec_pubkey_tweak_mul(B_scan_point, a.to_bytes(32, 'big'))
    C = secp256k1.ec_pubkey_serialize(C_point, secp256k1.EC_COMPRESSED)

    # Generate random k for proof
    import secrets
    k = secrets.randbelow(SECP256K1_ORDER - 1) + 1

    # R1 = k * G
    G = secp256k1.ec_pubkey_parse(unhexlify("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798"))
    R1_point = secp256k1.ec_pubkey_tweak_mul(G, k.to_bytes(32, 'big'))
    R1 = secp256k1.ec_pubkey_serialize(R1_point, secp256k1.EC_COMPRESSED)

    # R2 = k * B_scan
    R2_point = secp256k1.ec_pubkey_tweak_mul(B_scan_point, k.to_bytes(32, 'big'))
    R2 = secp256k1.ec_pubkey_serialize(R2_point, secp256k1.EC_COMPRESSED)

    # e = hash(A || B_scan || C || R1 || R2)
    e_preimage = A + B_scan + C + R1 + R2
    e = int.from_bytes(sha256(e_preimage).digest(), 'big') % SECP256K1_ORDER

    # s = k + e * a mod n
    s = (k + e * a) % SECP256K1_ORDER

    proof = e.to_bytes(32, 'big') + s.to_bytes(32, 'big')

    return C, proof


# ============================================================================
# Main PSBT Generator
# ============================================================================

def create_bip375_psbt(
    sp_address: str,
    amount_sats: int,
    mnemonic: str = DEFAULT_MNEMONIC,
    fake_txid: str = None,
    fake_vout: int = 0,
    input_amount_sats: int = None,
    network: str = "testnet"
) -> tuple:
    """
    Create a PSBT with BIP-375 Silent Payment fields.

    Args:
        sp_address: Silent Payment address (sp1... or tsp1...)
        amount_sats: Amount to send in satoshis
        mnemonic: BIP-39 mnemonic for input key
        fake_txid: Fake input txid (32 bytes hex, generated if None)
        fake_vout: Input vout index
        input_amount_sats: Input UTXO amount (default: amount + 1000 for fee)
        network: "mainnet" or "testnet"

    Returns:
        (psbt_base64, psbt_object, derived_output_pubkey)
    """
    # Parse SP address
    B_scan, B_spend, addr_network = parse_silent_payment_address(sp_address)

    # Set network based on address
    if addr_network == "testnet":
        network = "testnet"
        embit_network = "test"
    else:
        network = "mainnet"
        embit_network = "main"

    # Generate input key from mnemonic
    seed_bytes = bip39.mnemonic_to_seed(mnemonic)
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])

    # Derive key at m/86'/0'/0'/0/0 (Taproot)
    if network == "testnet":
        derivation_path = "m/86'/1'/0'/0/0"
    else:
        derivation_path = "m/86'/0'/0'/0/0"

    derived_key = root.derive(derivation_path)
    private_key = derived_key.key
    public_key = private_key.get_public_key()

    # Get private key as integer
    privkey_bytes = private_key.serialize()
    a = int.from_bytes(privkey_bytes, 'big')

    # Get compressed pubkey
    A = public_key.serialize()

    # Generate fake txid if not provided
    if fake_txid is None:
        import secrets
        fake_txid = secrets.token_hex(32)

    # Input amount
    if input_amount_sats is None:
        input_amount_sats = amount_sats + 1000  # Add fee

    # Create outpoint for SP derivation
    outpoint = (unhexlify(fake_txid)[::-1], fake_vout)  # txid is little-endian

    # Compute SP output pubkey
    output_xonly = compute_sp_output_pubkey(
        input_privkeys=[privkey_bytes],
        input_pubkeys=[A],
        outpoints=[outpoint],
        B_scan=B_scan,
        B_spend=B_spend,
        k=0
    )

    # Create Taproot output script: OP_1 <32-byte-xonly-pubkey>
    output_script = script.Script(b'\x51\x20' + output_xonly)

    # Build transaction
    tx = Transaction(
        version=2,
        vin=[
            TransactionInput(
                txid=unhexlify(fake_txid)[::-1],
                vout=fake_vout,
                sequence=0xfffffffd
            )
        ],
        vout=[
            TransactionOutput(
                value=amount_sats,
                script_pubkey=output_script
            )
        ],
        locktime=0
    )

    # Create PSBT
    psbt = PSBT(tx)

    # Add input info
    inp = psbt.inputs[0]

    # Create witness UTXO (Taproot input)
    input_script = script.Script(b'\x51\x20' + public_key.xonly())
    inp.witness_utxo = TransactionOutput(
        value=input_amount_sats,
        script_pubkey=input_script
    )

    # Add BIP32 derivation info
    fingerprint = root.child(0).fingerprint
    derivation = bip32.DerivationPath.parse(derivation_path)
    inp.taproot_bip32_derivations = {
        public_key.xonly(): ([], bip32.DerivationPath(fingerprint, derivation.derivation))
    }

    # Generate DLEQ proof
    C, dleq_proof = generate_dleq_proof(a, A, B_scan)

    # Add BIP-375 fields

    # Global: ECDH share (key: 0x07 || B_scan, value: C)
    ecdh_key = bytes([PSBT_GLOBAL_SP_ECDH_SHARE]) + B_scan
    psbt.unknown[ecdh_key] = C

    # Global: DLEQ proof (key: 0x08 || B_scan, value: 64-byte proof)
    dleq_key = bytes([PSBT_GLOBAL_SP_DLEQ]) + B_scan
    psbt.unknown[dleq_key] = dleq_proof

    # Output: SP V0 info (key: 0x09, value: B_scan || B_spend)
    out = psbt.outputs[0]
    if not hasattr(out, 'unknown') or out.unknown is None:
        out.unknown = {}
    sp_info_key = bytes([PSBT_OUT_SP_V0_INFO])
    out.unknown[sp_info_key] = B_scan + B_spend

    # Serialize to base64
    psbt_base64 = psbt.to_string()

    return psbt_base64, psbt, output_xonly


def main():
    parser = argparse.ArgumentParser(
        description="Generate BIP-375 test PSBTs for Silent Payment verification"
    )
    parser.add_argument(
        "--sp-address", "-a",
        required=True,
        help="Silent Payment address (sp1... or tsp1...)"
    )
    parser.add_argument(
        "--amount", "-n",
        type=int,
        default=100000,
        help="Amount in satoshis (default: 100000)"
    )
    parser.add_argument(
        "--mnemonic", "-m",
        default=DEFAULT_MNEMONIC,
        help="BIP-39 mnemonic for input key"
    )
    parser.add_argument(
        "--output", "-o",
        help="Output file path (prints to stdout if not specified)"
    )
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Print additional info"
    )

    args = parser.parse_args()

    try:
        psbt_base64, psbt, output_xonly = create_bip375_psbt(
            sp_address=args.sp_address,
            amount_sats=args.amount,
            mnemonic=args.mnemonic
        )

        if args.verbose:
            print(f"SP Address: {args.sp_address}", file=sys.stderr)
            print(f"Amount: {args.amount} sats", file=sys.stderr)
            print(f"Derived output pubkey: {output_xonly.hex()}", file=sys.stderr)
            print(f"PSBT has BIP-375 fields: Yes", file=sys.stderr)
            print("", file=sys.stderr)

        if args.output:
            with open(args.output, 'w') as f:
                f.write(psbt_base64)
            print(f"PSBT written to {args.output}", file=sys.stderr)
        else:
            print(psbt_base64)

    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
