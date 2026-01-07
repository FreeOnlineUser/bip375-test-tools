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
from typing import Tuple, List, Optional

from embit import bip32, bip39, ec, script
from embit.psbt import PSBT, InputScope, OutputScope, DerivationPath
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

def _bech32_polymod(values: List[int]) -> int:
    """Internal function for Bech32 checksum calculation."""
    GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1ffffff) << 5 ^ v
        for i in range(5):
            chk ^= GEN[i] if ((top >> i) & 1) else 0
    return chk


def _bech32_hrp_expand(hrp: str) -> List[int]:
    """Expand HRP for checksum calculation."""
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _bech32m_verify_checksum(hrp: str, data: List[int]) -> bool:
    """Verify Bech32m checksum."""
    return _bech32_polymod(_bech32_hrp_expand(hrp) + data) == BECH32M_CONST


def _bech32m_create_checksum(hrp: str, data: List[int]) -> List[int]:
    """Create Bech32m checksum."""
    values = _bech32_hrp_expand(hrp) + data
    polymod = _bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ BECH32M_CONST
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]


def _convertbits(data: List[int], frombits: int, tobits: int, pad: bool = True) -> Optional[List[int]]:
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


def bech32m_decode(bech: str) -> Tuple[str, bytes]:
    """
    Decode a Bech32m string (SP address) into HRP and data.

    Args:
        bech: The Bech32m encoded string

    Returns:
        Tuple of (hrp, data_bytes)

    Raises:
        ValueError: If the address is invalid
    """
    bech = bech.lower()

    # Find separator
    pos = bech.rfind('1')
    if pos < 1 or pos + 7 > len(bech):
        raise ValueError("Invalid separator position")

    hrp = bech[:pos]
    data_part = bech[pos + 1:]

    # Decode data characters
    data = []
    for c in data_part:
        if c not in CHARSET:
            raise ValueError(f"Invalid character: {c}")
        data.append(CHARSET.index(c))

    # Verify checksum
    if not _bech32m_verify_checksum(hrp, data):
        raise ValueError("Invalid checksum")

    # Remove checksum (last 6 characters) and convert from 5-bit to 8-bit
    data = data[:-6]

    # First element is the witness version
    if len(data) == 0:
        raise ValueError("Empty data")

    version = data[0]

    # Convert remaining 5-bit groups to bytes
    decoded = _convertbits(data[1:], 5, 8, False)
    if decoded is None:
        raise ValueError("Invalid padding")

    return hrp, bytes([version] + decoded)


def bech32m_encode(hrp: str, data: bytes) -> str:
    """Encode data as Bech32m string."""
    # First byte is version
    version = data[0]
    payload = list(data[1:])

    # Convert from 8-bit to 5-bit
    converted = _convertbits(payload, 8, 5, True)
    if converted is None:
        raise ValueError("Invalid data for encoding")

    # Prepend version
    data_5bit = [version] + converted

    checksum = _bech32m_create_checksum(hrp, data_5bit)
    return hrp + '1' + ''.join([CHARSET[d] for d in data_5bit + checksum])


# ============================================================================
# Silent Payment Address Generation & Parsing
# ============================================================================

def generate_sp_address(mnemonic: str = DEFAULT_MNEMONIC, network: str = "mainnet") -> Tuple[str, bytes, bytes]:
    """
    Generate a Silent Payment address from a mnemonic.

    Per BIP-352, SP addresses use:
    - B_scan = b_scan * G (scan private key derived at m/352'/0'/0'/1'/0)
    - B_spend = b_spend * G (spend private key derived at m/352'/0'/0'/0'/0)

    Args:
        mnemonic: BIP-39 mnemonic
        network: "mainnet" or "testnet"

    Returns:
        (sp_address, B_scan, B_spend)
    """
    from embit import bip39

    # Network settings
    if network == "testnet":
        embit_network = "test"
        hrp = "tsp"
        coin_type = "1'"
    else:
        embit_network = "main"
        hrp = "sp"
        coin_type = "0'"

    # Generate keys from mnemonic
    seed_bytes = bip39.mnemonic_to_seed(mnemonic)
    root = bip32.HDKey.from_seed(seed_bytes, version=NETWORKS[embit_network]["xprv"])

    # BIP-352 derivation paths
    # m/352'/coin'/account'/0'/0 for spend key
    # m/352'/coin'/account'/1'/0 for scan key
    spend_path = f"m/352'/{coin_type}/0'/0'/0"
    scan_path = f"m/352'/{coin_type}/0'/1'/0"

    spend_key = root.derive(spend_path).key
    scan_key = root.derive(scan_path).key

    B_spend = spend_key.get_public_key().serialize()
    B_scan = scan_key.get_public_key().serialize()

    # Encode as SP address
    # Format: version (0) + B_scan (33 bytes) + B_spend (33 bytes)
    payload = bytes([0]) + B_scan + B_spend
    sp_address = bech32m_encode(hrp, payload)

    return sp_address, B_scan, B_spend


def parse_silent_payment_address(address: str) -> Tuple[bytes, bytes, str]:
    """
    Parse a Silent Payment address and extract the scan and spend pubkeys.

    Args:
        address: Silent Payment address (sp1... or tsp1...)

    Returns:
        (B_scan, B_spend, network) where pubkeys are 33-byte compressed format
    """
    hrp, data = bech32m_decode(address)

    if hrp == "sp":
        network = "mainnet"
    elif hrp == "tsp":
        network = "testnet"
    else:
        raise ValueError(f"Invalid HRP for SP address: {hrp}")

    # First byte is version (should be 0 for v0 SP addresses)
    if len(data) < 1:
        raise ValueError("Missing version byte")

    version = data[0]
    if version != 0:
        raise ValueError(f"Unsupported SP address version: {version}")

    payload = data[1:]

    if len(payload) != 66:
        raise ValueError(f"Invalid SP address data length: {len(payload)}, expected 66")

    B_scan = payload[:33]
    B_spend = payload[33:66]

    # Validate that both are valid compressed public keys
    if B_scan[0] not in (0x02, 0x03) or B_spend[0] not in (0x02, 0x03):
        raise ValueError("Invalid public key prefix in SP address")

    return bytes(B_scan), bytes(B_spend), network


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
    A_sum_xonly = A_sum[1:]  # x-coordinate (32 bytes)

    # input_hash = hash(smallest_outpoint || A_sum)
    # BIP-352: use smallest outpoint, not all outpoints
    smallest_outpoint = min(outpoint_data)
    input_hash = tagged_hash("BIP0352/Inputs", smallest_outpoint + A_sum_xonly)

    # Compute ECDH: a_sum * input_hash * B_scan
    a_tweaked = (a_sum * int.from_bytes(input_hash, 'big')) % SECP256K1_ORDER

    # NOTE: ec_pubkey_tweak_mul modifies point IN-PLACE and returns None
    B_scan_point = secp256k1.ec_pubkey_parse(B_scan)
    secp256k1.ec_pubkey_tweak_mul(B_scan_point, a_tweaked.to_bytes(32, 'big'))
    ecdh_secret = secp256k1.ec_pubkey_serialize(B_scan_point, secp256k1.EC_COMPRESSED)

    # t_k = hash("BIP0352/SharedSecret" || ecdh_x || k)
    ecdh_x = ecdh_secret[1:33]  # x-coordinate only
    t_k = tagged_hash("BIP0352/SharedSecret", ecdh_x + k.to_bytes(4, 'little'))

    # P_k = B_spend + t_k * G (use ec_pubkey_tweak_add which adds t_k * G in-place)
    B_spend_point = secp256k1.ec_pubkey_parse(B_spend)
    secp256k1.ec_pubkey_tweak_add(B_spend_point, t_k)

    P_k_full = secp256k1.ec_pubkey_serialize(B_spend_point, secp256k1.EC_COMPRESSED)

    # Return x-only (32 bytes)
    return P_k_full[1:33]


def generate_dleq_proof(a: int, A: bytes, B_scan: bytes) -> tuple:
    """
    Generate a BIP-374 DLEQ proof.

    Proves that C = a * B_scan where A = a * G, without revealing 'a'.

    Per BIP-374, the challenge is computed as:
    e = hash_BIP0374/challenge(A || B || C || G || R1 || R2)

    Args:
        a: Private key scalar
        A: Public key A = a * G (33 bytes compressed)
        B_scan: Recipient's scan pubkey (33 bytes compressed)

    Returns:
        (C, proof) where C is the ECDH result and proof is 64 bytes
    """
    import secrets

    # Generator point G (compressed)
    G_bytes = unhexlify("0279BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")

    # C = a * B_scan (tweak_mul modifies in-place)
    B_scan_point = secp256k1.ec_pubkey_parse(B_scan)
    secp256k1.ec_pubkey_tweak_mul(B_scan_point, a.to_bytes(32, 'big'))
    C = secp256k1.ec_pubkey_serialize(B_scan_point, secp256k1.EC_COMPRESSED)

    # Generate random k for proof
    k = secrets.randbelow(SECP256K1_ORDER - 1) + 1

    # R1 = k * G (tweak_mul modifies in-place)
    G_point = secp256k1.ec_pubkey_parse(G_bytes)
    secp256k1.ec_pubkey_tweak_mul(G_point, k.to_bytes(32, 'big'))
    R1 = secp256k1.ec_pubkey_serialize(G_point, secp256k1.EC_COMPRESSED)

    # R2 = k * B_scan (need fresh parse since B_scan_point was modified)
    B_scan_point2 = secp256k1.ec_pubkey_parse(B_scan)
    secp256k1.ec_pubkey_tweak_mul(B_scan_point2, k.to_bytes(32, 'big'))
    R2 = secp256k1.ec_pubkey_serialize(B_scan_point2, secp256k1.EC_COMPRESSED)

    # BIP-374: e = hash_BIP0374/challenge(A || B || C || G || R1 || R2)
    e_preimage = A + B_scan + C + G_bytes + R1 + R2
    e = int.from_bytes(tagged_hash("BIP0374/challenge", e_preimage), 'big') % SECP256K1_ORDER

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

    # For Taproot key-path spend, the output script contains the TWEAKED pubkey
    # The tweak is: t = tagged_hash("TapTweak", internal_key || merkle_root)
    # For key-path only (no scripts), merkle_root is empty, so: t = tagged_hash("TapTweak", internal_key)
    # Output key = internal_key + t*G
    internal_xonly = public_key.xonly()

    # Compute taproot tweak
    tap_tweak = tagged_hash("TapTweak", internal_xonly)

    # Tweaked public key = P + t*G
    # We need to add t*G to the internal key point
    internal_point = secp256k1.ec_pubkey_parse(public_key.serialize())
    secp256k1.ec_pubkey_tweak_add(internal_point, tap_tweak)
    tweaked_pubkey = secp256k1.ec_pubkey_serialize(internal_point, secp256k1.EC_COMPRESSED)
    tweaked_xonly = tweaked_pubkey[1:33]  # x-coordinate only

    # Create witness UTXO with the TWEAKED pubkey (what actually appears on-chain)
    input_script = script.Script(b'\x51\x20' + tweaked_xonly)
    inp.witness_utxo = TransactionOutput(
        value=input_amount_sats,
        script_pubkey=input_script
    )

    # Add Taproot BIP32 derivation info so SeedSigner can sign
    # Get the master fingerprint from the root key
    fingerprint = root.my_fingerprint

    # Parse the derivation path to list of integers
    if network == "testnet":
        path_list = bip32.parse_path("m/86'/1'/0'/0/0")
    else:
        path_list = bip32.parse_path("m/86'/0'/0'/0/0")

    # Create DerivationPath object
    deriv_path = DerivationPath(fingerprint, path_list)

    # Add to taproot_bip32_derivations
    # Key is the public key, value is (leaf_hashes, derivation)
    # Empty leaf_hashes for key-path spend
    inp.taproot_bip32_derivations[public_key] = ([], deriv_path)

    # Also set the taproot internal key (x-only pubkey)
    inp.taproot_internal_key = public_key

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
    # IMPORTANT: Always assign a NEW dict to avoid embit's shared mutable default bug
    out = psbt.outputs[0]
    sp_info_key = bytes([PSBT_OUT_SP_V0_INFO])
    out.unknown = {sp_info_key: B_scan + B_spend}

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
