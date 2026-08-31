import asyncio
import json
import time

from btsbots.signbots import SignBots

import hashlib
from binascii import hexlify
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

def get_fixed_private_key(seed_text: str) -> ec.EllipticCurvePrivateKey:
    seed_bytes = hashlib.sha256(seed_text.encode('utf-8')).digest()
    private_value = int.from_bytes(seed_bytes, byteorder='big')
    curve = ec.SECP256R1()
    curve_order = 115792089210356248762697446949407573529996955224135760342422259061068512044369
    private_value = (private_value % (curve_order - 1)) + 1
    return ec.derive_private_key(private_value, curve)

def sign_data(private_key_object, text_data: str) -> str:
    message_bytes = text_data.encode('utf-8')
    der_signature = private_key_object.sign(
        message_bytes,
        ec.ECDSA(hashes.SHA256())
    )
    r, s = decode_dss_signature(der_signature)
    r_bytes = r.to_bytes(32, byteorder='big')
    s_bytes = s.to_bytes(32, byteorder='big')
    raw_signature_bytes = r_bytes + s_bytes
    signature_hex = hexlify(raw_signature_bytes).decode('utf-8')

    return signature_hex

async def generate_string_signed_envelope(op_type: str, params: dict, wif: str) -> dict:

    private_key = get_fixed_private_key(wif)
    public_key = private_key.public_key()

    pub_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.X962,
        format=serialization.PublicFormat.UncompressedPoint
    )
    pubkey_hex = hexlify(pub_bytes).decode('utf-8')

    raw_intent_object = {
        "type": op_type,
        "client_time": int(time.time()),
        "params": params
    }

    tx_payload_string = json.dumps(raw_intent_object, sort_keys=True, separators=(',', ':'))

    signature_hex = sign_data(private_key, tx_payload_string)

    return {
        "tx_string": tx_payload_string,
        "browser_pubkey": pubkey_hex,
        "browser_sig": signature_hex
    }

async def main():
    client = SignBots()
    print(f"[*] Authenticating account via secure WIF handshake...")
    await client.run()

    AUTHORIZED_BROWSER_WIF = "5JrrH48Mumd2xymt3aiezKX1QcV3LDaCYuYFGa8tsaSDsaNwAJ8"
    UNAUTHORIZED_BROWSER_WIF = "5KQwrPbwdL6PhXujxW37FSSQZ1JiwsST4cqQzDeyXtP79zkvFD3"

    test_suite = [
        {
            "id": "CASE_01_REJECT_UNAUTHORIZED_KEY",
            "type": "limit_order_create",
            "wif": UNAUTHORIZED_BROWSER_WIF,
            "params": {"sell_asset": "BTS", "amount": 1.5, "receive_asset": "USD", "price": 5.2, "simulate": True}
        },
        {
            "id": "CASE_02_REJECT_BLACKLIST_TRANSFER",
            "type": "transfer",
            "wif": AUTHORIZED_BROWSER_WIF,
            "params": {"to_account": "exchange.btsbots", "asset": "BTS", "amount": 0.1, "simulate": True}
        },
        {
            "id": "CASE_03_REJECT_BLACKLIST_MARKET",
            "type": "limit_order_create",
            "wif": AUTHORIZED_BROWSER_WIF,
            "params": {"sell_asset": "BTS", "amount": 0.3, "receive_asset": "BTC", "price": 0.3, "fill_or_kill": True, "simulate": True}
        },
        {
            "id": "CASE_04_ACCEPT_VALID_SELL_ORDER",
            "type": "limit_order_create",
            "wif": AUTHORIZED_BROWSER_WIF,
            "params": {"sell_asset": "BTS", "amount": 0.4, "receive_asset": "USD", "price": 5, "simulate": True}
        },
        {
            "id": "CASE_05_REJECT_REPLAY_ATTACK",
            "id_override": "CASE_04_ACCEPT_VALID_SELL_ORDER",
            "type": "limit_order_create",
            "wif": AUTHORIZED_BROWSER_WIF,
            "params": {"sell_asset": "BTS", "amount": 0.4, "receive_asset": "USD", "price": 5, "simulate": True}
        }
    ]

    print("\n=== [RUNNING TEST: MULTI-SCENARIO STRING-BASED SECURITY ATTACKS] ===")
    cached_envelopes = {}

    for idx, run_meta in enumerate(test_suite, 1):
        case_id = run_meta["id"]
        print(f"\n🚀 [{idx}/{len(test_suite)}] Processing evaluation target: {case_id}")

        if case_id == "CASE_05_REJECT_REPLAY_ATTACK":
            envelope = cached_envelopes["CASE_04_ACCEPT_VALID_SELL_ORDER"]
            print("   [!] Injecting identical duplicate raw string buffer payload to trigger replay protection...")
        else:
            envelope = await generate_string_signed_envelope(run_meta["type"], run_meta["params"], run_meta["wif"])
            cached_envelopes[case_id] = envelope

        try:
            tx_id = await client.submit_proxy_sign_request(envelope)
            print(f"   🎉 [Test Result] Success! Passed through firewall and signed on-chain: {tx_id}")
        except Exception as error:
            print(f"   ❌ [Test Result] Intercepted by Firewall: {error}")

        if idx < len(test_suite):
            await asyncio.sleep(1)

    print("\n=== 🏁 Integration Multi-Variant Scenario Suite Complete ===")
    await client.close()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception as e:
        pass
