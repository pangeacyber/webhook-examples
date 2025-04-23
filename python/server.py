#!/usr/bin/env python3

import binascii
import hashlib
import hmac
import os
from base64 import b64decode

from aiohttp import web
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

SIGNING_SECRET = os.getenv("SIGNING_SECRET", "")


def verify_signature(secret_key: bytes, signature: str, payload: bytes) -> bool:
    """Verifies a signature using HMAC-SHA256."""
    try:
        decoded_signature = b64decode(signature)
    except binascii.Error:
        return False

    mac = hmac.new(secret_key, payload, hashlib.sha256)
    expected_mac = mac.digest()
    return hmac.compare_digest(decoded_signature, expected_mac)


def decrypt_payload(secret: bytes, cipher_body: bytes) -> bytes:
    """Decrypts the payload using AES-GCM."""

    nonce_size = 12
    nonce = cipher_body[:nonce_size]
    ciphertext = cipher_body[nonce_size:]
    return AESGCM(secret).decrypt(nonce, ciphertext, None)


routes = web.RouteTableDef()


@routes.post("/webhook")
async def webhook(request: web.Request) -> web.StreamResponse:
    signature = request.headers.get("x-signature-sha256")
    if signature is None:
        return web.Response(text="Missing signature", status=400)

    payload = await request.read()

    if not verify_signature(b64decode(SIGNING_SECRET), signature, payload):
        return web.Response(text="Invalid signature", status=400)

    try:
        decrypted_body = decrypt_payload(b64decode(SIGNING_SECRET), payload)
        print("Decrypted payload:", decrypted_body.decode())
    except ValueError as e:
        print("Error decrypting payload:", e)
        return web.Response(text="Failed to decrypt content", status=503)

    return web.Response(text="OK")


def init() -> web.Application:
    app = web.Application()
    app.router.add_routes(routes)
    return app


web.run_app(init())
