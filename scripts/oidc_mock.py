#!/usr/bin/env python3
"""Minimal OIDC issuer for RustFS AssumeRoleWithWebIdentity tests.

Stdlib + openssl only. Issuer URL must match RUSTFS_IDENTITY_OPENID_CONFIG_URL
as seen from the RustFS container (http://oidc:8088).
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import subprocess
import tempfile
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ISSUER = os.environ.get("OIDC_ISSUER", "http://oidc:8088")
CLIENT_ID = os.environ.get("OIDC_CLIENT_ID", "duckbox-sts")
HOST = os.environ.get("OIDC_BIND", "0.0.0.0")
PORT = int(os.environ.get("OIDC_PORT", "8088"))
KID = "duckbox-oidc-1"

# Test-only RSA key (not a secret). n/e match this PEM.
PRIV_PEM = """-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCexgh/6HqoN0cb
zOzbDUJtOlyT8yFvZFu8dczdCX0um5D7O44GBZd9MQt+x2d6lm0kFVK6449lF/6X
S5OANcSiUF2UfTdp2/P/Me+p5a3pcZi/Dey2TzJUyx27g29LFZBfhQGIfUOJghz0
ppp1lDfcRAmjOfhbpvDvP+U4C1WT16QFXPppxILgCgWf+h0Zn1Acsdce1PkpsrMr
EHVsUYk6mH2srJM2H7YwR5xl1cfOa1JAdIuWSxhoGIH87uOK/Uk2bdUq83POm5QV
YoyyYNraeJ+p2LKYO62pWux/rqPjY1b8yuuMGTXiz8ZZus8Z37AYTDMo2mr7rTxK
du1OIhbjAgMBAAECggEABwKMToVnoPSr1YzjKjq4I5Vvj/Ksl7vxFu2GiX3JQp0I
tibnetmVWignr0XDilSI5g5w9CJm6to32dsy3HbDQz1UHGG46BoXeD1urOwglQ14
ZnsJZ/UwLjE3k1dWuxRtJuJ68llBeZk+iQiwCh/spXN1j3jYP8ernIyQJLzPXvMV
BP8LuasJy//1uMHKGHwk/DhHM3B2ILLD/vZXC/M7frB573A7AIjFvbQAPboRwEmB
2ZJUXlFGptngkkeJ2J7bjQprsueb1X1I2QDPobnup2XAsUtm//cm9q6MNPsqdwfC
0V2LKcCi17anIcj75roqkti8O/oXLedKIGri0Iwk/QKBgQDajcLRhgNTfkagl/qg
TVqfWW8LNIiE2QsrPwFdUcq+bvMvYRLgPXRufwTy/iNbtDUswcET1KPCZrT7R1eD
f37CTde8Kx229KBeaXRMHhWqesHMn0nRnI5gWsSYzNROMHM1wQOikvXvF25PDHek
DsssLb064t15OlsST4AWaP4sLQKBgQC5+i8sw3uDyGoxbn6Mp55n6pB73wD63sDc
klxU0MI1GqfcTcwty1iTmvzcTUKMc9Afpg5hXAc+oxKfmdhN2XGu3RZR3AUYMUAl
O/Pbwni4MmEhEj853fr9E1pOm9xf2yx7jfBg971vMjt64/fFi3M+mHiqy6TPbX6T
Sl5gvmRpTwKBgQC3Mdi5dBHZrKFa/8mPEQgDRh30UIaWhK/+AgQMywCc+7dQYZhG
6nxsGoB1hlzxA28HIynKi5Tw4NKXRkeu6/G+wS0yhxmTQB4kxVQ8cYNLsTY9ZM+l
qgsV7T+ZrSfQmoAX8MAxR+pqDUPjctneZKAdWgGiGIP4l9e603TUVBGpyQKBgFJy
pYNUzmcn7FwpvhShIsqy5Ibl4EtXgWzHvgMj4VUlkhFKtCABLC2T4lHQNpaJqVS+
i1WCNPwB03nJ/GjW411ASmrT/bYx71wSbhOY7WfLfd/pdPo0fNbBQ6Hh2xrr0Zac
4Fo8ulCXlmLuuaNsJRU1BxnA2jnTMvAdYiXFgkJlAoGAMYVp4VtJd1s2KCZ6dBzS
fduN9X6Co47d2fnpvO8mmq0KNBqMesyCdlqqmFzFMXlDR/Vl9eZTSxg0/pklPEFF
mXOXBtdoHwjynkf4OLFb97UodbZGQqeUStFespldlw++jo1jSYdnwC4x345xFd4g
FRA4rdh6kp1ggNN6BDe7Zic=
-----END PRIVATE KEY-----
"""
N = "nsYIf-h6qDdHG8zs2w1CbTpck_Mhb2RbvHXM3Ql9LpuQ-zuOBgWXfTELfsdnepZtJBVSuuOPZRf-l0uTgDXEolBdlH03advz_zHvqeWt6XGYvw3stk8yVMsdu4NvSxWQX4UBiH1DiYIc9KaadZQ33EQJozn4W6bw7z_lOAtVk9ekBVz6acSC4AoFn_odGZ9QHLHXHtT5KbKzKxB1bFGJOph9rKyTNh-2MEecZdXHzmtSQHSLlksYaBiB_O7jiv1JNm3VKvNzzpuUFWKMsmDa2nifqdiymDutqVrsf66j42NW_MrrjBk14s_GWbrPGd-wGEwzKNpq-608SnbtTiIW4w"
E = "AQAB"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_rs256(signing_input: bytes) -> bytes:
    with tempfile.NamedTemporaryFile("w", delete=False) as f:
        f.write(PRIV_PEM)
        path = f.name
    try:
        return subprocess.check_output(
            ["openssl", "dgst", "-sha256", "-sign", path],
            input=signing_input,
        )
    finally:
        os.unlink(path)


def mint_id_token() -> str:
    now = int(time.time())
    header = {"alg": "RS256", "kid": KID, "typ": "JWT"}
    claims = {
        "iss": ISSUER,
        "sub": "duckbox-sts-user",
        "aud": CLIENT_ID,
        "iat": now,
        "exp": now + 900,
        "groups": ["readwrite"],
        "roles": ["readwrite"],
        "email": "sts@example.test",
        "preferred_username": "duckboxsts",
    }
    head = b64url(json.dumps(header, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":")).encode())
    signing_input = f"{head}.{body}".encode()
    sig = b64url(sign_rs256(signing_input))
    return f"{head}.{body}.{sig}"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        return

    def _json(self, code: int, obj) -> None:
        raw = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _text(self, code: int, body: str, ctype: str = "text/plain") -> None:
        raw = body.encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path in ("/.well-known/openid-configuration", "/"):
            self._json(
                200,
                {
                    "issuer": ISSUER,
                    "jwks_uri": f"{ISSUER}/jwks",
                    "authorization_endpoint": f"{ISSUER}/authorize",
                    "token_endpoint": f"{ISSUER}/token",
                    "id_token_signing_alg_values_supported": ["RS256"],
                    "response_types_supported": ["id_token"],
                    "subject_types_supported": ["public"],
                },
            )
            return
        if path == "/jwks":
            self._json(
                200,
                {
                    "keys": [
                        {
                            "kty": "RSA",
                            "use": "sig",
                            "alg": "RS256",
                            "kid": KID,
                            "n": N,
                            "e": E,
                        }
                    ]
                },
            )
            return
        if path == "/token":
            self._text(200, mint_id_token(), "application/jwt")
            return
        if path == "/health":
            self._text(200, "ok")
            return
        self._text(404, "not found")


def main() -> None:
    # Touch openssl so a missing binary fails at boot, not at the first token.
    sign_rs256(hashlib.sha256(b"boot").digest())
    httpd = ThreadingHTTPServer((HOST, PORT), Handler)
    print(f"oidc_mock listening on {HOST}:{PORT} issuer={ISSUER}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
