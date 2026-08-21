import base64
import hashlib
import hmac
import json
import os
import time

import requests

GATEWAY_URL = os.getenv("GATEWAY_URL", "http://localhost:8080/test")
JWT_SECRET = os.getenv("JWT_SECRET", "ygfojur-longdfsg-rdhdandohjdm-jwt-sechgjret")
JWT_ISSUER = os.getenv("JWT_ISSUER", "yshourvfds-auhsth-sssvbfervice")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "your-cvmhgapi")
REQUEST_DELAY_SECONDS = float(os.getenv("REQUEST_DELAY_SECONDS", "0.1"))


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def make_jwt(subject: str, *, alg: str = "HS256", expires_in: int = 300, extra_claims=None) -> str:
    header = {"alg": alg, "typ": "JWT"}
    now = int(time.time())
    claims = {
        "sub": subject,
        "iat": now,
        "nbf": now,
        "exp": now + expires_in,
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
    }
    if extra_claims:
        claims.update(extra_claims)

    header_json = json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    claims_json = json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    signing_input = f"{b64url_encode(header_json)}.{b64url_encode(claims_json)}".encode("ascii")

    if alg == "HS256":
        digest = hashlib.sha256
    elif alg == "HS512":
        digest = hashlib.sha512
    else:
        raise ValueError(f"unsupported algorithm: {alg}")

    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, digest).digest()
    return f"{b64url_encode(header_json)}.{b64url_encode(claims_json)}.{b64url_encode(signature)}"


def send_request(label: str, payload, *, headers=None, count: int = 1, delay: float = REQUEST_DELAY_SECONDS):
    headers = dict(headers or {})
    headers.setdefault("Content-Type", "application/json")

    for idx in range(1, count + 1):
        try:
            response = requests.post(GATEWAY_URL, json=payload, headers=headers, timeout=10)
            print(f"[{label}] request {idx}/{count} -> {response.status_code} {response.text.strip()}")
        except requests.RequestException as exc:
            print(f"[{label}] request {idx}/{count} -> ERROR {exc}")
        if delay > 0:
            time.sleep(delay)


def build_payload(user_id: str, *, n: int, extra: str = "normal"):
    return {"user_id": user_id, "foo": extra, "n": n, "source": "load_test"}


def build_auth_header(subject: str, *, alg: str = "HS256", expires_in: int = 300, extra_claims=None):
    return {"Authorization": f"Bearer {make_jwt(subject, alg=alg, expires_in=expires_in, extra_claims=extra_claims)}"}


def run_genuine_traffic():
    base_users = [
        ("alice", "login_flow"),
        ("bob", "dashboard_view"),
        ("charlie", "profile_edit"),
        ("diana", "api_usage"),
        ("erin", "report_download"),
    ]

    for user_id, behavior in base_users:
        send_request(
            f"genuine:{user_id}",
            build_payload(user_id, n=1, extra=behavior),
            count=8,
            delay=0.08,
        )


def run_threat_actor_patterns():
    threat_payloads = [
        ("sql_injection", {"user_id": "alice' OR '1'='1", "foo": "SELECT * FROM users", "n": 1}),
        ("xss_script", {"user_id": "<script>alert('xss')</script>", "foo": "<img src=x onerror=alert(1)>", "n": 2}),
        ("command_injection", {"user_id": "bob; cat /etc/passwd", "foo": "$(id)", "n": 3}),
        ("path_traversal", {"user_id": "../../etc/passwd", "foo": "..\\..\\windows\\system32", "n": 4}),
        ("json_bomb", {"user_id": "mallory", "foo": "A" * 10000, "n": 5}),
        ("credential_stuffing", {"user_id": "admin", "foo": "password123", "n": 6}),
        ("auth_bypass", {"user_id": "root", "foo": "admin=true", "n": 7}),
        ("null_bytes", {"user_id": "charlie\x00", "foo": "bad\x00value", "n": 8}),
    ]

    for label, payload in threat_payloads:
        send_request(f"threat:{label}", payload, count=5, delay=0.05)


def run_authentication_tests():
    valid_headers = build_auth_header("alice", expires_in=300)
    expired_headers = build_auth_header("alice", expires_in=-60)
    wrong_alg_headers = build_auth_header("alice", alg="HS512", expires_in=300)
    malformed_headers = {"Authorization": "Token not-a-bearer-token"}
    invalid_token_headers = {"Authorization": "Bearer invalid.token.value"}

    for label, headers in [
        ("valid_jwt_hs256", valid_headers),
        ("expired_jwt_hs256", expired_headers),
        ("wrong_signing_algorithm", wrong_alg_headers),
        ("malformed_auth_scheme", malformed_headers),
        ("invalid_token_format", invalid_token_headers),
    ]:
        send_request(
            f"auth:{label}",
            build_payload("alice", n=10, extra=label),
            headers=headers,
            count=4,
            delay=0.08,
        )


def run_bulk_rampup():
    for burst in range(10):
        send_request(
            f"bulk:burst{burst}",
            build_payload(f"actor-{burst}", n=burst, extra="burst_request"),
            count=12,
            delay=0.02,
        )

    authenticated_payload = build_payload("alice", n=999, extra="steady_authenticated")
    send_request(
        "auth:bulk_valid",
        authenticated_payload,
        headers=build_auth_header("alice", expires_in=300),
        count=25,
        delay=0.03,
    )


def main():
    print("Starting request load against", GATEWAY_URL)
    print("JWT secret configured:", JWT_SECRET)
    run_genuine_traffic()
    run_threat_actor_patterns()
    run_authentication_tests()
    run_bulk_rampup()
    print("Request generation complete.")


if __name__ == "__main__":
    main()
