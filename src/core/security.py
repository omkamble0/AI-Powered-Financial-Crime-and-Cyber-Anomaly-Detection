"""
AegisFlow Platform — Enterprise Authentication & Role-Based Access Control (RBAC)
Author: Om Kamble

Implements standard JWT token lifecycle, PBKDF2 password hashing,
and granular RBAC dependencies for Analyst, Fraud Manager, Auditor, and Admin roles.
"""

import hashlib
import secrets
import socket
import ipaddress
import urllib.parse
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Dict, Any, List, Optional, Set
import jwt
from fastapi import HTTPException, Security, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from src.core.config import settings

# Security bearer scheme
security_bearer = HTTPBearer(auto_error=False)


class UserRole(str, Enum):
    ADMIN = "admin"
    FRAUD_MANAGER = "fraud_manager"
    ANALYST = "analyst"
    AUDITOR = "auditor"


# Role Hierarchy & Operational Permissions
ROLE_PERMISSIONS: Dict[UserRole, Set[str]] = {
    UserRole.ADMIN: {
        "transactions:read", "transactions:write",
        "cases:read", "cases:write", "cases:override",
        "rules:read", "rules:write",
        "models:read", "models:promote",
        "audit:read", "users:manage"
    },
    UserRole.FRAUD_MANAGER: {
        "transactions:read", "transactions:write",
        "cases:read", "cases:write", "cases:override",
        "rules:read", "rules:write",
        "models:read", "models:promote",
        "audit:read"
    },
    UserRole.ANALYST: {
        "transactions:read",
        "cases:read", "cases:write",
        "rules:read",
        "models:read",
        "audit:read"
    },
    UserRole.AUDITOR: {
        "transactions:read",
        "cases:read",
        "rules:read",
        "models:read",
        "audit:read"
    }
}


def hash_password(password: str, salt: Optional[str] = None) -> tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 (600,000 iterations in prod, 1,000 in test)."""
    if not salt:
        salt = secrets.token_hex(16)
    iterations = 1_000 if settings.is_testing else 600_000
    key = hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt.encode("utf-8"),
        iterations=iterations
    )
    return key.hex(), salt


def verify_password_with_status(password: str, stored_hash: str, salt: str) -> tuple[bool, bool]:
    """
    Verifies a plain password and reports if stored hash is legacy and needs rehash.
    Returns: (is_valid, needs_rehash)
    """
    # 1. Check modern PBKDF2-HMAC-SHA256
    new_hash, _ = hash_password(password, salt)
    if secrets.compare_digest(new_hash, stored_hash):
        return True, False
    # Check 600k iterations explicitly if test mode used 1k
    if settings.is_testing:
        key_600k = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt.encode("utf-8"), iterations=600_000).hex()
        if secrets.compare_digest(key_600k, stored_hash):
            return True, False
    # 2. Check legacy single-round SHA-256 hash
    legacy_hash = hashlib.sha256((password + salt).encode("utf-8")).hexdigest()
    if secrets.compare_digest(legacy_hash, stored_hash):
        return True, True
    return False, False


def verify_password(password: str, stored_hash: str, salt: str) -> bool:
    """Verifies a plain password against the stored PBKDF2 hash, with legacy SHA-256 fallback."""
    valid, _ = verify_password_with_status(password, stored_hash, salt)
    return valid


def validate_webhook_url(url: str, allow_private: Optional[bool] = None) -> str:
    """
    Validates a destination webhook/dispatch URL against SSRF (Server-Side Request Forgery).
    Blocks non-HTTP/S schemes, loopback (127.0.0.0/8), RFC 1918 private subnets,
    and link-local cloud metadata addresses (169.254.169.254).
    """
    if not url or not isinstance(url, str):
        raise ValueError("Webhook URL must be a non-empty string.")

    clean_url = url.strip()
    parsed = urllib.parse.urlparse(clean_url)
    if parsed.scheme.lower() not in ("http", "https"):
        raise ValueError(f"SSRF Protection: Unsupported scheme '{parsed.scheme}'. Only 'http' and 'https' are allowed.")

    hostname = parsed.hostname
    if not hostname:
        raise ValueError("SSRF Protection: URL does not specify a valid hostname.")

    # In testing mode or when explicitly allowed, skip private IP checks
    should_allow_private = allow_private if allow_private is not None else settings.is_testing
    if should_allow_private:
        return clean_url

    # Check for direct loopback or cloud metadata hostnames
    lowered_host = hostname.lower()
    if lowered_host in ("localhost", "127.0.0.1", "::1", "metadata.google.internal", "instance-data"):
        raise ValueError(f"SSRF Protection: Access to '{hostname}' is strictly prohibited.")

    # Resolve IP address to detect DNS rebinding or private IP destinations
    try:
        addr_info = socket.getaddrinfo(hostname, None)
    except socket.gaierror as e:
        raise ValueError(f"SSRF Protection: Hostname '{hostname}' could not be resolved: {e}")

    for item in addr_info:
        ip_str = item[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
            if (
                ip_obj.is_loopback
                or ip_obj.is_private
                or ip_obj.is_link_local
                or ip_obj.is_reserved
                or ip_obj.is_multicast
                or ip_obj.is_unspecified
            ):
                raise ValueError(
                    f"SSRF Protection: Destination IP '{ip_str}' belongs to a prohibited private, loopback, or metadata network."
                )
        except ValueError as ve:
            if "SSRF Protection" in str(ve):
                raise
            pass

    return clean_url




def generate_device_fingerprint_hash(
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None
) -> str:
    """
    Computes a stable cryptographic hash of client IP subnet and user agent to defend against
    session cookie / token hijacking (CWE-287 / CWE-384).
    Uses /24 subnet mask on IPv4 to allow legitimate mobile gateway hops while stopping remote relay.
    """
    ip_norm = (client_ip or "127.0.0.1").strip()
    try:
        ip_obj = ipaddress.ip_address(ip_norm)
        if ip_obj.version == 4:
            # /24 subnet grouping
            parts = ip_norm.split(".")
            subnet = ".".join(parts[:3]) if len(parts) == 4 else ip_norm
        else:
            # IPv6 /48 grouping
            subnet = ":".join(ip_norm.split(":")[:3])
    except ValueError:
        subnet = ip_norm

    ua_norm = (user_agent or "unknown").strip().lower()
    raw = f"{subnet}|{ua_norm}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def verify_token_device_binding(
    payload: Dict[str, Any],
    current_ip: Optional[str] = None,
    current_ua: Optional[str] = None
) -> tuple[bool, Optional[str]]:
    """
    Validates whether a presented JWT token matches the original issuing client fingerprint.
    Stops Trojan extensions (e.g. AggrTrade) from exfiltrating cookies for unauthorized execution.
    """
    token_dph = payload.get("dph")
    if not token_dph:
        # Token was issued without strict device binding
        return True, None

    current_dph = generate_device_fingerprint_hash(current_ip, current_ua)
    if not secrets.compare_digest(token_dph, current_dph):
        return False, (
            "SESSION_HIJACK_DETECTED: Active token presented from mismatched client IP subnet or "
            "browser fingerprint. Potential stolen session cookie or unauthorized token relay."
        )

    return True, None


def create_access_token(
    user_id: int,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None,
    client_ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    device_fingerprint: Optional[str] = None
) -> str:
    """Issues a cryptographically signed JWT access token with optional device-binding."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    )
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "access",
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    # Embed device fingerprint hash if client context is provided
    if device_fingerprint:
        payload["dph"] = device_fingerprint
    elif client_ip or user_agent:
        payload["dph"] = generate_device_fingerprint_hash(client_ip, user_agent)

    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def create_refresh_token(
    user_id: int,
    username: str,
    role: str,
    expires_delta: Optional[timedelta] = None
) -> str:
    """Issues a signed refresh token with extended validity."""
    expire = datetime.now(timezone.utc) + (
        expires_delta or timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    )
    payload = {
        "sub": str(user_id),
        "username": username,
        "role": role,
        "type": "refresh",
        "exp": expire,
        "iat": datetime.now(timezone.utc)
    }
    return jwt.encode(payload, settings.JWT_SECRET, algorithm=settings.JWT_ALGORITHM)


def decode_jwt_token(token: str) -> Dict[str, Any]:
    """Decodes and validates JWT token signature and expiration."""
    try:
        payload = jwt.decode(
            token,
            settings.JWT_SECRET,
            algorithms=[settings.JWT_ALGORITHM]
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication token has expired. Please log in again."
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token."
        )


def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Dict[str, Any]:
    """
    FastAPI dependency extracting and verifying user credentials from Authorization Bearer header.
    Falls back gracefully to session lookup or returns unauthenticated exception.
    """
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing Authorization Bearer token."
        )

    token = credentials.credentials
    # First attempt JWT decoding
    try:
        payload = decode_jwt_token(token)
        return {
            "id": int(payload["sub"]),
            "username": payload["username"],
            "role": payload.get("role", UserRole.ANALYST.value)
        }
    except HTTPException:
        # Check if it's an existing legacy database session token
        from src.db.database import get_user_by_token
        user = get_user_by_token(token)
        if user:
            return user
        raise


def get_optional_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Security(security_bearer)
) -> Optional[Dict[str, Any]]:
    """
    Safely resolves current user if Bearer token is provided.
    Returns None if unauthenticated instead of raising 401.
    """
    if not credentials or not credentials.credentials:
        return None
    try:
        return get_current_user(credentials)
    except Exception:
        return None


def require_roles(*allowed_roles: str):
    """
    RBAC dependency factory that validates whether the authenticated user possesses
    one of the required roles.
    Example: Depends(require_roles("admin", "fraud_manager"))
    """
    def _role_checker(current_user: Dict[str, Any] = Depends(get_current_user)):
        user_role_raw = current_user.get("role", "").lower().replace(" ", "_")

        # Map role aliases (e.g., 'Lead Risk Architect' -> 'admin')
        role_alias_map = {
            "lead_risk_architect": "admin",
            "risk_analyst": "analyst",
            "compliance_officer": "auditor",
            "fraud_ops_lead": "fraud_manager"
        }
        normalized_role = role_alias_map.get(user_role_raw, user_role_raw)

        allowed_normalized = [r.lower().replace(" ", "_") for r in allowed_roles]

        # Admin superuser always bypasses role check
        if normalized_role == UserRole.ADMIN.value or "admin" in allowed_normalized:
            if normalized_role == UserRole.ADMIN.value:
                return current_user

        if normalized_role not in allowed_normalized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied: Operation requires one of roles {allowed_roles}. Current role: '{current_user.get('role')}'."
            )
        return current_user

    return _role_checker
