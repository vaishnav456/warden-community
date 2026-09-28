"""
Warden — MFA (TOTP) service
"""
import pyotp
import secrets


def generate_secret() -> str:
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str, issuer: str = "Warden") -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=email, issuer_name=issuer)


def verify_totp(secret: str, code: str) -> bool:
    """Verify a 6-digit TOTP code. Allows ±1 window (30s drift)."""
    try:
        totp = pyotp.TOTP(secret)
        return totp.verify(code, valid_window=1)
    except Exception:
        return False


def generate_backup_codes(n: int = 8) -> list[str]:
    """Generate one-time backup codes."""
    return [secrets.token_hex(5).upper() for _ in range(n)]
