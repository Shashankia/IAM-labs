"""Lab settings. These values are public on purpose. This is not a production system."""

from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"

HOST = "127.0.0.1"
IDP_PORT = 8080
PORTAL_PORT = 5001
PAYROLL_PORT = 5002

IDP_BASE = f"http://{HOST}:{IDP_PORT}"
PORTAL_BASE = f"http://{HOST}:{PORTAL_PORT}"
PAYROLL_BASE = f"http://{HOST}:{PAYROLL_PORT}"
ISSUER = f"{IDP_BASE}/realms/helios"

LAB_PASSWORD = "Helios#2027"
SCIM_TOKEN = "scim-lab-token"
TOKEN_TTL_SECONDS = 600
JIT_MINUTES = 2

DEPARTMENTS = ["Engineering", "Finance", "Human Resources", "Platform"]
GROUPS = DEPARTMENTS + ["Identity"]

OIDC_CLIENTS = {
    "leave-portal": {
        "name": "Leave Portal",
        "redirect_uri": f"{PORTAL_BASE}/callback",
        "post_logout_uri": f"{PORTAL_BASE}/",
    },
    "payroll-viewer": {
        "name": "Payroll",
        "redirect_uri": f"{PAYROLL_BASE}/callback",
        "post_logout_uri": f"{PAYROLL_BASE}/",
    },
}

SAML_ENTITY_ID = f"{PORTAL_BASE}/saml/metadata"
SAML_ACS = f"{PORTAL_BASE}/saml/acs"


def data_dir() -> Path:
    override = __import__("os").environ.get("HELIOS_DATA")
    path = Path(override) if override else DATA
    path.mkdir(parents=True, exist_ok=True)
    return path


def db_path() -> Path:
    return data_dir() / "helios.sqlite"
