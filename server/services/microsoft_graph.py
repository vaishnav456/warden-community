"""Minimal Microsoft Graph client for tenant-owned Entra/Intune credentials.

Access tokens are requested on demand and never persisted. The caller stores
only the encrypted app-registration inputs through db.save_tenant_integration.
"""
import json
import urllib.error
import urllib.parse
import urllib.request


TOKEN_SCOPE = "https://graph.microsoft.com/.default"


class MicrosoftGraphError(Exception):
    pass


def _error_message(exc, secret=""):
    message = str(exc)
    if isinstance(exc, urllib.error.HTTPError):
        try:
            payload = json.loads(exc.read().decode("utf-8", errors="replace"))
            error = payload.get("error") or {}
            if isinstance(error, str):
                message = payload.get("error_description") or error
            else:
                message = error.get("message") or error.get("error_description") or message
        except Exception:
            pass
    if secret:
        message = message.replace(secret, "[redacted]")
    return message[:500]


def _json_request(url, *, data=None, headers=None, secret=""):
    request_headers = {"Accept": "application/json", **(headers or {})}
    req = urllib.request.Request(url, data=data, headers=request_headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            return json.loads(response.read().decode("utf-8"))
    except (urllib.error.HTTPError, urllib.error.URLError, TimeoutError, ValueError) as exc:
        raise MicrosoftGraphError(_error_message(exc, secret)) from exc


def acquire_access_token(tenant_id, client_id, client_secret):
    body = urllib.parse.urlencode({
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": TOKEN_SCOPE,
        "grant_type": "client_credentials",
    }).encode("utf-8")
    payload = _json_request(
        f"https://login.microsoftonline.com/{urllib.parse.quote(tenant_id, safe='')}/oauth2/v2.0/token",
        data=body,
        headers={"Content-Type": "application/x-www-form-urlencoded"},
        secret=client_secret,
    )
    token = payload.get("access_token")
    if not token:
        raise MicrosoftGraphError("Microsoft did not return an access token")
    return token


def test_connection(integration_config):
    tenant_id = integration_config["tenant_id"]
    client_id = integration_config["client_id"]
    client_secret = integration_config["client_secret"]
    token = acquire_access_token(tenant_id, client_id, client_secret)
    auth = {"Authorization": f"Bearer {token}"}

    organization = _json_request(
        "https://graph.microsoft.com/v1.0/organization"
        "?$select=id,displayName,verifiedDomains",
        headers=auth,
        secret=client_secret,
    )
    organizations = organization.get("value") or []
    if not organizations:
        raise MicrosoftGraphError(
            "No organization was returned. Grant Organization.Read.All application permission and admin consent."
        )
    org = organizations[0]
    if str(org.get("id", "")).lower() != str(tenant_id).lower():
        raise MicrosoftGraphError("Connected organization does not match the configured tenant ID")

    autopilot = _json_request(
        "https://graph.microsoft.com/v1.0/deviceManagement/"
        "windowsAutopilotDeviceIdentities?$top=1&$select=id,serialNumber",
        headers=auth,
        secret=client_secret,
    )
    domains = [
        item.get("name") for item in (org.get("verifiedDomains") or [])
        if item.get("isDefault") and item.get("name")
    ]
    return {
        "organization_id": org.get("id"),
        "organization_name": org.get("displayName") or "Microsoft Entra tenant",
        "default_domain": domains[0] if domains else None,
        "autopilot_access": isinstance(autopilot.get("value"), list),
    }


def list_autopilot_devices(integration_config, limit=10000):
    """Return normalized Autopilot identities, following Graph pagination."""
    token = acquire_access_token(
        integration_config["tenant_id"],
        integration_config["client_id"],
        integration_config["client_secret"],
    )
    headers = {"Authorization": f"Bearer {token}"}
    url = (
        "https://graph.microsoft.com/v1.0/deviceManagement/"
        "windowsAutopilotDeviceIdentities"
        "?$top=100&$select=id,serialNumber,azureActiveDirectoryDeviceId,displayName,groupTag"
    )
    devices = []
    while url and len(devices) < limit:
        if not url.startswith("https://graph.microsoft.com/"):
            raise MicrosoftGraphError("Microsoft returned an invalid pagination URL")
        payload = _json_request(
            url, headers=headers,
            secret=integration_config["client_secret"],
        )
        for item in payload.get("value") or []:
            normalized = {
                "provider_device_id": str(item.get("id") or "").strip(),
                "serial_number": str(item.get("serialNumber") or "").strip(),
                "entra_device_id": str(item.get("azureActiveDirectoryDeviceId") or "").strip(),
                "display_name": str(item.get("displayName") or "").strip(),
                "group_tag": str(item.get("groupTag") or "").strip(),
            }
            if any(normalized[key] for key in ("provider_device_id", "serial_number", "entra_device_id")):
                devices.append(normalized)
                if len(devices) >= limit:
                    break
        url = payload.get("@odata.nextLink")
    return devices
