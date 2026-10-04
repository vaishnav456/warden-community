"""Encrypted SMTP configuration, durable delivery and opt-in event mail."""
import hashlib
import json
import logging
import re
import secrets
import smtplib
import ssl
import threading
import time
import uuid
from datetime import datetime, timedelta, timezone
from email.message import EmailMessage
from email.utils import formataddr
from urllib.parse import urlsplit
from pathlib import Path
from jinja2 import Environment, FileSystemLoader, select_autoescape

import config
import db
from services.platform_secrets import encrypt_platform_field, decrypt_platform_field

SCOPE_MODE = "company"
CATEGORIES = {
    "alerts_critical": "Critical alerts",
    "alerts_other": "Warning alerts",
    "approvals": "Approval requests and decisions",
    "jobs_failed": "Failed jobs",
    "jobs_completed": "Completed jobs",
    "home_sync": "Home synchronization results",
    "updates": "Agent updates and build results",
    "general": "Other in-app notifications",
}
log = logging.getLogger("warden.mail")


def scope_key(company_id=None):
    return "platform" if SCOPE_MODE == "platform" else "company:" + str(company_id) if company_id else None


def address(value):
    value = str(value or "").strip()
    if len(value) > 254 or not re.fullmatch(r"[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", value):
        raise ValueError("Enter a valid email address")
    return value


def validate_settings(body, previous=None):
    previous = previous or {}
    if not isinstance(body, dict):
        raise ValueError("Invalid SMTP settings")
    host = str(body.get("host") or "").strip()
    if not host or len(host) > 253 or re.search(r"[\s/@\\]", host) or "://" in host:
        raise ValueError("Enter an SMTP hostname or IP address, without a URL")
    try:
        port = int(str(body.get("port", "587")))
    except ValueError:
        raise ValueError("Enter a valid SMTP port") from None
    if not 1 <= port <= 65535:
        raise ValueError("Enter a port from 1 to 65535")
    mode = body.get("mode", "starttls")
    if mode not in ("starttls", "tls"):
        raise ValueError("Use STARTTLS or TLS; unencrypted SMTP is not supported")
    username = str(body.get("username") or "").strip()
    password = str(body.get("password") or "")
    # Google displays app passwords in four groups. Strip that display
    # formatting only for Google's SMTP endpoint; spaces in other providers'
    # passwords must remain untouched.
    if host.casefold() == "smtp.gmail.com" and re.fullmatch(r"[A-Za-z0-9]{4}(?: [A-Za-z0-9]{4}){3}", password):
        password = password.replace(" ", "")
    if not password and not body.get("clear_password"):
        if host == previous.get("host") and username == previous.get("username"):
            password = previous.get("password") or ""
    if len(username) > 512 or len(password) > 2048 or "\n" in username or "\r" in username:
        raise ValueError("Invalid SMTP credentials")
    if username and not password:
        raise ValueError("Enter the SMTP password for this server/account")
    name = str(body.get("from_name") or "Warden").strip()
    if len(name) > 120 or "\n" in name or "\r" in name:
        raise ValueError("Invalid sender name")
    enabled = body.get("enabled", False)
    if not isinstance(enabled, bool):
        raise ValueError("Invalid enabled option")
    return dict(host=host, port=port, mode=mode, username=username, password=password,
                from_email=address(body.get("from_email")), from_name=name, enabled=enabled)


def get_settings(company_id=None):
    key = scope_key(company_id)
    if not key:
        return None
    rows = db._get("mail_settings?scope_key=eq." + db._q(key) + "&limit=1")
    if not rows:
        return None
    return json.loads(decrypt_platform_field(key, "smtp.config", rows[0]["config_encrypted"]))


def save_settings(company_id, actor_id, settings):
    key = scope_key(company_id)
    return db._post("mail_settings?on_conflict=scope_key", {
        "scope_key": key, "company_id": company_id if SCOPE_MODE == "company" else None,
        "config_encrypted": encrypt_platform_field(key, "smtp.config", json.dumps(settings)),
        "updated_by": actor_id, "updated_at": db._now_iso(),
    }, prefer="resolution=merge-duplicates,return=minimal")


def public_settings(settings):
    result = dict(settings or {})
    result["password_saved"] = bool(result.pop("password", ""))
    return result


def base_url():
    base = str(config.SERVER_URL).rstrip("/")
    parsed = urlsplit(base)
    if parsed.scheme not in ("https", "http") or not parsed.hostname or parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ValueError("Configure a valid SERVER_URL")
    if parsed.scheme != "https" and parsed.hostname not in ("localhost", "127.0.0.1", "::1"):
        raise ValueError("Email links require HTTPS except for localhost development")
    return base


def render_email(subject, text, category, template="notification", action_url=None, action_label="Open Warden", expiry_notice=""):
    if template not in ("notification", "welcome", "password_reset", "identity_setup"):
        raise ValueError("Unknown email template")
    base = base_url()
    if action_url and not action_url.startswith(base + "/"):
        raise ValueError("Email actions must use the configured Warden URL")
    environment = Environment(loader=FileSystemLoader(str(Path(__file__).resolve().parents[1] / "templates")),
                              autoescape=select_autoescape(["html"]))
    paragraphs = [part for part in text.split("\n\n") if part and part != action_url]
    return environment.get_template("email/" + template + ".html").render(
        subject=subject, paragraphs=paragraphs, server_url=base, action_url=action_url,
        action_label=action_label, expiry_notice=expiry_notice, optional=category not in ("security", "test"))


def send(settings, recipient, subject, text, message_id=None, html=None):
    if not settings or not settings.get("enabled"):
        raise ValueError("SMTP is disabled")
    if settings.get("mode") not in ("starttls", "tls"):
        raise ValueError("Unencrypted SMTP is not supported")
    recipient = address(recipient)
    if "\r" in subject or "\n" in subject:
        raise ValueError("Invalid message subject")
    message = EmailMessage()
    message["From"] = formataddr((settings["from_name"], address(settings["from_email"])))
    message["To"] = recipient
    message["Subject"] = subject[:180]
    message["Message-ID"] = "<" + str(message_id or uuid.uuid4()) + "@warden-mail>"
    message.set_content(text)
    if html:
        message.add_alternative(html, subtype="html")
    context = ssl.create_default_context()
    transport = smtplib.SMTP_SSL if settings["mode"] == "tls" else smtplib.SMTP
    kwargs = dict(host=settings["host"], port=settings["port"], timeout=15)
    if settings["mode"] == "tls":
        kwargs["context"] = context
    with transport(**kwargs) as client:
        client.ehlo()
        if settings["mode"] == "starttls":
            client.starttls(context=context)  # required, never opportunistic
            client.ehlo()
        if settings.get("username"):
            client.login(settings["username"], settings["password"])
        rejected = client.send_message(message)
        if rejected:
            raise smtplib.SMTPRecipientsRefused(rejected)


def allowed(admin, category, company_id, branch_id=None):
    if not admin or not admin.get("is_active") or str(admin.get("company_id") or "") != str(company_id or ""):
        return False
    if category in ("security", "test"):
        return True
    if admin.get("role") == "branch_admin" and (not branch_id or str(admin.get("branch_id")) != str(branch_id)):
        return False
    if category == "approvals" and admin.get("role") not in ("company_admin", "branch_admin", "superadmin"):
        return False
    prefs = admin.get("notification_prefs") or {}
    selected = prefs.get("email_categories") if isinstance(prefs.get("email_categories"), dict) else {}
    return selected.get(category, category in ("alerts_critical", "jobs_failed")) is True


def enqueue(admin, category, subject, text, event_key=None, branch_id=None, expires_at=None, identity=None, guard=None,
            template="notification", action_url=None, action_label="Open Warden", expiry_notice=""):
    company_id = identity.get("company_id") if identity else admin.get("company_id")
    settings = get_settings(company_id)
    if not settings or not settings.get("enabled"):
        return False
    recipient = identity.get("login_email") if identity else admin.get("email")
    recipient = address(recipient)
    mid = str(uuid.uuid4())
    payload = dict(to=recipient, subject=subject, text=text, guard=guard,
                   html=render_email(subject, text, category, template, action_url, action_label, expiry_notice))
    db._post("mail_outbox?on_conflict=event_key", {
        "id": mid, "event_key": event_key or mid, "company_id": company_id,
        "branch_id": branch_id, "admin_id": admin["id"] if admin else None,
        "identity_id": identity["id"] if identity else None,
        "category": category, "payload_encrypted": encrypt_platform_field(mid, "mail.payload", json.dumps(payload)),
        "expires_at": expires_at or (datetime.now(timezone.utc)+timedelta(days=1)).isoformat(),
    }, prefer="resolution=ignore-duplicates,return=minimal")
    return True


def request_reset(admin):
    if not admin or not admin.get("is_active") or not (get_settings(admin.get("company_id")) or {}).get("enabled"):
        return False
    recovery_base = base_url()  # validate before invalidating any prior recovery link
    token = secrets.token_urlsafe(32)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    accepted = db._rpc("request_admin_password_reset", {
        "p_admin_id": admin["id"], "p_token_hash": token_hash,
        "p_email_hash": hashlib.sha256(admin["email"].lower().encode()).hexdigest(),
        "p_token_version": int(admin.get("access_token_version") or 0),
    })
    if not accepted:
        return False
    # Fragment is not sent in HTTP requests or referrer headers.
    link = recovery_base + "/auth/reset-password#token=" + token
    return enqueue(admin, "security", "Reset your Warden password",
                   "A password reset was requested for your Warden account.\n\n" + link +
                   "\n\nThis single-use link expires in 30 minutes. Your current password remains unchanged until you complete the reset. "
                   "If you did not request this, you can ignore this email. MFA settings remain unchanged.",
                   event_key="reset:" + token_hash,
                   expires_at=(datetime.now(timezone.utc)+timedelta(minutes=30)).isoformat(),
                   guard={"reset_hash": token_hash}, template="password_reset", action_url=link, action_label="Reset password")


def identity_link(identity, token, expires_at):
    try:
        link = base_url() + "/identity/setup/" + token
        return enqueue(None, "security", "Set your Warden identity password",
                       "Use this single-use link to set your Warden identity password:\n\n" + link +
                       "\n\nThe link expires at " + expires_at + ". Do not forward it.",
                       identity=identity, expires_at=expires_at,
                       guard={"identity_setup_hash": hashlib.sha256(token.encode()).hexdigest()},
                       template="identity_setup", action_url=link, action_label="Choose your password",
                       expiry_notice="Expires at " + expires_at + ".")
    except Exception as exc:
        log.warning("Identity setup email not queued (%s)", type(exc).__name__)
        return False


def _finish(row, claim, status, code, delay=0):
    fields = dict(status=status, result_code=code, claim_token=None, lease_until=None)
    if status in ("sent", "failed", "skipped"):
        fields["payload_encrypted"] = None
    if status == "sent":
        fields["sent_at"] = db._now_iso()
    if delay:
        fields["available_at"] = (datetime.now(timezone.utc)+timedelta(seconds=delay)).isoformat()
    db._patch("mail_outbox?id=eq." + db._q(row["id"]) + "&claim_token=eq." + db._q(claim), fields)


def deliver_one():
    claim = str(uuid.uuid4())
    rows = db._rpc("claim_mail_message", {"p_claim": claim}) or []
    if not rows:
        return False
    row = rows[0]
    try:
        payload = json.loads(decrypt_platform_field(row["id"], "mail.payload", row["payload_encrypted"]))
        if row.get("admin_id"):
            recipient = db.get_admin_by_id(row["admin_id"])
            permitted = allowed(recipient, row["category"], row.get("company_id"), row.get("branch_id"))
            current_email = (recipient or {}).get("email")
        else:
            recipient = db.get_warden_identity(row.get("identity_id"), row["company_id"])
            permitted = bool(recipient and recipient.get("is_enabled", True))
            current_email = (recipient or {}).get("login_email")
        if not permitted or str(current_email).casefold() != payload["to"].casefold():
            _finish(row, claim, "skipped", "recipient_or_preferences_changed")
            return True
        guard = payload.get("guard") or {}
        if guard.get("reset_hash"):
            tokens = db._get("admin_password_reset_tokens?token_hash=eq." + db._q(guard["reset_hash"]) +
                             "&consumed_at=is.null&expires_at=gt." + db._q(db._now_iso()) + "&limit=1")
            if not tokens or int(recipient.get("access_token_version") or 0) != tokens[0]["token_version"]:
                _finish(row, claim, "skipped", "reset_superseded")
                return True
        if guard.get("identity_setup_hash") and recipient.get("password_setup_token_hash") != guard["identity_setup_hash"]:
            _finish(row, claim, "skipped", "reset_superseded")
            return True
        settings = get_settings(row.get("company_id"))
        if not settings or not settings.get("enabled"):
            _finish(row, claim, "skipped", "smtp_disabled")
            return True
        send(settings, payload["to"], payload["subject"], payload["text"], row["id"], html=payload.get("html"))
        _finish(row, claim, "sent", "smtp_accepted")
    except Exception as exc:
        # Never persist/log provider text: servers can echo addresses/secrets.
        code = ("authentication_failed" if isinstance(exc, smtplib.SMTPAuthenticationError)
                else "recipient_rejected" if isinstance(exc, smtplib.SMTPRecipientsRefused)
                else "tls_failed" if isinstance(exc, ssl.SSLError)
                else "delivery_failed")
        permanent = code in ("authentication_failed", "recipient_rejected", "tls_failed") or row["attempts"] >= 6
        _finish(row, claim, "failed" if permanent else "pending", code,
                0 if permanent else min(1800, 30 * 2**row["attempts"]))
    return True


def event_copy(event):
    kind = event["kind"]
    if kind == "account_created":
        return "Welcome to Warden", ("Your administrator account is ready. Sign in to your organization workspace. "
                "Your administrator controls the devices and actions available to your role. "
                "If you have not received a password, use Forgot password on the sign-in page. "
                "No password is included in this email."), "/login"
    if kind in ("password_changed", "email_changed", "mfa_changed", "account_created"):
        label = {"password_changed": "Your Warden password changed", "email_changed": "Your Warden login email changed",
                 "mfa_changed": "Your Warden MFA configuration changed", "account_created": "Welcome to Warden"}[kind]
        return label, label + ". If this was unexpected, contact your administrator.", "/login"
    if kind.startswith("approval_"):
        return "Warden approval: " + kind[9:].replace("_", " "), "An approval request needs review or has a new decision.", "/escalations"
    if kind.startswith("job_"):
        label = "Warden task failed" if kind == "job_failed" else "Warden task completed"
        if event["category"] == "home_sync":
            label = "Warden Home sync failed" if kind == "job_failed" else "Warden Home sync completed"
        return label, "Review the device-reported result in Warden. Sensitive output is not included in this email.", "/jobs/" + str(event["record_id"])
    if kind.startswith("build_"):
        return "Warden build " + kind[6:], "Review the installer build result in Warden.", "/settings/builds"
    if kind == "alert":
        return "Warden alert needs attention", "A " + ("critical" if event["category"] == "alerts_critical" else "warning") + " alert was reported. Sign in to review the latest status.", "/alerts"
    return "New Warden notification", "A new notification is available in your Warden workspace.", "/dashboard"


def _paged(path):
    yield from db._get_all(path + "&order=id.asc", page_size=200)


def fanout_one():
    claim = str(uuid.uuid4())
    rows = db._rpc("claim_mail_event", {"p_claim": claim}) or []
    if not rows:
        return False
    event = rows[0]
    try:
        return _fanout_event(event, claim)
    except Exception:
        # Do not log provider text, recipient data or security URLs.
        attempts = int(event.get("attempts") or 1)
        fields = dict(claim_token=None, lease_until=None, result_code="fanout_failed")
        if attempts >= 6:
            fields["dead_lettered_at"] = db._now_iso()
        else:
            fields["available_at"] = (datetime.now(timezone.utc) +
                                      timedelta(seconds=min(1800, 30 * 2**attempts))).isoformat()
        db._patch("mail_events?id=eq." + db._q(event["id"]) + "&claim_token=eq." + db._q(claim), fields)
        log.warning("Mail event deferred after attempt %d", attempts)
        return True


def _fanout_event(event, claim):
    if event.get("admin_id"):
        admins = [db.get_admin_by_id(event["admin_id"])]
    else:
        admins = _paged("admin_users?company_id=eq." + db._q(event["company_id"]) +
                         "&is_active=eq.true&select=id,email,company_id,role,branch_id,is_active,notification_prefs")
    subject, text, path = event_copy(event)
    for admin in admins:
        if allowed(admin, event["category"], event.get("company_id"), event.get("branch_id")):
            enqueue(admin, event["category"], subject, text + "\n\n" + base_url() + path,
                    branch_id=event.get("branch_id"), event_key=str(event["id"]) + ":" + str(admin["id"]),
                    expires_at=event["expires_at"],
                    template="welcome" if event["kind"] == "account_created" else "notification",
                    action_url=base_url() + path,
                    action_label="Sign in to Warden" if event["category"] == "security" else "Review in Warden")
    db._patch("mail_events?id=eq." + db._q(event["id"]) + "&claim_token=eq." + db._q(claim),
              {"processed": True, "claim_token": None, "lease_until": None})
    return True


def cleanup():
    cutoff = (datetime.now(timezone.utc)-timedelta(days=7)).isoformat()
    db._delete("mail_outbox?created_at=lt." + db._q(cutoff) + "&status=in.(sent,failed,skipped)")
    db._delete("mail_events?expires_at=lt." + db._q(db._now_iso()) + "&dead_lettered_at=is.null")
    db._delete("mail_events?dead_lettered_at=lt." + db._q(cutoff))
    db._delete("admin_password_reset_tokens?expires_at=lt." + db._q(db._now_iso()))


def _loop():
    from services.lifecycle import stopping
    loops = 0
    while not stopping.wait(10):
        try:
            for _ in range(10):
                if stopping.is_set():
                    break
                if not fanout_one():
                    break
            for _ in range(10):
                if stopping.is_set():
                    break
                if not deliver_one():
                    break
            loops += 1
            if loops % 360 == 0:
                cleanup()
        except Exception as exc:
            log.warning("Mail worker deferred (%s)", type(exc).__name__)


def start():
    threading.Thread(target=_loop, name="smtp-outbox", daemon=True).start()
