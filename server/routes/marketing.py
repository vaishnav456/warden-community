"""Public landing page for Warden Community."""
from flask import Blueprint, g, render_template

import config

bp = Blueprint("marketing", __name__)


@bp.route("/")
def index():
    return render_template(
        "landing.html",
        canonical_url=f"{config.SERVER_URL.rstrip('/')}/",
        console_url="/dashboard",
        github_url="https://github.com/vaishnav456/warden-community",
        trial_enabled=True,
        trial_url="https://warden.uranledgr.com/trial",
        current_user=g.get("admin"),
    )
