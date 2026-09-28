"""Organization asset lifecycle register."""

from datetime import date

from flask import Blueprint, abort, g, render_template

import db
from middleware.auth import company_required, login_required


bp = Blueprint("assets", __name__)


@bp.route("/assets")
@login_required
@company_required
def index():
    branch_id = None
    if g.admin.get("role") == "branch_admin":
        branch_id = g.admin.get("branch_id")
        if not branch_id:
            abort(403)
    assets = db.get_asset_register(g.company["id"], branch_id=branch_id)
    today = date.today().isoformat()
    return render_template(
        "assets/index.html",
        assets=assets,
        today=today,
        active_page="assets",
    )
