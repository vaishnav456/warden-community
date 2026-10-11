"""Independent private entry point; no import of the Warden server application."""
import os
from warden_admin.web import create_app

app = create_app(os.environ["WARDEN_ADMIN_VAULT"], os.environ["WARDEN_ADMIN_ARCHIVE"],
                 os.environ["WARDEN_ADMIN_CHECKPOINT"])
