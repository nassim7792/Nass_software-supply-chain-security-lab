"""A small FastAPI app that depends on `internal-auth-utils`.

The app itself is unremarkable. The point is what already happened *before* this
code ever ran: installing the dependency fired the impostor package's hook, and
importing it below runs attacker-controlled code at process start.
"""
import os

from fastapi import FastAPI

# This import triggers internal_auth_utils' import-time hook (see its __init__).
import internal_auth_utils

app = FastAPI(title="target-app", version="0.1.0")


@app.get("/")
def root():
    return {
        "app": "target-app",
        "internal_auth_utils_version": getattr(internal_auth_utils, "__version__", "?"),
        "note": "If this says 99.0.0, the impostor won resolution.",
    }


@app.get("/whoami")
def whoami():
    # Uses the (fake) dependency API — the realistic reason the app imported it.
    token = internal_auth_utils.get_token(service="demo")
    return {"token": token, "db": os.environ.get("DATABASE_URL", "unset")}


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)
