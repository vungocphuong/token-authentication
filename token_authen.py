import hmac
import hashlib
import time
import uuid
from flask import Flask, request, abort, send_from_directory

app = Flask(__name__)
SECRET = b"mysecrettoken"

# Generate signed URL for a given UUID prefix
@app.route("/generate-link/<path:filename>")
def generate_link(filename):
    user_uuid = str(uuid.uuid4())
    prefix = f"/case-studies/{user_uuid}/"
    expires = int(time.time()) + 3600  # valid for 1h
    msg = f"{prefix}?{expires}".encode()
    signature = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    return {
        "signed_url": f"{prefix}{filename}?{expires}-{signature}"
    }

# Validate request before serving file
@app.route("/case-studies/<uuid:user_uuid>/<path:filename>")
def download_file(user_uuid, filename):
    prefix = f"/case-studies/{user_uuid}/"
    token = request.query_string.decode()
    try:
        expires, signature = token.split("-", 1)
        expires = int(expires)
    except Exception:
        abort(403, "Invalid token format")

    if time.time() > expires:
        abort(403, "Token expired")

    msg = f"{prefix}?{expires}".encode()
    expected = hmac.new(SECRET, msg, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(signature, expected):
        abort(403, "Invalid signature")

    # serve file from local ./files dir
    return send_from_directory("files", filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080)
