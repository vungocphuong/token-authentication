import hmac
import base64
import time
import uuid
from hashlib import sha256
from flask import Flask, request, abort, send_from_directory
import urllib.parse

app = Flask(__name__)
SECRET = b"mysecrettoken"   # secret 

# --------------------------
# 1. Generate signed URL
# --------------------------
@app.route("/generate-link/<path:filename>")
def generate_link(filename):
    user_uuid = str(uuid.uuid4())
    prefix = f"/case-studies/{user_uuid}/"
    
    issued_at = str(int(time.time()))  

    # message = path + filename + expires
    msg = f"{prefix}{issued_at}".encode()
    digest = hmac.new(SECRET, msg, sha256)

    # param = verify=<expires>-<base64signature>
    signature = base64.b64encode(digest.digest()).decode()
    param = urllib.parse.urlencode({"verify": f"{issued_at}-{signature}"})

    signed_url = f"{prefix}{filename}?{param}"
    return {"signed_url": signed_url}


# --------------------------
# 2. Validate request
# --------------------------
@app.route("/case-studies/<uuid:user_uuid>/<path:filename>")
def download_file(user_uuid, filename):
    token = request.args.get("verify")
    if not token or "-" not in token:
        abort(403, "Missing or invalid token")

    try:
        issued_at_str, b64sig = token.split("-", 1)
        expires = int(issued_at_str) + 3600
    except Exception:
        abort(403, "Bad token format")

    if time.time() > expires:
        abort(403, "Token expired")

    prefix = f"/case-studies/{user_uuid}/"
    msg = f"{prefix}{issued_at_str}".encode()
    expected = base64.b64encode(
        hmac.new(SECRET, msg, sha256).digest()
    ).decode()

    if not hmac.compare_digest(b64sig, expected):
        abort(403, "Invalid signature")

    # serve file từ ./files
    return send_from_directory("files", filename)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8085)