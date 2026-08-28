"""
Minimal dummy backend used only to verify the proxy passes requests
through correctly end-to-end. Not part of the proxy itself.
"""

from flask import Flask, request, jsonify, make_response

app = Flask(__name__)


@app.route("/", methods=["GET"])
def index():
    return jsonify(route="/", message="dummy backend home"), 200


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        body = request.get_json(silent=True) or request.form.to_dict()
        return jsonify(route="/login", method="POST", received=body), 200
    return jsonify(route="/login", method="GET"), 200


@app.route("/search", methods=["GET"])
def search():
    q = request.args.get("q", "")
    resp = make_response(jsonify(route="/search", query=q))
    # Set a cookie so we can verify cookie passthrough works both
    # directions (client -> proxy -> backend and back again).
    resp.set_cookie("session_test", "dummy-value")
    return resp, 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
