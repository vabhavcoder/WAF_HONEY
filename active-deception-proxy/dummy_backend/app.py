"""Small backend application for testing the reverse proxy."""
from flask import Flask, jsonify, request

app = Flask(__name__)


@app.get("/")
def index():
    return jsonify(message="Hello from the dummy backend")


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        return jsonify(message="Login request received", form=request.form.to_dict())
    return jsonify(message="Send a POST request to test login passthrough")


@app.get("/search")
def search():
    return jsonify(query=request.args.get("q", ""), message="Search request received")


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=False)
