"""
Fake web app. Everything here is a decoy: /login never checks the
submitted credentials against anything real (there's nothing to check
against — no user database exists in this process), /admin never
grants access to anything, and no route ever reads from or touches
the real backend or its data. The only thing every route does is
look plausible and log what was sent.

Every request that reaches ANY route in this app is logged with full
detail via a single before_request hook, rather than each route
calling the logger separately — that way a new route added later is
covered automatically, and the log schema can't drift route-to-route.
"""

from flask import Flask, request, Response, render_template_string

from honeypot.logger import log_honeypot_event

app = Flask(__name__)


def _event_type_for(path, method):
    if path == "/login":
        return "http_login_attempt" if method == "POST" else "http_login_page_view"
    if path == "/admin":
        return "http_admin_probe"
    if path == "/":
        return "http_index_probe"
    return "http_unknown_path_probe"


@app.before_request
def _log_every_request():
    # request.form / request.get_json are safe to call here even though
    # a route handler will also touch the request later — Flask caches
    # both, so this doesn't consume the body stream for the handler.
    parsed_params = None
    if request.form:
        parsed_params = dict(request.form)
    else:
        parsed_params = request.get_json(silent=True)

    log_honeypot_event(
        _event_type_for(request.path, request.method),
        request.remote_addr,
        {
            "method": request.method,
            "path": request.path,
            "query_string": request.query_string.decode("utf-8", errors="ignore"),
            "headers": dict(request.headers),
            "body": request.get_data(as_text=True) or "",
            "params": parsed_params,
        },
    )


# Never render user input through a template with autoescape off, and
# never pass it to eval/exec/subprocess/etc — a honeypot that's itself
# exploitable defeats the point and is a real risk, not a fake one.
# render_template_string below only ever renders our own fixed HTML.

_LOGIN_PAGE = """
<!doctype html>
<title>Admin Login</title>
<h2>Administrator Login</h2>
<form method="post">
  <label>Username: <input type="text" name="username"></label><br>
  <label>Password: <input type="password" name="password"></label><br>
  <button type="submit">Sign in</button>
</form>
{% if show_error %}<p style="color:red">Invalid username or password.</p>{% endif %}
"""


@app.route("/", methods=["GET"])
def fake_index():
    return render_template_string(
        "<!doctype html><title>Dashboard</title>"
        "<h2>Internal Dashboard</h2>"
        '<p><a href="/login">Sign in</a> to continue.</p>'
    )


@app.route("/login", methods=["GET", "POST"])
def fake_login():
    if request.method == "POST":
        # Submitted credentials are logged (by the before_request hook
        # above, via `params`) and then discarded — never compared
        # against anything, never stored anywhere else, never used to
        # grant access to anything.
        return render_template_string(_LOGIN_PAGE, show_error=True), 401
    return render_template_string(_LOGIN_PAGE, show_error=False)


@app.route("/admin", methods=["GET", "POST"])
def fake_admin():
    # Looks like a weakly-protected admin panel to bait further
    # probing, but never actually serves any admin functionality.
    return Response(
        "<!doctype html><title>403 Forbidden</title>"
        "<h1>403 Forbidden</h1>"
        "<p>You don't have permission to access /admin on this server.</p>",
        status=403,
        mimetype="text/html",
    )


@app.route("/<path:path>")
def fake_catch_all(path):
    # Any other path still gets logged (via before_request) and still
    # gets a plausible 404 rather than Flask's default debug-looking
    # page — a real app wouldn't reveal it's Flask.
    return Response(
        "<!doctype html><title>404 Not Found</title>"
        "<h1>404 Not Found</h1>",
        status=404,
        mimetype="text/html",
    )
