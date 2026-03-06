from flask import Flask, request, render_template, jsonify
import os
import re

app = Flask(__name__)
FLAG = os.environ.get("FLAG", "FLAG{f1lt3r_byp4ss_xss_c0nf1rm3d}")


def sanitize(text):
    """
    Blocklist sanitizer — strips <script> and a list of common event handlers.
    Developers added the ones they knew about. They missed some.
    """
    # Strip <script> tags
    text = re.sub(r'<script.*?>.*?</script>', '', text, flags=re.IGNORECASE | re.DOTALL)

    # Strip common event handlers — developer thought this was enough
    blocked = [
        'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
        'onkeydown', 'onkeyup', 'onkeypress', 'onchange', 'onsubmit',
        'onreset', 'onselect', 'onblur', 'ondblclick', 'oncontextmenu',
    ]
    for handler in blocked:
        text = re.sub(rf'{handler}\s*=', '', text, flags=re.IGNORECASE)

    return text


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/search")
def search():
    query = request.args.get("q", "")
    sanitized = sanitize(query)
    return render_template("search.html", query=sanitized, blocked=blocked_list())


def blocked_list():
    return [
        'script', 'onerror', 'onload', 'onclick', 'onmouseover', 'onmouseout',
        'onkeydown', 'onkeyup', 'onkeypress', 'onchange', 'onsubmit',
        'onreset', 'onselect', 'onblur', 'ondblclick', 'oncontextmenu',
    ]


@app.route("/flag")
def flag():
    """
    Standard browser navigation sets 'Sec-Fetch-Dest' to 'document'.
    JavaScript 'fetch()' sets 'Sec-Fetch-Dest' to 'empty'.
    """
    dest = request.headers.get("Sec-Fetch-Dest")
    
    # If you just type /flag in the URL bar, 'dest' will be 'document'
    if dest == "document" or not dest:
        return "<h2>Access Denied</h2><p>Direct navigation is blocked. You must use a script to fetch this resource.</p>", 403
    
    return jsonify({"flag": FLAG})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
