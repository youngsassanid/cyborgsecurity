import html
import subprocess

from flask import Blueprint

from web.auth import requires_auth

assets_bp = Blueprint("assets", __name__)


@assets_bp.route("/test")
@requires_auth
def run_tests():
    try:
        result = subprocess.run(
            ["python", "-m", "unittest", "discover", "-s", "tests", "-v"],
            capture_output=True,
            text=True,
        )
        output = html.escape(result.stdout + result.stderr)
        status = "All tests passed!" if result.returncode == 0 else "Some tests failed."
    except Exception as e:
        output = str(e)
        status = "Test execution failed."

    return f"""
    <html><head><style>
        body {{ background:#001a00; color:#00ff41; font-family:monospace; padding:20px; }}
        pre {{ background:#000; padding:15px; border-radius:8px; overflow:auto; }}
    </style></head><body>
        <h2>Unit Test Results</h2>
        <p>{status}</p>
        <pre>{output}</pre>
        <a href="/dashboard" style="color:#00aaff;">← Back to Dashboard</a>
    </body></html>
    """
