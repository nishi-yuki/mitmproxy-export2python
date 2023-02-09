"""Export flow to python requests."""

from mitmproxy import flow
from mitmproxy.addons import export


def python_script(f: flow.Flow) -> str:
    request = export.cleanup_request(f)
    request = export.pop_headers(request)

    url = repr(request.pretty_url)
    method = request.method.lower()
    headers = repr({k: v for k, v in request.headers.items(multi=True)})

    try:
        body = repr(request.get_text(strict=True))
    except ValueError:
        body = repr(request.get_content(strict=False))

    script = f"requests.{method}({url}, headers={headers}, data={body})"
    return script


class Export2Python:
    def running(self):
        export.formats["python_requests"] = python_script


addons = [Export2Python()]
