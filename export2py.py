"""Export flow to python requests."""

from mitmproxy import flow
from mitmproxy.addons.export import formats, cleanup_request, pop_headers


def python_script(f: flow.Flow) -> str:
    request = cleanup_request(f)
    request = pop_headers(request)

    url = repr(request.pretty_url)
    method = request.method.lower()
    headers = repr({k: v for k, v in request.headers.items(multi=True)})

    try:
        body = repr(request.get_text(strict=True))
    except ValueError:
        body = repr(request.get_content(strict=False))

    script = f"requests.{method}({url}, headers={headers}, data={body})"
    return script


formats["python_requests"] = python_script
