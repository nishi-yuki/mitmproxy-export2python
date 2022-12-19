"""Export flow to python requests."""
import logging

import pyperclip

import mitmproxy.types
from mitmproxy import command
from mitmproxy import flow
from mitmproxy.addons.export import cleanup_request, pop_headers


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


class Export2py:
    @command.command("export2py.file")
    def file(self, flow: flow.Flow, path: mitmproxy.types.Path) -> None:
        """
        Export a flow to path.
        """
        script = python_script(flow)
        try:
            with open(path, "w") as f:
                    f.write(script)
        except OSError as e:
            logging.error(str(e))

    @command.command("export2py.clip")
    def clip(self, f: flow.Flow) -> None:
        """
        Export a flow to the system clipboard.
        """
        try:
            pyperclip.copy(python_script(f))
        except pyperclip.PyperclipException as e:
            logging.error(str(e))

    @command.command("export2py")
    def export_str(self, f: flow.Flow) -> str:
        """
        Export a flow to python.
        """
        return python_script(f)


addons = [Export2py()]
