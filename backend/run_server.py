"""Single entry point for the packaged backend.

Frozen by PyInstaller into a standalone binary so the Electron app can bundle
the whole Python backend — the end user needs no Python install. The same
binary also serves the captive-portal subprocess: when app.eviltwin needs the
portal it re-invokes this executable with `--portal ...` (see portal_command),
because a frozen binary can't `python -m app.portal`.
"""

import sys


def main() -> None:
    argv = sys.argv[1:]
    if argv and argv[0] == "--portal":
        # dispatch: run_server --portal <port> <creds_file> [ssid]
        from app import portal

        sys.argv = ["portal", *argv[1:]]
        portal.main()
        return

    import uvicorn

    from app.main import app

    port = int(argv[0]) if argv else 8000
    uvicorn.run(app, host="127.0.0.1", port=port)


if __name__ == "__main__":
    main()
