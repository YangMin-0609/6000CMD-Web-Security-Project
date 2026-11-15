Group 3 Django Helpdesk
Quick start for Windows

If the demo is already running, open https://localhost/ in Chrome.
For a fresh setup, download this repository and extract it. Open PowerShell
in the folder containing manage.py.

1. Install the tools and build the page assets

Install uv, Node.js and Caddy. Make sure uv, node and caddy are available
in PowerShell. If corepack is missing, run npm install --global corepack
and reopen PowerShell.

    uv python install 3.12
    uv sync --python 3.12 --dev --group test
    corepack yarn install
    & .\team-setup\build_static_windows.ps1 -ProjectRoot .

2. Prepare the demo database once

    uv run python manage.py migrate --noinput
    uv run python manage.py loaddata emailtemplate.json
    uv run python manage.py loaddata demo.json
    uv run python manage.py changepassword admin
    uv run python manage.py create_queue_permissions

Choose your own password when prompted. You can sign in as admin.

3. Start both servers

In the first PowerShell window, run:

    uv run python manage.py runserver 127.0.0.1:8091 --settings=demodesk.config.settings_local_https

In a second window, open the same project folder and run:

    caddy run --config .\team-setup\Caddyfile.local --adapter caddyfile

Keep both windows open and visit https://localhost/ in Chrome.
For later sessions, repeat Step 3. Press Ctrl+C in both windows to stop.

If Chrome shows a certificate warning

While Caddy is running, open a third PowerShell window and run caddy environ.
Find caddy.AppDataDir. If your computer allows local test certificates,
replace the placeholder with that path and run:

    certutil.exe -user -addstore Root "<Caddy.AppDataDir>\pki\authorities\local\root.crt"

Restart Chrome and check that the connection is secure before signing in.

Before trying the private ticket link

Sign in at https://localhost/admin/. Under Sites, set the domain for the
existing site to localhost. Demo emails appear in the Django terminal.

See USER-MANUAL.txt for the walkthrough. If the page is unstyled, repeat
the two asset commands in Step 1.
