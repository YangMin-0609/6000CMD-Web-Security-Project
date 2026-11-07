# Django Helpdesk Team Setup Guide for Windows and VS Code

This guide is for teammates who have **VS Code but have not set up the Django project yet**. Run the commands in a **PowerShell terminal** inside VS Code. Each member should use their own local development database.

> **Coordinator:** This folder is part of the [group GitHub repository](https://github.com/YangMin-0609/6000CMD-Web-Security-Project). Members should clone the group repository, not the latest version of the upstream project. These steps are based on the assessed `v2.3.3` demo project. Ask one teammate to verify the instructions with a fresh clone before the whole group relies on them.

## 1. Install the required software once

1. Install [Git for Windows](https://git-scm.com/install/windows).
2. Install [Node.js LTS](https://nodejs.org/en/download). The project uses Node.js to install its front-end CSS and JavaScript packages.
3. In VS Code, install the Microsoft **Python** extension. The extension does not install Python itself; `uv` will install the version used by this project.
4. Open PowerShell and install [`uv`](https://docs.astral.sh/uv/getting-started/installation/):

   ```powershell
   winget install --id=astral-sh.uv -e
   ```

5. **Close and reopen VS Code.** In a new terminal, check that all tools are available:

   ```powershell
   git --version
   uv --version
   node --version
   npm --version
   ```

   If any command says `not recognized`, check that the software installed successfully and restart the terminal before continuing.

## 2. Clone the group repository

In PowerShell, go to the folder where you want to keep the project. Then run:

```powershell
git clone https://github.com/YangMin-0609/6000CMD-Web-Security-Project.git
cd 6000CMD-Web-Security-Project
```

You should now see `manage.py`, `pyproject.toml`, `package.json`, and `team-setup` in the project root. In VS Code, use **File → Open Folder** to open this project folder.

## 3. Install Python and Django dependencies once

From the **project root**, run:

```powershell
uv python install 3.12
uv sync --python 3.12 --dev --group test
```

`uv` creates a project-specific `.venv` and installs the dependencies. You do not need to install Django separately or activate the virtual environment. The project declares support for Python 3.10 and later; the group will use Python 3.12 to keep environments consistent.

## 4. Install front-end assets once

The project's `package.json` specifies Yarn 4, and its pages use local vendor CSS and JavaScript files. Check whether Corepack is available:

```powershell
corepack --version
```

If Corepack is missing, run `npm install --global corepack`, then reopen the terminal. From the project root, run:

```powershell
corepack yarn install
& .\team-setup\build_static_windows.ps1 -ProjectRoot .
```

The provided helper copies front-end files from `node_modules` into `src/helpdesk/static/helpdesk/vendor`. It **does not delete the database or source code**. It should finish with `Static vendor assets are ready`. Read the script in the group repository before running it. If a school or company computer blocks PowerShell scripts, ask the coordinator for help; do not change the security policy for the whole computer.

## 5. Create your own local demo database once

Still in the project root, run these commands in order:

```powershell
uv run python manage.py migrate --noinput
uv run python manage.py loaddata emailtemplate.json
uv run python manage.py loaddata demo.json
uv run python manage.py changepassword admin
```

The final command lets you choose a private password for the local demo `admin` account. Do not send your password in the group chat. Do not commit `.venv`, `demodesk/db.sqlite3`, or locally uploaded attachments to GitHub. Do not reload the demo fixtures every time you start the server.

For **SEC-01 queue-permission testing**, run this after loading the demo queues:

```powershell
uv run python manage.py create_queue_permissions
```

The coordinator must then provide consistent test-account setup instructions: grant a test staff account permission for the **Django Helpdesk** queue, but not **Some Product**. These database permissions do not automatically transfer with the Python source code.

## 6. Start and check the application

```powershell
uv run python manage.py check
uv run python manage.py runserver 127.0.0.1:8080
```

Open [http://127.0.0.1:8080/](http://127.0.0.1:8080/) in your browser. Confirm that the page is styled correctly and that you can sign in with your local account. Keep the server terminal open while testing; press **Ctrl+C** to stop it.

In VS Code, press **Ctrl+Shift+P → Python: Select Interpreter** and select `.venv\Scripts\python.exe` from this project. This makes code completion and tests use the same environment.

## Every later session

Open the project folder in VS Code and run only:

```powershell
uv run python manage.py runserver 127.0.0.1:8080
```

Do not run `uv sync`, `migrate`, or `loaddata` on every launch. Re-run an installation or migration step only when the group updates dependencies or database migrations and tells you to do so.

## Troubleshooting

| Problem | Check first |
| --- | --- |
| `uv`, `git`, or `node` is `not recognized` | Confirm the software installed, then restart VS Code and its terminal. |
| `No module named django` | Confirm you are in the folder containing `pyproject.toml` and completed `uv sync --python 3.12 --dev --group test`. |
| `no such table` | Run `migrate`; do not copy another member's SQLite database. |
| Page has no styling or buttons fail | Confirm `corepack yarn install` and the Windows static helper both completed successfully. |
| Port 8080 is already in use | Check whether another Django server is still running and stop the old one. |
| You cannot find or access the repository | Ask the coordinator for the **group** repository URL and collaborator access. |

**Important:** Do not use `make rundemo` directly in Windows PowerShell. It repeats demo initialisation, and its static build uses Unix shell commands. This guide separates one-time setup from daily startup.

Official references: [uv project environments](https://docs.astral.sh/uv/guides/projects/) · [Python in VS Code](https://code.visualstudio.com/docs/languages/python/) · [Yarn and Corepack](https://yarnpkg.com/corepack)
