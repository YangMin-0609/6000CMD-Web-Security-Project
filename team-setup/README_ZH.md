# Django Helpdesk 小组成员安装指南（Windows + VS Code）

本指南给**刚安装 VS Code、尚未安装 Django 项目**的组员使用。所有命令在 VS Code 的 **PowerShell 终端**执行。只在自己的电脑和本地测试数据库操作。

> 组长：本文件夹已放进[小组 GitHub 仓库](https://github.com/YangMin-0609/6000CMD-Web-Security-Project)。组员应 clone 小组仓库，不要直接 clone 官方仓库的最新版。本指南按项目当前的 `v2.3.3` 代码与 demo 配置编写；先请一位组员完成一次全新 clone 验证。

## A. 第一次安装软件

1. 安装 [Git for Windows](https://git-scm.com/install/windows)。
2. 安装 [Node.js LTS](https://nodejs.org/en/download)。项目需要它来安装前端样式和 JavaScript。
3. 在 VS Code 的 Extensions 中安装 Microsoft 的 **Python** extension。VS Code extension 不等于 Python 本身；下一步的 `uv` 会安装项目所需的 Python。
4. 打开 PowerShell，安装 [`uv`](https://docs.astral.sh/uv/getting-started/installation/)：

   ```powershell
   winget install --id=astral-sh.uv -e
   ```

5. **关闭并重新打开 VS Code**，在新终端检查：

   ```powershell
   git --version
   uv --version
   node --version
   npm --version
   ```

   如果某个命令显示 `not recognized`，先确认软件已安装，再重开终端；不要继续执行后面的步骤。

## B. 下载小组项目

在 PowerShell 进入你想存放项目的文件夹，然后运行：

```powershell
git clone https://github.com/YangMin-0609/6000CMD-Web-Security-Project.git
cd 6000CMD-Web-Security-Project
```

当前文件夹应有 `manage.py`、`pyproject.toml`、`package.json` 和 `team-setup`。在 VS Code 选择 **File → Open Folder** 打开这个项目文件夹。

## C. 安装 Python 与 Django 依赖（只需第一次）

在**项目根目录**运行：

```powershell
uv python install 3.12
uv sync --python 3.12 --dev --group test
```

`uv` 会建立项目自己的 `.venv` 并安装依赖，不必先手动安装 Django，也不必激活虚拟环境。项目声明支持 Python 3.10 及以上；小组统一使用 3.12 是为了减少环境差异。

## D. 安装前端样式与脚本（只需第一次）

项目的 `package.json` 使用 Yarn 4，模板也引用本地 vendor CSS/JS。先检查：

```powershell
corepack --version
```

如果没有 `corepack`，运行 `npm install --global corepack`，然后重开终端。接着在项目根目录运行：

```powershell
corepack yarn install
& .\team-setup\build_static_windows.ps1 -ProjectRoot .
```

辅助脚本只复制 `node_modules` 的前端文件到项目的 `src/helpdesk/static/helpdesk/vendor`，**不会删除数据库或源代码**。成功时会显示 `Static vendor assets are ready`。请先阅读小组仓库中的脚本再运行；如果公司/学校电脑禁止 PowerShell 脚本，联系组长，不要更改整台电脑的安全策略。

## E. 建立自己的 demo 数据库（只需第一次）

仍在项目根目录，依次运行：

```powershell
uv run python manage.py migrate --noinput
uv run python manage.py loaddata emailtemplate.json
uv run python manage.py loaddata demo.json
uv run python manage.py changepassword admin
```

`changepassword` 会让你为本地 demo 的 `admin` 账号设置**自己的密码**。不要在群里发送密码；不要把 `.venv`、`demodesk/db.sqlite3` 或本地上传的附件提交到 GitHub。不要在以后每次启动时重新加载 demo fixtures。

如果要测试 **SEC-01 队列权限**，还需要在加载 demo queues 后运行：

```powershell
uv run python manage.py create_queue_permissions
```

然后由组长提供一致的测试账号设置：授予测试 staff 账号 **Django Helpdesk** 队列权限，**不要**授予 **Some Product**。这项数据库权限不会自动随 Python 代码进入别人的电脑。

## F. 启动与确认

```powershell
uv run python manage.py check
uv run python manage.py runserver 127.0.0.1:8080
```

浏览器打开 [http://127.0.0.1:8080/](http://127.0.0.1:8080/)。确认首页有正常样式，并能用自己的本地账号登录。服务器运行期间不要关闭该终端；结束时按 **Ctrl+C**。

在 VS Code 按 **Ctrl+Shift+P → Python: Select Interpreter**，选择项目里的 `.venv\Scripts\python.exe`，让代码提示和测试使用同一环境。

## 以后每次打开项目

在 VS Code 打开项目文件夹，只需运行：

```powershell
uv run python manage.py runserver 127.0.0.1:8080
```

不需要每次都运行 `uv sync`、`migrate` 或 `loaddata`。只有小组更新了依赖或数据库迁移时，才按组长通知重新执行相应步骤。

## 常见问题

| 情况 | 先检查什么 |
| --- | --- |
| `uv` / `git` / `node` 无法识别 | 安装后是否重新打开 VS Code；软件是否安装成功 |
| `No module named django` | 是否在有 `pyproject.toml` 的项目根目录；是否完成 `uv sync --python 3.12 --dev --group test` |
| `no such table` | 是否执行过 `migrate`；不要复制其他人的 SQLite 数据库 |
| 页面没样式或按钮异常 | 是否执行 `corepack yarn install` 和 `build_static_windows.ps1`，以及脚本是否显示成功 |
| 8080 端口已占用 | 是否已有另一个 Django 终端在运行；先停止旧服务器 |
| 不知道 GitHub 仓库链接或无法访问 | 向组长索取**小组**仓库链接和协作者权限 |

**重要：**不要在 Windows PowerShell 中直接运行仓库的 `make rundemo`。它会重新执行 demo 初始化，而且其中的静态资源步骤依赖 Unix 命令；本指南把一次性步骤和日常启动分开。

参考：[uv 项目环境](https://docs.astral.sh/uv/guides/projects/) · [VS Code Python 环境](https://code.visualstudio.com/docs/languages/python/) · [Yarn/Corepack](https://yarnpkg.com/corepack)
