# 用 Codex 部署 Browser Workspace

[返回 README](../README.md) · [部署指南](DEPLOYMENT.md) · [桌面打包](PACKAGING.md)

Codex 可以读取本仓库、修改配置和执行你已授权的部署命令。本项目自身不需要调用 OpenAI API。推荐先用 SSH 隧道完成部署和验收，再按需要配置 HTTPS 域名。

## 方式一：本地 Codex + SSH

适合已经在自己电脑使用 Codex 的情况。

1. 克隆 `https://github.com/evte/browser-workspace.git`，在 Codex 桌面端打开克隆后的项目目录，或在该目录运行 `codex`。
2. 先在本机终端确认 `ssh 用户名@服务器地址` 能正常连接，使用已配置的密钥，核对首次连接的服务器指纹。
3. 告诉 Codex 服务器 SSH 别名、部署目录，以及选择 SSH 隧道还是 HTTPS 域名。已有部署要同时说明原 Compose 项目名和配置文件位置。
4. 让 Codex 执行部署并返回容器状态和访问地址。只请求修复代码不会自动获得生产部署目标，应明确说要部署到哪台服务器。

示例提示词（将占位信息替换成真实目标；不粘贴私钥）：

```text
请读取 AGENTS.md 和 docs/DEPLOYMENT.md，将此仓库部署到我的 Linux 服务器。
SSH 别名：browser-prod
部署目录：~/apps/browser-workspace
访问方式：SSH 隧道，远端 127.0.0.1:8000

先检查系统架构、Docker 与 Compose、端口、磁盘、目录及已有容器/卷。
首次部署克隆仓库并使用 ./deploy.sh up；已有部署复用原项目名和 .env。
若已有数据，先按部署指南备份，更新时只做快进拉取。
保留账号、Cookie、代理、2FA 主密钥和环境文件，不使用 down -v。
不要把 SSH 私钥、.env、密码、Cookie 或数据库提交到仓库或打印在回复中。
部署后检查 /api/session 与容器状态，返回实际结果、访问方式及查看初始密码的命令。
如果缺少必要的连接信息或权限，指出缺少哪项。
```

这是本仓库的部署流程建议。Codex CLI 可在本地项目中读写文件并运行已安装的工具；所需 SSH、Docker 和网络访问取决于当前环境权限。[官方 CLI 说明](https://learn.chatgpt.com/docs/codex/cli)

## 方式二：直接在服务器运行 Codex CLI

先安装 Node.js / npm（若选择 npm 安装方式）及服务器运行所需的 Docker。以下命令中的 Codex 登录由你本人完成：

```bash
npm install -g @openai/codex
codex --version
codex login --device-auth

git clone https://github.com/evte/browser-workspace.git
cd browser-workspace
codex
```

如果项目已经存在，进入原目录即可，不要再次创建部署目录。安装方式依据[官方 Codex CLI 文档](https://learn.chatgpt.com/docs/codex/cli)。无浏览器服务器可使用设备码登录，在自己的浏览器打开终端提供的链接并输入一次性代码；个人账号或工作区可能需要先启用设备码登录。其他登录方式和当前可用性以[官方认证文档](https://learn.chatgpt.com/docs/auth?surface=cli)为准。

进入 Codex 后可以直接输入：

```text
读取本仓库 AGENTS.md 和部署指南，检查这台服务器是否满足运行条件，
然后使用 ./deploy.sh up 部署当前代码。保留已有 .env 和数据卷。
检查容器与 /api/session，给出通过 SSH 隧道连接的命令。
不要输出管理密码，告诉我如何自行查看即可。
```

使用普通部署账号和已有的 Docker 权限。实际命令仍受 Codex 当前权限配置约束；遇到权限提示按任务需要处理，不需要为此关闭所有沙箱与审批。Codex 的登录凭据不属于项目配置，不要加入 `.env`、Git、Docker 镜像或桌面安装包。

## 项目如何给 Codex 提供上下文

根目录的 [AGENTS.md](../AGENTS.md) 给出架构、部署入口、验证方式和必须保留的数据。Codex 会在开始工作时读取作用域内的项目指令；新增或修改后，开启新会话让它重新加载。[官方 AGENTS.md 说明](https://learn.chatgpt.com/docs/agent-configuration/agents-md)

日常修改可使用这样的提示词：

```text
阅读 AGENTS.md，修复我描述的问题并运行相关测试。
同步更新 README 或 docs 中受影响的命令。
给出变更摘要与验证结果。此次只修改源码，不部署服务器。
```

不要在 `AGENTS.md` 里写服务器密码、代理账号、2FA 密钥或用户数据。文件中列出的测试是开发检查，不会替代真实服务器上的部署验收。

## 方式三：使用 Codex Cloud 改代码

可以在 Codex Cloud 创建或选择环境，连接 GitHub、选择 `evte/browser-workspace`，让 Codex 准备依赖并运行测试，随后检查改动并提交或创建 PR。网络访问及服务凭据由环境设置管理。[官方 Codex Cloud 指南](https://learn.chatgpt.com/docs/cloud)

对于本项目，建议云端任务处理源码、测试和文档，正式部署使用前两种方案。云端工作区不等于你的 Linux 生产服务器，连接 GitHub 也不会自动获得 SSH 登录能力。完整浏览器运行还需要 Docker、Linux 网络命名空间、`SYS_ADMIN` / `NET_ADMIN` 和持久化卷，不能把云端单元测试通过当成生产部署已完成。

可让云端环境执行的检查示例（先准备 Python 3.12 与 Node.js 22.12+）：

```bash
python -m pip install -r backend/requirements.txt httpx
ELECTRON_SKIP_BINARY_DOWNLOAD=1 npm ci
npm run test:desktop
PYTHONPATH=. python -m unittest discover -s tests -v
```

这里跳过 Electron 二进制下载，只跑 Node 单元测试，不会打开桌面应用。真实桌面启动和打包另见[打包指南](PACKAGING.md)。
