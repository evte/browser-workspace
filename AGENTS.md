# Browser Workspace 项目指南

## 架构与入口

- `backend/`：FastAPI + SQLite、账号团队、代理、TOTP、Chromium / X11 / noVNC 进程管理。
- `frontend/`：原生 JavaScript / HTML / CSS 管理页，不是 React 项目。
- `desktop/`：Electron 客户端，远程页面启用隔离和沙箱，没有 Node 权限。
- `deploy.sh` / `compose.yaml`：服务端部署入口；先读 `docs/DEPLOYMENT.md`。
- `docs/PACKAGING.md`：桌面打包；`docs/CODEX.md`：Codex 操作示例。

## 关键约束

目标网站 Cookie 和环境文件必须留在服务器。保持代理失效即断网的行为，不能回退直连。团队权限必须在 API 与远程连接两端检查。

部署使用用户指定的目标、目录、配置文件和 Compose 项目名。已有部署复用原数据卷，更新前确认备份路径；不要通过新项目名制造一个看似丢数据的新空卷。用户已经明确授权的部署可继续执行，不重复索要相同授权；缺少实际目标或连接权限时说明缺项。

不删除持久化卷，不覆盖已有 `.env`，不重建 `totp.key`，不随意改变内核或设备种子。`.env`、数据库、Cookie、代理凭据、2FA 密钥、SSH 私钥以及 Codex 凭据不能提交到 Git、打包进桌面应用或打印进任务日志。`./deploy.sh password` 是给用户自行在服务器终端查看密码的命令。

## 验证

根据改动选择相关检查，不把本机模拟结果描述为真实服务器验收。

```bash
bash -n deploy.sh
python3 -m unittest discover -s tests -p 'test_deploy.py' -v
npm run test:desktop
```

后端开发先在独立 Python 环境安装 `backend/requirements.txt` 和 `httpx`，再运行：

```bash
PYTHONPATH=. python -m unittest discover -s tests -v
```

网络命名空间集成测试需要具备上述能力的 Linux 容器和 `RUN_NETWORK_NAMESPACE_TESTS=1`。macOS 原生不能运行完整浏览器服务，使用 Docker Desktop。部署完成检查容器状态、`/api/session` 与访问入口；账号注册由用户完成。

改部署命令、配置变量、打包路径时同步更新文档。保持一个服务进程；不要自行改为多 worker。打包只运行于目标平台，`npm run pack` 不包含开发者证书签名、公证或自动更新。代码公开不等于已选择开源许可证。
