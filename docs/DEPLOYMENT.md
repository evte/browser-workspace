# 服务端部署

服务端运行 FastAPI、Chromium、Xvfb 和 noVNC。桌面端只连接服务端；目标网站的 Cookie、浏览器环境、代理凭据和 2FA 密钥均保存在服务端的数据卷中。部署服务器不需要安装 Electron 或 Node.js。

## 1. 准备服务器

使用 Linux `amd64` 或 `arm64` 主机，以及能运行本项目能力配置的 Docker Engine。macOS 可用 Docker Desktop 做本地开发预览，Linux 容器才是浏览器实际运行的位置。

准备 Git、Bash、OpenSSL、Docker 和支持 `docker compose up --wait` 的 Compose 插件。按你的发行版使用 [Docker Engine 官方安装说明](https://docs.docker.com/engine/install/ubuntu/)；已有 Docker 的 Linux 主机可参照 [Compose 插件安装说明](https://docs.docker.com/compose/install/linux/)。脚本只检查依赖，不自动安装软件、修改 Docker 权限或防火墙。

```sh
git --version
openssl version
docker info
docker compose version
```

运行脚本的用户必须能访问 Docker。为镜像构建、内核下载与解压、浏览器缓存、备份预留磁盘空间。4 核 16 GB 可以作为试运行配置，但不能保证十个 Facebook 页面并发、尤其包含视频时仍然流畅；从少量环境逐步增加，并观察 CPU、内存和远程画面延迟。

## 2. 首次部署

在服务器执行：

```sh
git clone https://github.com/evte/browser-workspace.git
cd browser-workspace
./deploy.sh up
./deploy.sh password
```

`up` 首次创建权限为 `0600` 的 `.env`，生成随机 `ACCESS_PASSWORD`，构建镜像并启动服务，等待 `/api/session` 健康检查通过。首次构建需要下载系统依赖。默认地址是服务器的 `127.0.0.1:8000`；默认 Compose 项目名是 `browser-workspace`，数据卷名是 `browser-workspace_browser_data`。

部署脚本不会在普通输出中显示密码。`password` 是显式查看命令，从运行中的容器读取正在使用的初始管理密码。它不是账号密码，也不会重置已有账号；不要把输出贴到工单、聊天或仓库。

再次执行 `up` 会保留已有 `.env` 和数据卷。脚本定位自身所在的仓库，不依赖调用时的当前目录。

这里的健康检查验证管理 API 已可用，不会自动启动 Chromium。首次注册后，再创建一个测试环境，启动并打开远程画面，验证服务器的浏览器内核、网络命名空间和访问网络；使用代理时同时检查出口 IP 和代理失效后的断网行为。

## 3. 通过 SSH 隧道连接

没有域名时，保持服务端只监听回环地址，在自己的电脑另开终端：

```sh
ssh -N -L 8000:127.0.0.1:8000 用户名@服务器地址
```

保持该终端连接。浏览器打开 `http://127.0.0.1:8000`，或在 Electron 的服务器地址中填写此地址。首次注册需要输入自己的昵称、邮箱、账号密码，以及上一步取得的「服务器初始管理密码」。之后用邮箱和账号密码登录。

如果本机 8000 已占用，可将隧道左侧端口改成 18000：

```sh
ssh -N -L 18000:127.0.0.1:8000 用户名@服务器地址
```

此时客户端连接 `http://127.0.0.1:18000`。右侧端口必须与服务器 `.env` 的 `BROWSER_PORT` 一致。

## 4. 配置文件和常用命令

参考仓库中的 [`.env.example`](../.env.example)。默认由脚本生成 `.env`，不要用示例文件覆盖已经投入使用的配置。

| 配置 | 默认值 | 用途 |
| --- | --- | --- |
| `ACCESS_PASSWORD` | 首次自动随机生成 | 保护首个账号的注册；至少 12 个字符 |
| `COMPOSE_PROJECT_NAME` | `browser-workspace` | 决定 Compose 资源和数据卷名称 |
| `BROWSER_BIND_ADDRESS` | `127.0.0.1` | 宿主机监听地址 |
| `BROWSER_PORT` | `8000` | 宿主机端口，容器内部始终为 8000 |

修改配置后执行 `./deploy.sh up`。服务启用后不要随意改变项目名：新名称会使用另一套 Compose 资源与卷，看起来会像「数据丢失」。如果接管原来用 `docker compose -p old-name` 启动的部署，先确认旧卷，再保持原项目名和原环境配置运行。

```sh
./deploy.sh status                  # 容器与健康状态
./deploy.sh logs                    # 跟随日志，Ctrl+C 退出日志查看
./deploy.sh stop                    # 停止服务，保留数据卷
./deploy.sh up                      # 构建并启动；已有配置保留
./deploy.sh update                  # 干净的 Git 工作区中 pull --ff-only，再构建并启动
./deploy.sh password                # 查看运行中服务使用的初始管理密码
./deploy.sh help
```

脚本支持 `--env-file PATH`、`--project-name NAME` 和 `--wait-timeout SECONDS`。例如：

```sh
./deploy.sh up --wait-timeout 300
./deploy.sh status --env-file /secure/browser.env --project-name existing-browser
```

`--env-file` 的相对路径以调用者当前目录为准，未指定时使用仓库根目录 `.env`；项目名优先级是命令行参数、环境文件、默认值。对同一部署使用同一组参数。脚本不会继承终端中另一项目的 Compose 配置变量。

`update` 遇到未提交改动会停止，不会替你丢弃修改或强制合并。构建失败时不会重启旧服务；服务替换后的健康检查失败会返回非零状态，需要看日志处理，不会自动回滚数据库。更新或停止服务会结束正在运行的服务端浏览器，环境文件仍保留。更新前请备份。

## 5. 使用域名和 HTTPS

需要直接远程连接时，将域名解析到服务器，使用有效的 TLS 证书和 HTTPS 反向代理。Electron 远程连接要求 HTTPS；它只允许回环地址使用 HTTP。以下是**宿主机 Nginx** 的示例，不适用于未调整上游地址的独立 Nginx 容器。

先通过 SSH 隧道完成初始账号注册。确认域名、证书和 Nginx 已准备好，再将以下内容放入 Nginx `http` 上下文包含的配置文件，例如 `/etc/nginx/conf.d/browser-workspace.conf`。替换域名和证书路径；保持后端 `BROWSER_BIND_ADDRESS=127.0.0.1`。

```nginx
map $http_upgrade $browser_workspace_connection {
    default upgrade;
    ''      close;
}

server {
    listen 80;
    server_name browser.example.com;
    return 301 https://browser.example.com$request_uri;
}

server {
    listen 443 ssl;
    server_name browser.example.com;
    ssl_certificate     /etc/letsencrypt/live/browser.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/browser.example.com/privkey.pem;
    client_max_body_size 2m;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection $browser_workspace_connection;
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
        proxy_buffering off;
    }
}
```

检查配置后加载：

```sh
sudo nginx -t
sudo systemctl reload nginx
curl --fail https://browser.example.com/api/session
```

客户端填写 `https://browser.example.com`，不要加子路径。后端会校验 `Origin` 与 `Host`；不要把 `Host` 改为 `127.0.0.1`。noVNC 的 `/api/profiles/<id>/ws` 需要 WebSocket Upgrade，相关机制见 [Nginx WebSocket 官方说明](https://nginx.org/en/docs/http/websocket.html)。本应用读取代理覆盖后的 `X-Forwarded-Proto: https` 来设置登录 Cookie 的 `Secure` 属性。

Nginx 应覆盖转发头，后端端口仍只允许本机访问。若另行配置 Uvicorn 信任代理以取得真实客户端 IP，应仅信任实际代理来源地址；参见 [Uvicorn 代理头设置](https://uvicorn.dev/settings/#http)，不要直接把所有来源都设为可信。按现有云防火墙策略开放域名所需的 HTTPS 端口；脚本不会替你开放端口或签发、续期证书。

## 6. 备份和恢复

应备份**整个 `/data` 卷**和 `.env`。卷内包含 `profiles.sqlite3`、`totp.key`、`profiles/` 和 `kernels/` 等内容。数据库与 `totp.key` 必须配套，否则已有 2FA 密钥无法解密。浏览器文件中含网站登录凭据，应将备份加密后存入受控位置。

下面的命令用于默认项目名、默认 `.env`，从仓库根目录的 Bash 执行。自定义部署须同步替换 Compose 的项目名和环境文件路径。

```sh
(
set -eu
umask 077
backup_dir="$HOME/browser-workspace-backups/$(date -u +%Y%m%dT%H%M%SZ)"
mkdir -p "$HOME/browser-workspace-backups"
mkdir "$backup_dir"
chmod 700 "$backup_dir"
./deploy.sh stop
cp .env "$backup_dir/server.env"
docker compose --env-file .env -p browser-workspace -f compose.yaml \
  run --rm --no-deps -T --entrypoint tar browser \
  -czpf - -C /data . > "$backup_dir/browser-data.tgz"
tar -tzf "$backup_dir/browser-data.tgz" >/dev/null
./deploy.sh up
)
```

先确认归档命令和校验都成功，再把备份复制到独立的加密存储。备份期间服务停止，不能同时操作环境；归档或校验失败时，示例保持服务停止，先处理失败原因，再手动恢复服务。

恢复建议在**全新服务器和空数据卷**进行，使用与备份相同的服务端架构和对应版本的代码；下载的浏览器内核不能直接跨 CPU 架构运行。把备份放到 `/secure/backup`，再执行以下步骤；已有 `.env` 或目标数据卷时会停止，避免覆盖现有环境。

```sh
(
set -eu
tar -tzf /secure/backup/browser-data.tgz >/dev/null
test ! -e .env || { echo '已有 .env，请先确认恢复目标'; exit 1; }
if docker volume inspect browser-workspace_browser_data >/dev/null 2>&1; then
  echo '目标卷已经存在，请改用全新恢复目标，不要覆盖生产数据'
  exit 1
fi
install -m 600 /secure/backup/server.env .env
docker compose --env-file .env -p browser-workspace -f compose.yaml build browser
docker compose --env-file .env -p browser-workspace -f compose.yaml \
  run --rm --no-deps -T --entrypoint sh browser -c \
  'test -z "$(ls -A /data)" || { echo "目标卷不是空卷" >&2; exit 1; }; exec tar -xzpf - -C /data' \
  < /secure/backup/browser-data.tgz
./deploy.sh up
)
```

只有构建和解压都成功后才启动服务；失败时不启动半恢复的数据卷。恢复后登录检查团队、环境、代理和 2FA，并实际启动一个环境。不要执行 `docker compose down -v` 或删除正在使用的数据卷；重装应用不需要删除环境数据。

## 7. 故障排查与边界

| 现象 | 检查方向 |
| --- | --- |
| Docker 不可用 | Docker 服务是否启动、当前用户是否有权限；macOS 需启动 Docker Desktop |
| 端口已占用 | 调整 `.env` 的 `BROWSER_PORT`，同步更新 SSH 隧道或 Nginx 上游 |
| 健康检查超时 | `./deploy.sh logs`，检查密码配置、磁盘、内存和数据库权限 |
| HTTPS 登录或写入返回 403 | 检查反向代理是否保留原始 `Host`，客户端是否连接正确域名 |
| 登录正常但浏览器画面断开 | 检查 WebSocket 转发、代理超时，以及服务端环境是否仍在运行 |
| 下载内核失败 | 查看环境错误信息和服务器出网；内核须匹配架构并通过摘要校验 |
| 浏览器启动提示隔离能力不足 | 检查 Linux Docker 是否允许 Compose 中声明的 `SYS_ADMIN`、`NET_ADMIN` 和网络命名空间操作 |

当前为早期原型，只能运行单个后端工作进程。环境有独立 UID、数据目录和网络命名空间，但仍共享容器内核，Chromium 使用 `--no-sandbox`；不是适合不可信租户的完整虚拟机隔离方案。服务端无需 Node.js，多用户管理和远程画面能力不代表浏览器并发容量无限。

管理平台当前支持注册，不发送验证邮件或密码重置邮件。上线范围、注册访问控制和资源配额应按实际使用场景规划；公开源码本身不会把你的本地服务或数据卷公开。
