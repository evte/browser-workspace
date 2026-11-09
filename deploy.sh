#!/usr/bin/env bash
# Deploy with an existing Docker Engine / Docker Desktop and Compose plugin.
# This script never sources .env and never deletes the persistent data volume.
set -euo pipefail

ROOT=$(CDPATH= cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ENV_FILE="$ROOT/.env"
PROJECT_OVERRIDE=''
WAIT_TIMEOUT=180
ACTION=up
ACTION_SET=0
ENV_TMP=''

cleanup() {
  if [ -n "$ENV_TMP" ]; then rm -f -- "$ENV_TMP"; fi
}
trap cleanup EXIT

die() { printf '错误：%s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'HELP'
用法：./deploy.sh [命令] [选项]

命令（默认 up）：
  up        首次生成 .env（已有文件保留），构建并启动，等待健康检查
  update    确认 Git 工作区干净，git pull --ff-only 后构建并启动
  status    查看当前项目的容器状态
  logs      查看最近 100 行日志并持续跟随（Ctrl+C 退出）
  stop      停止容器，保留容器和持久化卷
  password  输出运行中服务的初始管理密码，仅用于首次注册
  help      显示本帮助

选项：
  --env-file PATH         配置文件；默认仓库根目录 .env，相对路径按当前目录解析
  --project-name NAME     Compose 项目名；默认取配置文件或 browser-workspace
  --wait-timeout SECONDS  up/update 的健康检查超时，默认 180 秒

需要已安装 Docker 和支持 up --wait-timeout 的 Compose 插件。
默认仅监听 127.0.0.1:8000；远程访问请用 SSH 隧道或配置 HTTPS 反向代理。
更新会重启服务并结束运行中的浏览器；浏览器文件、账号和密钥保留在卷中。
HELP
}

while [ "$#" -gt 0 ]; do
  case "$1" in
    up|update|status|logs|stop|password|help)
      [ "$ACTION_SET" -eq 0 ] || die '只能指定一个命令。'
      ACTION=$1; ACTION_SET=1; shift ;;
    --env-file|--project-name|--wait-timeout)
      [ "$#" -ge 2 ] && [ -n "$2" ] || die "$1 缺少值。"
      case "$1" in
        --env-file) ENV_FILE=$2 ;;
        --project-name) PROJECT_OVERRIDE=$2 ;;
        --wait-timeout) WAIT_TIMEOUT=$2 ;;
      esac
      shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) die "未知参数：$1；运行 ./deploy.sh help 查看用法。" ;;
  esac
done
[ "$ACTION" != help ] || { usage; exit 0; }
case "$WAIT_TIMEOUT" in ''|*[!0-9]*) die '--wait-timeout 必须是 1–3600 的整数。' ;; esac
[ "$WAIT_TIMEOUT" -ge 1 ] && [ "$WAIT_TIMEOUT" -le 3600 ] || die '--wait-timeout 必须是 1–3600 的整数。'

case "$ENV_FILE" in /*) ;; *) ENV_FILE="$PWD/$ENV_FILE" ;; esac
[ -d "$(dirname -- "$ENV_FILE")" ] || die '配置文件所在目录不存在。'
[ ! -L "$ENV_FILE" ] || die '配置文件不能是符号链接。'

valid_project() {
  case "$1" in ''|*[!a-z0-9_-]*) return 1 ;; esac
  case "$1" in [a-z0-9]*) return 0 ;; *) return 1 ;; esac
}
if [ -n "$PROJECT_OVERRIDE" ]; then
  valid_project "$PROJECT_OVERRIDE" || die '项目名须以小写字母或数字开头，仅包含小写字母、数字、连字符和下划线。'
fi

command -v docker >/dev/null 2>&1 || die '未安装 Docker。请按 docs/DEPLOYMENT.md 安装 Docker Engine 或 Docker Desktop。'
docker compose version >/dev/null 2>&1 || die '缺少 Docker Compose 插件；请安装 Compose v2 或更新版本。'
docker info >/dev/null 2>&1 || die '无法访问 Docker daemon；请启动 Docker，并确认当前账号有访问权限。'

if [ "$ACTION" = update ]; then
  command -v git >/dev/null 2>&1 || die 'update 需要 Git。'
  git -C "$ROOT" rev-parse --is-inside-work-tree >/dev/null 2>&1 || die 'update 需要 Git 克隆的项目目录。'
  [ -z "$(git -C "$ROOT" status --porcelain)" ] || die 'Git 工作区有未提交修改；请先提交或保存修改，再执行 update。'
  git -C "$ROOT" pull --ff-only
  # A pull can update this script too. Re-enter the fetched version as `up`.
  args=(up --env-file "$ENV_FILE" --wait-timeout "$WAIT_TIMEOUT")
  if [ -n "$PROJECT_OVERRIDE" ]; then args+=(--project-name "$PROJECT_OVERRIDE"); fi
  exec bash "$ROOT/deploy.sh" "${args[@]}"
fi

if [ ! -e "$ENV_FILE" ]; then
  [ "$ACTION" = up ] || die '找不到配置文件；请先运行 ./deploy.sh up，或指定 --env-file。'
  command -v openssl >/dev/null 2>&1 || die '首次生成密码需要 OpenSSL，请先安装。'
  umask 077
  ENV_TMP=$(mktemp "${ENV_FILE}.tmp.XXXXXX")
  password=$(openssl rand -hex 24) || die '无法生成随机初始密码。'
  [ "${#password}" -eq 48 ] || die '随机密码生成失败。'
  printf 'COMPOSE_PROJECT_NAME=%s\nBROWSER_BIND_ADDRESS=127.0.0.1\nBROWSER_PORT=8000\nACCESS_PASSWORD=%s\n' \
    "${PROJECT_OVERRIDE:-browser-workspace}" "$password" > "$ENV_TMP"
  unset password
  # A hard link creates the destination atomically and refuses to overwrite a race winner.
  if ln "$ENV_TMP" "$ENV_FILE" 2>/dev/null; then
    printf '已创建配置文件：%s（权限 600，随机密码已保存）\n' "$ENV_FILE"
  else
    [ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || die '无法创建配置文件。'
  fi
  rm -f -- "$ENV_TMP"; ENV_TMP=''
fi
[ -f "$ENV_FILE" ] && [ ! -L "$ENV_FILE" ] || die '配置路径必须是普通文件。'
chmod 600 "$ENV_FILE" || die '无法保护配置文件权限。'

# Only a restricted project-name string is read locally. Docker parses all other
# dotenv values; shell substitutions and commands in the file are never executed.
PROJECT=$(awk '
  /^[[:space:]]*(export[[:space:]]+)?COMPOSE_PROJECT_NAME[[:space:]]*=/ {
    count++; sub(/^[^=]*=[[:space:]]*/, ""); sub(/[[:space:]]+#.*$/, "");
    sub(/[[:space:]]*\r?$/, ""); print
  }
  END { if (count > 1) exit 2 }
' "$ENV_FILE") || die 'COMPOSE_PROJECT_NAME 重复，请在配置文件中只保留一个值。'
case "$PROJECT" in
  \"*\") PROJECT=${PROJECT#\"}; PROJECT=${PROJECT%\"} ;;
  \'*\') PROJECT=${PROJECT#\'}; PROJECT=${PROJECT%\'} ;;
esac
PROJECT=${PROJECT_OVERRIDE:-${PROJECT:-browser-workspace}}
valid_project "$PROJECT" || die '配置中的 COMPOSE_PROJECT_NAME 无效；须是小写字母、数字、连字符或下划线，且以字母或数字开头。'

compose() (
  # Pin this file/project and let only the chosen .env supply application settings.
  # Inherited COMPOSE_FILE / COMPOSE_PROFILES etc must not target another stack.
  while IFS= read -r variable; do unset "$variable"; done < <(compgen -v COMPOSE_ || true)
  unset ACCESS_PASSWORD BROWSER_BIND_ADDRESS BROWSER_PORT
  docker compose --project-directory "$ROOT" --env-file "$ENV_FILE" \
    -f "$ROOT/compose.yaml" --project-name "$PROJECT" "$@"
)

printf '项目：%s | 配置：%s\n' "$PROJECT" "$ENV_FILE"
compose config --quiet >/dev/null 2>&1 || die 'Compose 配置无效；检查 .env 中的 ACCESS_PASSWORD、监听地址和端口。'

case "$ACTION" in
  up)
    if ! docker compose up --help 2>/dev/null | grep -q -- '--wait-timeout'; then
      die '当前 Compose 太旧，不支持 up --wait-timeout；请升级 Compose 插件。'
    fi
    compose build browser
    if ! compose up -d --wait --wait-timeout "$WAIT_TIMEOUT" browser; then
      die '服务未在超时内健康启动；运行 ./deploy.sh status 和 ./deploy.sh logs（使用相同配置选项）排查。已有卷和配置保留。'
    fi
    printf '部署完成，健康检查通过。\n'
    printf '运行 ./deploy.sh password（带上相同配置选项）查看首次注册需要的初始管理密码。\n'
    printf '默认本机访问：http://127.0.0.1:8000；自定义端口请按 .env 设置连接。\n'
    ;;
  status) compose ps ;;
  logs) compose logs --tail 100 --follow browser ;;
  stop) compose stop browser ;;
  password)
    # This command intentionally reveals the current running service's setup key.
    compose exec -T browser python -c 'import os; print(os.environ["ACCESS_PASSWORD"])'
    ;;
esac
