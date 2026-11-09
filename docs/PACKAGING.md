# Electron 桌面端开发与打包

桌面端是服务端的管理与远程操作客户端。打包后的程序连接已部署的服务端，不会把目标网站的浏览器环境下载到本机，也不会替代服务器运行 Chromium。先阅读 [服务端部署](DEPLOYMENT.md)。

## 从源码运行

在有桌面环境的电脑上安装 Node.js **22.12.0 或更新版本**，然后执行：

```sh
git clone https://github.com/evte/browser-workspace.git
cd browser-workspace
npm ci
npm run test:desktop
npm start
```

`npm ci` 按 `package-lock.json` 安装固定依赖，并下载 Electron 运行时。当前项目使用 Electron `45.2.3` 和 `@electron/packager` `20.3.0`。不要在正常安装时设置 `ELECTRON_SKIP_BINARY_DOWNLOAD=1`，否则开发启动可能找不到运行时。

连接页填写服务器根地址，例如 `https://browser.example.com`。使用 SSH 隧道或本机 Docker 时可填 `http://127.0.0.1:8000`。服务器地址不包含账号密码、查询参数、片段或子路径。

## 打包命令

在**目标操作系统**和目标架构对应的 Node.js 下执行：

```sh
npm ci
npm run test:desktop
npm run pack
```

脚本直接使用 `process.platform` 和 `process.arch`。可先查看当前打包目标：

```sh
node -p "process.platform + ' ' + process.arch"
```

它会覆盖同平台、同架构的旧 `dist` 产物。现有脚本没有跨平台目标参数，也不生成通用 macOS Universal 包；Apple Silicon 下若使用 Rosetta 的 x64 Node.js，目标会是 `darwin-x64`。

| 构建机器 / Node 架构 | 可执行文件 |
| --- | --- |
| macOS Apple Silicon / arm64 | `dist/Browser Workspace-darwin-arm64/Browser Workspace.app` |
| macOS Intel / x64 | `dist/Browser Workspace-darwin-x64/Browser Workspace.app` |
| Windows / x64 | `dist/Browser Workspace-win32-x64/Browser Workspace.exe` |
| Windows / arm64 | `dist/Browser Workspace-win32-arm64/Browser Workspace.exe` |
| Linux / x64 | `dist/Browser Workspace-linux-x64/Browser Workspace` |
| Linux / arm64 | `dist/Browser Workspace-linux-arm64/Browser Workspace` |

本项目已在 macOS ARM64 上实际打包并运行；表格中其他目标的路径依据当前脚本生成规则，尚未在本项目中逐一运行验证。Linux 桌面客户端需要图形会话及 Electron 的系统依赖，不能在无桌面会话的服务器终端中直接当 GUI 使用。

macOS 启动示例：

```sh
open "dist/Browser Workspace-darwin-arm64/Browser Workspace.app"
```

Windows PowerShell 启动示例：

```powershell
& '.\dist\Browser Workspace-win32-x64\Browser Workspace.exe'
```

Linux x64 启动示例：

```sh
"./dist/Browser Workspace-linux-x64/Browser Workspace"
```

## 产物包含什么

当前产物是应用目录，**不是安装器**。macOS 分发整个 `.app`；Windows 和 Linux 分发整个 `Browser Workspace-<platform>-<arch>` 目录，不能只复制主可执行文件。可按目标平台打成 ZIP 或 tar 归档后分发。

项目将桌面源码打入 `app.asar`，服务器、管理前端和数据仍由独立的服务端部署提供。`dist/`、`node_modules/` 和 `.env` 不提交到 Git。Electron 打包结构可参阅 [官方 Application Packaging 文档](https://www.electronjs.org/docs/latest/tutorial/application-distribution)。

打包范围由 `desktop/package-files.cjs` 的文件白名单限定，只包含 `package.json`、桌面运行代码、连接页和三个图标。部署配置、服务器代码、数据库、备份和开发文档都不会进入桌面包；新增桌面运行资源时需同步更新白名单并运行桌面测试。自定义部署配置建议放在仓库外，通过 `deploy.sh --env-file` 引用。

当前未提供 DMG、PKG、MSI、NSIS、AppImage、DEB 安装器，没有自动更新服务，也没有自动发布 GitHub Release 的工作流。后续若要提供安装器，可在现有应用打包的基础上增加相应分发工具。

## 应用图标

图标资源已提交到 `desktop/assets/`：

| 文件 | 使用位置 |
| --- | --- |
| `app-icon.png` | Electron 窗口、Linux 应用 |
| `app-icon.icns` | macOS 应用包 |
| `app-icon.ico` | Windows 应用 |

更换图标时，用至少 `1024×1024` 的正方形 PNG 替换源文件，在 macOS 执行：

```sh
npm run icons
npm run pack
```

`icons` 使用 macOS 自带的 `sips`、`iconutil`，生成标准 ICNS 和包含多个尺寸的 ICO。Windows/Linux 可直接使用仓库中已生成的图标；只在这些平台运行 `pack` 不需要重新生成图标。

## 签名、公证与正式分发

当前未配置开发者证书签名或 Apple 公证。macOS 打包过程中的本地 ad-hoc 签名不等于 Developer ID 签名或公证，不能据此宣称应用已经通过正式分发认证。

向其他电脑正式分发时，应配置平台相应的签名流程。macOS 需准备开发者证书并完成公证，Windows 需准备合适的代码签名方式；这些凭据不应提交仓库。具体接入参照 [Electron Code Signing 官方文档](https://www.electronjs.org/docs/latest/tutorial/code-signing)，在 `desktop/package.cjs` 中增加符合实际证书和 CI 环境的配置。仓库暂未包含这一步的证书、自动化或安装包。

## 常见问题

| 现象 | 处理方式 |
| --- | --- |
| `Electron runtime is missing` | 确认没有跳过运行时下载，网络可访问 Electron 发布资源，再运行 `npm ci`；开发脚本也可复用当前平台已有的完整打包产物 |
| 下载失败 | 检查本机网络与代理，优先使用官方 Electron 下载来源，不要替换为无法核验的二进制 |
| macOS 签名出现磁盘空间错误 | 清理确认可丢弃的旧构建文件并预留解压、临时签名和最终包同时存在的空间，再重试 |
| 缺少图标 | 确认三个图标文件已从 Git 完整检出；更换图标后先在 macOS 生成对应格式 |
| 应用启动但连接失败 | 服务端需先健康启动；确认地址、证书和 SSH 隧道，不要把服务器 HTTP 公网地址填入客户端 |

要让 Codex 协助完成这些命令、构建检查或服务器部署，参阅 [Codex 部署指南](CODEX.md)。
