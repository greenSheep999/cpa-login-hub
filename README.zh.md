# cpa-login-hub · 中文说明

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.22%2B-00ADD8.svg)](go.mod)
[![Status](https://img.shields.io/badge/status-alpha-orange.svg)](#路线图)

一个给 [CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI) (CPA)
使用的批量 OAuth 登录插件,底层用
[Camoufox](https://github.com/daijro/camoufox) 反指纹自动化。装上以后在
CPA 管理面板里点一下 provider,插件驱动真实浏览器走完登录流程,拿到 token,
自动灌到 CPA 号池里 —— 不用手 curl,也不用手写脆弱的 JSON。

English: [README.md](README.md)

## Provider 支持矩阵

| Provider | 首次登录 | 续期(纯协议) | 备注 |
|---|:---:|:---:|---|
| **kiro (IdC)** | ✅ v0.1 | ✅ v0.1 | AWS IAM Identity Center — 首登自动 scrape MFA + 改密到固定值 |
| kiro (M365)   | 🚧 v0.2 | ✅ v0.1 | Microsoft Entra external_idp — worker 代码已就位,StartLogin 分派待补 |
| openai (codex) | 🚧 v0.2 | 🚧 v0.2 | 集成 chongpt.xyz 接码,支持长效手机验证 |
| grok          | 🚧 v0.2 | 🚧 v0.2 | x.ai Camoufox 走 consent 页 |
| antigravity   | 🚧 v0.2 | 🚧 v0.2 | Google 登录 + 手动扫码激活 |

`worker/helpers/` 里已经带了 5 provider 的完整 Python 实现,v0.2 只是把它们
接进 Go 插件的 `StartLogin` 分派。

## 工作原理

```
CPA 管理面板
       │  POST /v0/management/auth-files/plugin-login-url
       ▼
CPA 主进程 dlopen 加载 cpa-login-hub.so
       │  cliproxy_plugin_call("auth.login.start", …)
       ▼
Go 插件(本仓库)
       │  fork 子进程组(独立 session,便于整树 kill)
       ▼
Python worker(worker/runner.py)
       │  Camoufox + Playwright 浏览器状态机
       ▼
provider 登录页(kiro / M365 / codex / …)
       │  写出 CLIProxyAPI_<id>.json
       ▼
Go 插件读回 JSON,包成 pluginapi.AuthData
       │
       ▼
CPA 落到 auth-dir,凭据立刻可用
```

刷新走 `auth.refresh` **不跑浏览器** —— Go 里纯 `net/http` POST 到 provider
token 端点,毫秒级返回。详见 [docs/DESIGN.md](docs/DESIGN.md)。

## 安装

### 从 release 装(推荐)

```bash
curl -L https://github.com/greenSheep999/cpa-login-hub/releases/latest/download/cpa-login-hub-darwin-amd64.tar.gz \
  | tar -xzC ~/.cli-proxy-api/plugins/
```

CPA 的 `config.yaml`:

```yaml
plugins:
  enabled: true
  dir: ~/.cli-proxy-api/plugins
  configs:
    cpa-login-hub:
      enabled: true
      priority: 100
```

重启 CPA。第一次登录时会自动装 Python venv(~90 秒),之后就秒开了。

### 从源码装

```bash
git clone https://github.com/greenSheep999/cpa-login-hub.git
cd cpa-login-hub
make install CPA_PLUGIN_DIR=~/.cli-proxy-api/plugins
```

## 依赖

- **CPA (CLIProxyAPI) ≥ v0.9** — 早于此版本还没有插件 ABI
- **Python 3.11+** —— macOS/Linux 自带; Windows 用户去 [python.org](https://python.org) 装
- **Camoufox** —— 首登自动下载 (~150 MB Firefox)
- 到 provider 的出口网络(AWS SSO OIDC / Microsoft Entra / x.ai / ...)

## 使用

装完之后 CPA 管理面板会新出一个 **"Login Hub"** 分组:

1. 选一个 provider (比如 `kiro`)
2. 填参数:IdC 需要 `sso_start_url` + `username` + `password`,M365 需要 `email` + `password`
3. 点 **开始登录** — 插件弹 Camoufox 走完流程
4. 浏览器关掉后凭据自动出现在 CPA 号池

REST API 细节见 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)。

## 路线图

- [x] **v0.1** — 骨架 + kiro IdC(首登 + 续期)
- [ ] **v0.2** — 5 个 provider 全部激活:
  kiro M365、openai/codex(带 SMS 接码)、grok、antigravity(带扫码激活)
- [ ] **v0.3** — 面板前端资源:CPA 里嵌入批量导入 UI
- [ ] **v0.4** — SMS 服务商抽象层(目前只支持 chongpt.xyz)

## 参与开发

欢迎 issue / PR。开发环境搭建见 [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)。

## License

Apache License 2.0 — 详见 [LICENSE](LICENSE)。

## 致谢

- Python worker 来自 [muxhub](https://github.com/daniellee2015/muxhub)
  的 `scripts/login-hub/`,IdC 实现参考了
  [kiro.rs](https://github.com/router-for-me/kiro.rs)。
- Camoufox: [daijro](https://github.com/daijro/camoufox)。
- CPA 插件 ABI:
  [`ag-importer-plugin` 设计文档](https://github.com/router-for-me/CLIProxyAPI/blob/main/docs/design/ag-importer-plugin.md)。
