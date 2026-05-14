# 2FAGate — 为任意 Caddy 站点添加双因素认证

超轻量（~15MB）Docker 服务，配合 Caddy `forward_auth` 为网站加上 TOTP 两步验证。

## 工作原理

```
浏览器 → Caddy → forward_auth → 2FA Auth(/auth)
                   ↓ 200            ↑ 302 redirect
                后端服务       /_auth/login  ← 用户输 TOTP → 签发 cookie
```

1. 用户访问受保护域名，Caddy 调用 `/auth` 验证 cookie
2. 无 cookie → 302 跳转到登录页
3. 用户输入 6 位 TOTP 验证码 → 签发 cookie → 跳回
4. 后续带 cookie 的请求直接放行

## 快速开始

### 1. 启动

```bash
docker compose up -d
```

所有密钥首次启动自动生成，无需手动配置。

### 2. 扫码

```bash
docker compose logs auth
```

终端打印 ASCII 二维码，用 Authenticator App 扫码。

### 3. 配置 Caddy

在 `/etc/caddy/Caddyfile` 中添加：

```
你的域名 {
    handle /_auth/* {
        uri strip_prefix /_auth
        reverse_proxy 127.0.0.1:18080
    }
    handle {
        forward_auth 127.0.0.1:18080 {
            uri /auth
        }
        reverse_proxy 你的后端地址
    }
}
```

重载：

```bash
systemctl reload caddy
```

### 4. 验证

访问 `https://你的域名/` → 跳转登录页 → 输 TOTP → 进入后端。

## 配置参考

在 `docker-compose.yml` 中设置：

| 环境变量 | 说明 | 默认值 |
|---|---|---|
| `TOTP_SKEW` | 容差 ±N 个时间窗口（每窗口 30s） | `1` |
| `TOTP_ANTI_REPLAY` | 禁止重复使用同一个码，`false` 关闭 | `true` |
| `COOKIE_MAX_AGE` | cookie 有效期（秒），`0` = 永不过期 | `2592000` (30 天) |
| `ISSUER` | Authenticator App 中显示的名称 | 宿主机 hostname |
| `LISTEN` | 监听地址 | `:8080` |

`COOKIE_SECRET` 和 `TOTP_SECRET` 自动生成，存储在容器内 `/data/`，`docker stop/start` 保留，`docker rm` 后消失。

## 配合已有后端

后端已运行（如 `localhost:3006`），直接改 Caddyfile 的 `reverse_proxy` 指向它即可，不需要本项目的 hello 容器。

## 容器生命周期 & 密钥

```
docker stop  → 密钥保留
docker start → 密钥保留
docker restart → 密钥保留
docker rm    → 密钥清除
docker compose down → 密钥清除
docker compose up -d → 重新生成
```

每次 `rm` 后启动会重新生成 TOTP 密钥，需重新扫码。
