# v2ray-agent (sing-box 精简版)

基于 [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) 精简修改，仅保留 sing-box 核心。

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL%20v3-blue.svg)](https://www.gnu.org/licenses/agpl-3.0)

## 功能

### 支持的协议

| 协议 | 说明 |
|------|------|
| VLESS + Vision + TCP | 基础协议 |
| VLESS + TLS + WS | CDN 友好 |
| VMess + TLS + WS | CDN 友好 |
| Trojan + TLS | 传统协议 |
| Hysteria2 | UDP 高速协议 |
| VLESS + Reality + Vision | 无需域名 |
| VLESS + Reality + gRPC | 无需域名 |
| Tuic | UDP 协议 |
| Naive | HTTP/2 代理 |
| VMess + HTTPUpgrade | CDN 友好 |
| AnyTLS | TLS 伪装 |
| Socks5 | 入站/出站支持 |

### 主要功能

- **自动 TLS**: 自动申请和续订 SSL 证书
- **用户管理**: 添加/删除/查看用户
- **分流工具**: 按入站协议分流，支持 Socks5 出站转发
- **订阅支持**: 生成和管理订阅链接
- **伪装站管理**: Nginx 伪装站点配置
- **CDN 节点管理**: 优选 IP 配置
- **WARP/IPv6 分流**: 支持第三方 IP 出站

## 快速开始

### 安装

```bash
wget -P /root -N --no-check-certificate "https://raw.githubusercontent.com/taozle/v2ray-agent/master/install.sh" && chmod 700 /root/install.sh && /root/install.sh
```

### 使用

安装后，运行以下命令可再次打开管理菜单:

```bash
vasma
```

## 菜单结构

```
1. 安装/重新安装
2. 任意组合安装
4. Hysteria2 管理
5. Reality 管理
6. Tuic 管理
─────────────────
7. 用户管理
8. 伪装站管理
9. 证书管理
10. CDN 节点管理
11. 分流工具
─────────────────
16. Core 管理
17. 更新脚本
18. 安装 BBR
─────────────────
20. 卸载脚本
```

## 分流工具使用

分流工具支持按入站协议将流量转发到指定的 Socks5 服务器：

1. 菜单选择 `11.分流工具`
2. 选择 `1.添加分流`
3. 选择要分流的入站协议（如 VLESSTCP、VLESSWS 等）
4. 配置 Socks5 出站服务器（IP、端口、可选认证）
5. 该入站的所有流量将自动转发到 Socks5 出站

## 相关文档

- [原版脚本教程](https://www.v2ray-agent.com/archives/1710141233)
- [脚本快速搭建教程](https://www.v2ray-agent.com/archives/1682491479771)
- [VPS 选购攻略](https://www.v2ray-agent.com/archives/1679975663984)

## 与原版区别

| 功能 | 原版 | 精简版 |
|------|------|--------|
| Xray-core | ✅ | ❌ |
| sing-box | ✅ | ✅ |
| 域名黑名单 | ✅ | ❌ |
| BT 下载管理 | ✅ | ❌ |
| 多端口配置 | ✅ | ❌ |
| DNS/SNI 分流 | ✅ | ❌ |
| 入站分流 | ❌ | ✅ |
| Socks5 入站 | ❌ | ✅ |

## 致谢

- [mack-a/v2ray-agent](https://github.com/mack-a/v2ray-agent) - 原版脚本
- [SagerNet/sing-box](https://github.com/SagerNet/sing-box) - sing-box 核心

## 许可证

本项目根据 [AGPL-3.0 许可证](LICENSE) 授权。
