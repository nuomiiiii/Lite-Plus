# Linux 一键更新与回退

Lite 会在版本接口中返回部署类型：`docker`、`linux`、`windows` 或 `unknown`。

Linux 一键更新面向使用官方安装脚本管理的直接安装，包括 systemd 主机和 OpenWrt / iStoreOS 等 procd 软路由。兼容以下常见环境：

- Ubuntu 18.04+
- Debian 9+
- CentOS / RHEL 7+
- Rocky Linux / AlmaLinux 8+
- OpenWrt / iStoreOS 等带 procd 的软路由（需官方 Linux 架构包）

更新器不调用 `apt`、`dnf` 或 `yum`，而是使用与发行版无关的静态 Linux 二进制。systemd 环境用临时更新助手；procd 环境用 `start-stop-daemon` 或 `setsid` 拉起同样的助手，避免停止 Lite 时把更新进程一起杀掉。实际是否可用以运行时能力检测为准。

后台「立即更新」在部署类型为 `linux` 且能力检测通过时可用。安装脚本会写入 `LITE_DEPLOYMENT=linux`，systemd 写入 `lite.service`，软路由写入 `/etc/init.d/lite` 和 pid 文件。

## 更新事务

1. 从 `nuomiiiii/Lite-Plus` 的 GitHub Release 下载当前 CPU 架构的文件。
2. 使用 `lite-update.json` 校验版本号、七位构建标识、文件大小和 SHA-256。资产名是 `Lite-$GOOS-$GOARCH`。
3. 由独立更新助手停止 Lite（systemd 临时服务，或软路由上已脱离服务进程组的助手）。
4. 冷备份当前程序和完整 `data` 目录。
5. 原子替换程序并重新启动服务。
6. 持续检查版本接口；新服务稳定运行后才确认成功。
7. 启动失败、版本不符或健康检查中断时，同时恢复旧程序和更新前数据。

更新助手会记录事务阶段。助手自身异常退出后，systemd 会再次启动它并继续回退；procd 环境则依赖已脱离的助手进程继续完成回退。成功更新会保留最近两份回退快照。

## 不启用一键更新的情况

- Docker：保留 GitHub 更新入口，应由宿主机更新镜像并重建容器。
- Windows：保留 GitHub 更新入口，不能复用 Linux 的更新流程。
- 非 root、当前进程不是安装脚本登记的服务主进程，或软路由缺少 `start-stop-daemon` / `setsid` / `nohup`。
- 主数据库或 SQLite 指标库位于受管 `data` 目录之外。
- 指标数据使用外部 MySQL/PostgreSQL。Lite 无法替外部数据库制作可验证的回退快照，因此不会承诺一键回退。
- `data` 是独立挂载点。此布局无法通过目录交换完成原子数据回退。
