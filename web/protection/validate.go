package protection

import (
	"fmt"
	"strconv"
	"strings"

	v2 "github.com/nuomiiiii/lite/protocol/v2"
)

func NormalizeConfig(cfg v2.ProtectionConfig) (v2.ProtectionConfig, error) {
	var whitelist []string
	seen := map[string]struct{}{}
	for _, item := range cfg.Whitelist {
		ip, ok := v2.NormalizeProtectionIP(item)
		if !ok {
			return cfg, fmt.Errorf("白名单包含无效 IP")
		}
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		whitelist = append(whitelist, ip)
	}
	cfg.Whitelist = whitelist
	for i := range cfg.Sources {
		src, err := normalizeSource(cfg.Sources[i])
		if err != nil {
			return cfg, err
		}
		cfg.Sources[i] = src
	}
	ids := map[string]struct{}{}
	for i := range cfg.Policies {
		pol, err := normalizePolicy(cfg.Policies[i])
		if err != nil {
			return cfg, err
		}
		if pol.SourceID != "" {
			found := false
			for _, src := range cfg.Sources {
				if src.ID == pol.SourceID {
					found = true
					if src.Format == v2.ProtectionLogSSHD {
						pol.Paths = nil
						pol.PathThreshold = 0
						pol.PathWindowSec = 0
						pol.PathStatus = nil
					}
					if src.DeployMode == v2.ProtectionDeployProxy && pol.Mode == v2.ProtectionModeEnforce {
						return cfg, fmt.Errorf("代理后来源只能观察，不能在本机 nft 执行封禁")
					}
					if strings.TrimSpace(pol.BindAddr) != "" && policyDetectsFromLogs(pol) {
						if err := sourceCoversBindAddr(src, pol.BindAddr); err != nil {
							return cfg, err
						}
					}
					break
				}
			}
			if !found {
				return cfg, fmt.Errorf("策略引用了不存在的日志来源")
			}
		} else if strings.TrimSpace(pol.BindAddr) != "" && policyDetectsFromLogs(pol) {
			return cfg, fmt.Errorf("限定本地地址的请求或路径策略需要指定日志来源")
		}
		if _, ok := ids[pol.ID]; ok {
			return cfg, fmt.Errorf("策略 ID 重复")
		}
		ids[pol.ID] = struct{}{}
		cfg.Policies[i] = pol
	}
	var sshd int
	for _, src := range cfg.Sources {
		if strings.TrimSpace(src.Format) == v2.ProtectionLogSSHD {
			sshd++
		}
	}
	if sshd > 1 {
		return cfg, fmt.Errorf("同一节点只能接入一条 SSH 日志，journal 和文件日志同时接会把一次失败计两次")
	}
	return cfg, nil
}

func normalizeSource(src v2.ProtectionLogSource) (v2.ProtectionLogSource, error) {
	src.ID = strings.TrimSpace(src.ID)
	src.Path = strings.TrimSpace(src.Path)
	src.Format = strings.TrimSpace(src.Format)
	src.DeployMode = strings.TrimSpace(src.DeployMode)
	if src.DeployMode == "" {
		src.DeployMode = v2.ProtectionDeployDirect
	}
	if src.DeployMode != v2.ProtectionDeployDirect && src.DeployMode != v2.ProtectionDeployProxy {
		return src, fmt.Errorf("未知部署模式")
	}
	if !v2.ValidProtectionLogFormat(src.Format) {
		return src, fmt.Errorf("不支持的日志格式")
	}
	if src.Format == v2.ProtectionLogSSHD {
		if src.DeployMode != v2.ProtectionDeployDirect {
			return src, fmt.Errorf("SSH 日志只能直连检测")
		}
		src.BindProtocol = strings.ToLower(strings.TrimSpace(src.BindProtocol))
		if src.BindProtocol == "" {
			src.BindProtocol = v2.FirewallProtoTCP
		}
		if src.BindProtocol != v2.FirewallProtoTCP {
			return src, fmt.Errorf("SSH 日志来源需要绑定 TCP")
		}
		port := strings.TrimSpace(src.BindPort)
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return src, fmt.Errorf("SSH 日志来源需要绑定 SSH 端口")
		}
		src.BindPort = port
		src.HostFilter = ""
		if v2.IsProtectionJournalPath(src.Path) {
			src.Path = v2.ProtectionJournalSSHD
		} else if src.Path == "" || !linuxAbsolutePath(src.Path) {
			return src, fmt.Errorf("SSH 日志路径必须是绝对路径或 journal:sshd")
		}
	} else if src.Path == "" || !linuxAbsolutePath(src.Path) {
		return src, fmt.Errorf("日志路径必须是绝对路径")
	}
	if src.Format == v2.ProtectionLogNginxCombined {
		if strings.TrimSpace(src.BindPort) == "" || strings.TrimSpace(src.BindProtocol) == "" {
			return src, fmt.Errorf("Nginx combined 需要绑定协议和端口")
		}
		if strings.Contains(src.BindPort, ",") {
			return src, fmt.Errorf("Nginx combined 不能绑定多个端口")
		}
	}
	if strings.TrimSpace(src.BindAddr) != "" {
		ip, ok := v2.NormalizeProtectionIP(src.BindAddr)
		if !ok {
			return src, fmt.Errorf("日志来源本地地址无效")
		}
		src.BindAddr = ip
	}
	return src, nil
}

func policyDetectsFromLogs(pol v2.ProtectionPolicy) bool {
	if pol.RequestThreshold > 0 && pol.RequestWindowSec > 0 {
		return true
	}
	return len(pol.Paths) > 0 && pol.PathThreshold > 0 && pol.PathWindowSec > 0
}

func sourceCoversBindAddr(src v2.ProtectionLogSource, bind string) error {
	bindIP, ok := v2.NormalizeProtectionIP(bind)
	if !ok {
		return fmt.Errorf("本地地址无效")
	}
	if src.BindAddr != "" {
		if src.BindAddr != bindIP {
			return fmt.Errorf("日志来源绑定地址与策略不一致")
		}
		return nil
	}
	if src.Format == v2.ProtectionLogNginxJSON {
		return nil
	}
	return fmt.Errorf("限定本地地址的日志策略需要来源绑定该地址，或使用带目标地址的 Nginx JSON")
}

func linuxAbsolutePath(path string) bool {
	path = strings.TrimSpace(path)
	if path == "" || strings.ContainsAny(path, `\:`) {
		return false
	}
	return strings.HasPrefix(path, "/")
}

func normalizePolicy(pol v2.ProtectionPolicy) (v2.ProtectionPolicy, error) {
	pol.ID = strings.TrimSpace(pol.ID)
	pol.Name = strings.TrimSpace(pol.Name)
	pol.Mode = strings.TrimSpace(pol.Mode)
	pol.Protocol = strings.ToLower(strings.TrimSpace(pol.Protocol))
	pol.Port = strings.TrimSpace(pol.Port)
	if pol.ID == "" {
		return pol, fmt.Errorf("策略缺少 ID")
	}
	if pol.Mode == "" {
		pol.Mode = v2.ProtectionModeObserve
	}
	if pol.Mode != v2.ProtectionModeObserve && pol.Mode != v2.ProtectionModeEnforce {
		return pol, fmt.Errorf("策略模式无效")
	}
	if pol.Protocol == "" {
		pol.Protocol = v2.FirewallProtoTCP
	}
	if pol.Protocol != v2.FirewallProtoTCP && pol.Protocol != v2.FirewallProtoUDP {
		return pol, fmt.Errorf("策略只支持 tcp 或 udp")
	}
	if pol.Port == "" {
		return pol, fmt.Errorf("策略需要目标端口")
	}
	if pol.Port != "*" {
		n, err := strconv.Atoi(pol.Port)
		if err != nil || n < 1 || n > 65535 {
			return pol, fmt.Errorf("端口无效")
		}
	}
	if strings.TrimSpace(pol.BindAddr) != "" {
		if _, ok := v2.NormalizeProtectionIP(pol.BindAddr); !ok {
			return pol, fmt.Errorf("本地地址无效")
		}
	}
	pol.BanDurationSec = v2.NormalizeProtectionBanSec(pol.BanDurationSec)
	if pol.RequestThreshold < 0 || pol.RequestWindowSec < 0 || pol.PathThreshold < 0 || pol.PathWindowSec < 0 {
		return pol, fmt.Errorf("阈值无效")
	}
	return pol, nil
}
