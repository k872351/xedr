package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// upgradeHTTPClient 与 API 客户端对齐 TLS 策略：默认校验证书；仅 cfg.Insecure 可跳过。
func upgradeHTTPClient(cfg Config) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	if cfg.Insecure {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec
	}
	return &http.Client{Timeout: 3 * time.Minute, Transport: tr}
}

// validateUpgradeURL 生产默认要求 HTTPS；仅 Insecure 调试模式允许 http://。
func validateUpgradeURL(cfg Config, url string) error {
	u := strings.TrimSpace(url)
	if u == "" {
		return fmt.Errorf("缺少升级 URL")
	}
	if strings.HasPrefix(u, "https://") {
		return nil
	}
	if strings.HasPrefix(u, "http://") {
		if cfg.Insecure {
			return nil
		}
		return fmt.Errorf("生产升级禁止明文 HTTP，请使用 HTTPS（或显式 insecure_skip_verify 仅用于调试）")
	}
	if strings.HasPrefix(u, "/") {
		return nil // 相对路径，由 ServerURL 决定
	}
	return fmt.Errorf("非法升级 URL")
}

func normalizeUpgradeSHA256(want string) (string, error) {
	s := strings.ToLower(strings.TrimSpace(want))
	if len(s) != 64 {
		return "", fmt.Errorf("sha256 必须为 64 位十六进制，实际长度 %d", len(s))
	}
	for _, c := range s {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return "", fmt.Errorf("sha256 含非法字符")
		}
	}
	return s, nil
}
