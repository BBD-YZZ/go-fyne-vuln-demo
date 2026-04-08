package dnslog

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"time"
	"vuln-scan/client"
	"vuln-scan/tools"
)

const (
	HTTP string = "http"
	DNS  string = "dns"
)

type CeyeConfig struct {
	Type      string
	Token     string
	Domain    string
	Enabled   bool
	FilterStr string // 生成的随机过滤字符串
}

type CeyeRecord struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Type       string `json:"type"`
	RemoteAddr string `json:"remote_addr"`
	CreatedAt  string `json:"created_at"`
}

type CeyeMeta struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

type CeyeResponse struct {
	Meta CeyeMeta     `json:"meta"`
	Data []CeyeRecord `json:"data"`
}

func (c *CeyeConfig) IsValid() bool {
	if !c.Enabled {
		return false
	}
	return c.Token != "" && c.Domain != "" && c.Type != "" && tools.IsDomainOrIP(c.Domain)
}

func CheckCeyeRecord(cfg *CeyeConfig, domain string) (bool, []CeyeRecord, error) {
	if cfg == nil {
		return false, nil, nil
	}

	if !cfg.IsValid() {
		return false, nil, nil
	}

	if domain == "" {
		return false, nil, nil
	}

	filter := strings.Split(strings.TrimSpace(domain), ".")
	if len(filter) != 4 {
		return false, nil, nil
	}

	getRecordsUrl := fmt.Sprintf("http://api.ceye.io/v1/records?token=%s&type=%s&filter=%s", cfg.Token, cfg.Type, filter[0])
	clientCfg := client.ClientConfig{
		TimeOut:            30 * time.Second,
		InsecureSkipVerify: true,
		UserAgent:          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0 Safari/537.36",
	}

	client, err := client.NewClient(&clientCfg)
	if err != nil {
		return false, nil, err
	}

	resp, err := client.Get(getRecordsUrl)
	if err != nil {
		return false, nil, err
	}
	defer client.Close()

	if resp.StatusCode != 200 {
		return false, nil, fmt.Errorf("ceye api status code: %d", resp.StatusCode)
	}
	var ceyeResp CeyeResponse
	if err := json.NewDecoder(bytes.NewReader(resp.BodyBytes)).Decode(&ceyeResp); err != nil {
		return false, nil, err
	}
	if ceyeResp.Meta.Code != 200 {
		return false, nil, fmt.Errorf("ceye api error: %s", ceyeResp.Meta.Message)
	}

	if len(ceyeResp.Data) == 0 {
		return false, nil, nil
	}

	return true, ceyeResp.Data, nil
}

func (cfg *CeyeConfig) GetCeyeFilterDoamin() string {
	if cfg == nil {
		return ""
	}

	if !cfg.IsValid() {
		return ""
	}

	// 如果FilterStr为空，生成随机字符串
	if cfg.FilterStr == "" {
		cfg.FilterStr = tools.GenerateStr(10)
	}

	domain := fmt.Sprintf("%s.%s", cfg.FilterStr, cfg.Domain)
	return domain
}
