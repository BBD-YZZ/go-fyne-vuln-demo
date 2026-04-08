package client

import (
	"fmt"
	"net/url"
	"strings"
	"time"
	"vuln-scan/tools"
)

const (
	HTTP   string = "http"
	SOCKS5 string = "socks5"
)

type ProxyConfig struct {
	Enable   bool   // 是否启用代理
	Type     string // 代理类型
	Host     string // 代理主机
	Port     string // 代理端口
	Username string // 代理用户名
	Password string // 代理密码
}

func NewProxyConfig(enable bool, proxyType string, host, port, username, password string) *ProxyConfig {
	return &ProxyConfig{Enable: enable, Type: proxyType, Host: host, Port: port, Username: username, Password: password}
}

func (p *ProxyConfig) CheckProxyConfig() bool {
	if !p.Enable {
		return true // 未启用代理，直接返回true
	}

	if p.Type != HTTP && p.Type != SOCKS5 {
		return false // 代理类型无效，返回false
	}
	if p.Host == "" {
		return false // 代理主机不能为空，返回false
	}
	if p.Port == "" {
		return false // 代理端口不能为空，返回false
	}
	if !tools.IsDomainOrIP(p.Host) {
		return false // 代理主机不是域名或IP地址，返回false
	}

	_, err := url.Parse(fmt.Sprintf("http://%s:%s", p.Host, p.Port))
	if err != nil {
		return false // 代理端口格式无效，返回false
	}
	return true // 代理配置有效，返回true
}

func (p *ProxyConfig) GetProxyUrl() string {
	if !p.Enable || !p.CheckProxyConfig() {
		return "" // 未启用代理或代理配置无效，返回空字符串
	}

	var proxyURL string
	if p.Username != "" && p.Password != "" {
		proxyURL = fmt.Sprintf("%s://%s:%s@%s:%s", strings.ToLower(p.Type), p.Username, p.Password, p.Host, p.Port)
	} else {
		proxyURL = fmt.Sprintf("%s://%s:%s", strings.ToLower(p.Type), p.Host, p.Port)
	}
	return proxyURL
}

// CheckProxyUse 检查代理是否可用，返回true表示可用，false表示不可用
// maxResponseLength 可选参数，指定响应最大长度，默认为0表示输出完整响应，大于0表示截取指定长度
func (p *ProxyConfig) CheckProxyUse(maxResponseLength ...int) bool {
	if !p.Enable || !p.CheckProxyConfig() {
		return false // 未启用代理或代理配置无效，返回false
	}

	proxyStr := p.GetProxyUrl()

	client, err := NewClient(&ClientConfig{
		TimeOut:            5 * time.Second,
		ProxyURL:           proxyStr,
		InsecureSkipVerify: true,
		// DisableCompression: true,
	})
	if err != nil {
		return false // 创建客户端失败，返回false
	}
	defer client.Close()

	resp, err := client.Get("https://www.baidu.com")
	if err != nil {
		return false // 发送请求失败，返回false
	}

	if resp.StatusCode != 200 {
		return false // 响应状态码不是200，返回false
	}

	fmt.Println(resp.RequestPacket.ToString())
	if len(maxResponseLength) > 0 && len(resp.ResponsePacket.RawResponse) > maxResponseLength[0] {
		fmt.Println(resp.ResponsePacket.ToStringWithLimit(maxResponseLength[0]))
	} else {
		fmt.Println(resp.ResponsePacket.ToString())
	}
	return true // 代理使用成功，返回true
}
