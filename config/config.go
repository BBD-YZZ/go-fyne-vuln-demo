package config

import (
	"os"
	"vuln-scan/webhook"

	"gopkg.in/ini.v1"
)

const (
	ConfigFile = "config.ini"
)

// Config 应用配置结构体
type Config struct {
	Proxy       ProxyConfig
	Ceye        CeyeConfig
	MessagePush MessagePushConfig
	AI          AIConfig
}

// ProxyConfig 代理配置
type ProxyConfig struct {
	Type     string
	Host     string
	Port     string
	Username string
	Password string
}

// CeyeConfig CEYE配置
type CeyeConfig struct {
	Type   string
	Token  string
	Domain string
}

// MessagePushConfig 消息推送配置
type MessagePushConfig struct {
	Platform webhook.PlatformType
	URL      string
	Token    string
	Secret   string
}

// AIConfig AI配置
type AIConfig struct {
	APIKey   string
	APIURL   string
	Model    string
	Provider string
}

// LoadConfig 加载配置
func LoadConfig() (*Config, error) {
	configPath := getConfigPath()

	// 如果配置文件不存在，返回默认配置
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		return &Config{
			Proxy: ProxyConfig{
				Type:     "http",
				Host:     "",
				Port:     "",
				Username: "",
				Password: "",
			},
			Ceye: CeyeConfig{
				Type:   "dns",
				Token:  "",
				Domain: "",
			},
			MessagePush: MessagePushConfig{
				Platform: webhook.PlatformWeChat,
				URL:      "",
				Token:    "",
				Secret:   "",
			},
			AI: AIConfig{
				APIKey:   "",
				APIURL:   "https://api.openai.com/v1/chat/completions",
				Model:    "gpt-3.5-turbo",
				Provider: "openai",
			},
		}, nil
	}

	// 加载INI文件
	cfg, err := ini.Load(configPath)
	if err != nil {
		return nil, err
	}

	config := &Config{}

	// 加载代理配置
	proxySection := cfg.Section("proxy")
	config.Proxy.Type = proxySection.Key("type").MustString("http")
	config.Proxy.Host = proxySection.Key("host").MustString("")
	config.Proxy.Port = proxySection.Key("port").MustString("")
	config.Proxy.Username = proxySection.Key("username").MustString("")
	config.Proxy.Password = proxySection.Key("password").MustString("")

	// 加载CEYE配置
	ceyeSection := cfg.Section("ceye")
	config.Ceye.Type = ceyeSection.Key("type").MustString("dns")
	config.Ceye.Token = ceyeSection.Key("token").MustString("")
	config.Ceye.Domain = ceyeSection.Key("domain").MustString("")

	// 加载消息推送配置
	messagePushSection := cfg.Section("message_push")
	platformStr := messagePushSection.Key("platform").MustString("wechat")
	config.MessagePush.Platform = webhook.PlatformType(platformStr)
	config.MessagePush.URL = messagePushSection.Key("url").MustString("")
	config.MessagePush.Token = messagePushSection.Key("token").MustString("")
	config.MessagePush.Secret = messagePushSection.Key("secret").MustString("")

	// 加载AI配置
	aiSection := cfg.Section("ai")
	config.AI.APIKey = aiSection.Key("api_key").MustString("")
	config.AI.APIURL = aiSection.Key("api_url").MustString("https://api.openai.com/v1/chat/completions")
	config.AI.Model = aiSection.Key("model").MustString("gpt-3.5-turbo")
	config.AI.Provider = aiSection.Key("provider").MustString("openai")

	return config, nil
}

// SaveConfig 保存配置
func SaveConfig(config *Config) error {
	cfg := ini.Empty()

	// 保存代理配置
	proxySection := cfg.Section("proxy")
	proxySection.Key("type").SetValue(config.Proxy.Type)
	proxySection.Key("host").SetValue(config.Proxy.Host)
	proxySection.Key("port").SetValue(config.Proxy.Port)
	proxySection.Key("username").SetValue(config.Proxy.Username)
	proxySection.Key("password").SetValue(config.Proxy.Password)

	// 保存CEYE配置
	ceyeSection := cfg.Section("ceye")
	ceyeSection.Key("type").SetValue(config.Ceye.Type)
	ceyeSection.Key("token").SetValue(config.Ceye.Token)
	ceyeSection.Key("domain").SetValue(config.Ceye.Domain)

	// 保存消息推送配置
	messagePushSection := cfg.Section("message_push")
	messagePushSection.Key("platform").SetValue(string(config.MessagePush.Platform))
	messagePushSection.Key("url").SetValue(config.MessagePush.URL)
	messagePushSection.Key("token").SetValue(config.MessagePush.Token)
	messagePushSection.Key("secret").SetValue(config.MessagePush.Secret)

	// 保存AI配置
	aiSection := cfg.Section("ai")
	aiSection.Key("api_key").SetValue(config.AI.APIKey)
	aiSection.Key("api_url").SetValue(config.AI.APIURL)
	aiSection.Key("model").SetValue(config.AI.Model)
	aiSection.Key("provider").SetValue(config.AI.Provider)

	// 写入文件
	configPath := getConfigPath()
	return cfg.SaveTo(configPath)
}

// getConfigPath 获取配置文件路径
func getConfigPath() string {
	// 使用当前工作目录
	return ConfigFile
}
