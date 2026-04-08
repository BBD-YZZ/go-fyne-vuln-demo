package webhook

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
	"vuln-scan/client"

	"github.com/google/uuid"
)

// PlatformType 消息平台类型
type PlatformType string

const (
	PlatformWeLink   PlatformType = "welink"   // 华为云WeLink
	PlatformWeChat   PlatformType = "wechat"   // 企业微信
	PlatformDingTalk PlatformType = "dingtalk" // 钉钉
	PlatformFeishu   PlatformType = "feishu"   // 飞书
)

// WebhookConfig 配置结构体
type WebhookConfig struct {
	Platform   PlatformType `json:"platform"`   // 平台类型
	URL        string       `json:"url"`        // Webhook URL
	Token      string       `json:"token"`      // Token（部分平台需要）
	Secret     string       `json:"secret"`     // 签名密钥（部分平台需要）
	IsAt       bool         `json:"isAt"`       // 是否@特定人员
	IsAtAll    bool         `json:"isAtAll"`    // 是否@所有人
	AtAccounts []string     `json:"atAccounts"` // @人员列表
}

// MessageRequest WeLink消息请求结构体
type MessageRequest struct {
	MessageType string   `json:"messageType"`
	Content     Content  `json:"content"`
	TimeStamp   int64    `json:"timeStamp"`
	UUID        string   `json:"uuid"`
	IsAt        bool     `json:"isAt"`
	IsAtAll     bool     `json:"isAtAll"`
	AtAccounts  []string `json:"atAccounts"`
}

// Content WeLink消息内容结构体
type Content struct {
	Text string `json:"text"`
}

// WeChatMessage 企业微信消息结构体
type WeChatMessage struct {
	MsgType string     `json:"msgtype"`
	Text    WeChatText `json:"text"`
}

// WeChatText 企业微信文本消息
type WeChatText struct {
	Content             string   `json:"content"`
	MentionedList       []string `json:"mentioned_list,omitempty"`
	MentionedMobileList []string `json:"mentioned_mobile_list,omitempty"`
}

// DingTalkMessage 钉钉消息结构体
type DingTalkMessage struct {
	MsgType string       `json:"msgtype"`
	Text    DingTalkText `json:"text"`
	At      DingTalkAt   `json:"at,omitempty"`
}

// DingTalkText 钉钉文本消息
type DingTalkText struct {
	Content string `json:"content"`
}

// DingTalkAt 钉钉@信息
type DingTalkAt struct {
	AtMobiles []string `json:"atMobiles,omitempty"`
	AtUserIds []string `json:"atUserIds,omitempty"`
	IsAtAll   bool     `json:"isAtAll"`
}

// FeishuMessage 飞书消息结构体
type FeishuMessage struct {
	MsgType string        `json:"msg_type"`
	Content FeishuContent `json:"content"`
}

// FeishuContent 飞书消息内容
type FeishuContent struct {
	Text string `json:"text"`
}

// sendHTTPRequest 发送HTTP请求
func sendHTTPRequest(url string, proxyStr string, body []byte) error {
	clientcfg := &client.ClientConfig{
		TimeOut:            10 * time.Second,
		ProxyURL:           proxyStr,
		InsecureSkipVerify: true,
		DefaultHeader: map[string]string{
			"Content-Type":   "application/json",
			"Accept-Charset": "UTF-8",
		},
	}

	cli, err := client.NewClient(clientcfg)
	if err != nil {
		return fmt.Errorf("创建客户端失败: %v", err)
	}
	defer cli.Close()

	requestCfg := &client.RequestConfig{
		Body: body,
	}

	resp, err := cli.Post(url, requestCfg)
	if err != nil {
		return fmt.Errorf("发送POST请求失败: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("请求失败，状态码: %d，响应内容: %s", resp.StatusCode, resp.Body)
	}

	return nil
}

// sendWeLinkMessage 发送WeLink消息
func sendWeLinkMessage(config *WebhookConfig, proxyStr string, message string) error {
	if config.Token == "" && config.URL == "" {
		return fmt.Errorf("WeLink Token和URL不能同时为空")
	}

	request := MessageRequest{
		MessageType: "text",
		Content: Content{
			Text: message,
		},
		TimeStamp:  time.Now().UnixMilli(),
		UUID:       uuid.New().String(),
		IsAt:       config.IsAt,
		IsAtAll:    config.IsAtAll,
		AtAccounts: config.AtAccounts,
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %v", err)
	}

	url := config.URL
	if url == "" {
		url = fmt.Sprintf("https://open.welink.huaweicloud.com/api/werobot/v1/webhook/send?token=%s&channel=standard", config.Token)
	}

	return sendHTTPRequest(url, proxyStr, requestBody)
}

// sendWeChatMessage 发送企业微信消息
func sendWeChatMessage(config *WebhookConfig, proxyStr string, message string) error {
	var mentionedList []string
	if config.IsAtAll {
		mentionedList = append(mentionedList, "@all")
	} else if config.IsAt {
		mentionedList = config.AtAccounts
	}

	request := WeChatMessage{
		MsgType: "text",
		Text: WeChatText{
			Content:       message,
			MentionedList: mentionedList,
		},
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %v", err)
	}

	return sendHTTPRequest(config.URL, proxyStr, requestBody)
}

// sendDingTalkMessage 发送钉钉消息
func sendDingTalkMessage(config *WebhookConfig, proxyStr string, message string) error {
	// 生成时间戳
	timestamp := strconv.FormatInt(time.Now().UnixMilli(), 10)

	// 生成签名
	sign := ""
	if config.Secret != "" {
		stringToSign := timestamp + "\n" + config.Secret
		h := hmac.New(sha256.New, []byte(config.Secret))
		h.Write([]byte(stringToSign))
		signData := h.Sum(nil)
		sign = url.QueryEscape(base64.StdEncoding.EncodeToString(signData))
	}

	// 构建完整URL
	requestURL := config.URL
	if sign != "" {
		if url.QueryEscape(requestURL) != requestURL {
			// URL已经包含参数
			requestURL += "&timestamp=" + timestamp + "&sign=" + sign
		} else {
			// URL不包含参数
			requestURL += "?timestamp=" + timestamp + "&sign=" + sign
		}
	}

	request := DingTalkMessage{
		MsgType: "text",
		Text: DingTalkText{
			Content: message,
		},
		At: DingTalkAt{
			AtUserIds: config.AtAccounts,
			IsAtAll:   config.IsAtAll,
		},
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %v", err)
	}

	return sendHTTPRequest(requestURL, proxyStr, requestBody)
}

// sendFeishuMessage 发送飞书消息
func sendFeishuMessage(config *WebhookConfig, proxyStr string, message string) error {
	request := FeishuMessage{
		MsgType: "text",
		Content: FeishuContent{
			Text: message,
		},
	}

	requestBody, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("序列化请求体失败: %v", err)
	}

	return sendHTTPRequest(config.URL, proxyStr, requestBody)
}

// SendVulnerabilityAlert 发送漏洞告警消息
func SendVulnerabilityAlert(config *WebhookConfig, proxyStr string, target string, vulnType string, messageinfo ...string) error {
	msg := ""
	if len(messageinfo) != 0 {
		msg = messageinfo[0]
	}

	message := fmt.Sprintf("⚠️ 漏洞告警 ⚠️\n目标地址: %s\n漏洞类型: %s\n发现时间: %s\n漏洞详情: \n%s",
		target, vulnType, time.Now().Format("2006-01-02 15:04:05"), msg)

	switch config.Platform {
	case PlatformWeLink:
		return sendWeLinkMessage(config, proxyStr, message)
	case PlatformWeChat:
		return sendWeChatMessage(config, proxyStr, message)
	case PlatformDingTalk:
		return sendDingTalkMessage(config, proxyStr, message)
	case PlatformFeishu:
		return sendFeishuMessage(config, proxyStr, message)
	default:
		return fmt.Errorf("不支持的平台类型: %s", config.Platform)
	}
}

// config := &wekhook.WebhookConfig{
//     Platform:   wekhook.PlatformWeChat,
//     URL:        "https://qyapi.weixin.qq.com/cgi-bin/webhook/send?key=xxx",
//     IsAtAll:    true,
// }

// config := &wekhook.WebhookConfig{
//     Platform:   wekhook.PlatformDingTalk,
//     URL:        "https://oapi.dingtalk.com/robot/send?access_token=xxx",
//     IsAtAll:    true,
// }

// config := &wekhook.WebhookConfig{
//     Platform:   wekhook.PlatformFeishu,
//     URL:        "https://open.feishu.cn/open-apis/bot/v2/hook/xxx",
// }

// err := wekhook.SendVulnerabilityAlert(config, "https://example.com", "CVE-2023-1234")

// // 在CheckButtonFunc函数中添加
// if 发现漏洞 {
//     go func() {
//         config := &wekhook.WebhookConfig{
//             Token:      "your_token",
//             Channel:    "standard",
//             IsAtAll:    true,
//         }
//         err := wekhook.SendVulnerabilityAlert(config, target, vuln)
//         if err != nil {
//             AppendLogEntry("ERROR", fmt.Sprintf("发送告警失败: %v", err), win.LoggerScroll, win.LoggerContainer, 100)
//         }
//     }()
// }
