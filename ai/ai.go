package ai

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Config AI配置
type Config struct {
	Enabled  bool
	APIKey   string
	APIURL   string
	Model    string
	Provider string // AI服务提供商：openai, anthropic, google, baidu, kimi
}

// AnalysisResult AI分析结果
type AnalysisResult struct {
	Success         bool   `json:"success"`
	Vulnerability   string `json:"vulnerability"`
	Target          string `json:"target"`
	Description     string `json:"description"`
	RootCause       string `json:"root_cause"`
	Remediation     string `json:"remediation"`
	Impact          string `json:"impact"`
	Recommendations string `json:"recommendations"`
	Confidence      string `json:"confidence"`
	Timestamp       string `json:"timestamp"`
}

// DefaultConfig 默认配置
var DefaultConfig = &Config{
	Enabled:  false,
	APIURL:   "https://api.openai.com/v1/chat/completions",
	Model:    "gpt-3.5-turbo",
	Provider: "openai",
}

// AnalyzeVulnerability 分析漏洞
func AnalyzeVulnerability(cfg *Config, vulnerabilityID, target, requestPacket, responsePacket string) (*AnalysisResult, error) {
	if !cfg.Enabled {
		return nil, fmt.Errorf("AI功能未启用")
	}

	if cfg.APIKey == "" {
		return nil, fmt.Errorf("AI API Key未配置，请在设置中配置有效的API Key")
	}

	// 构建提示词
	prompt := fmt.Sprintf(`
请详细分析以下漏洞信息：

漏洞ID：%s
目标地址：%s
请求包：
%s

响应包：
%s

请从以下几个方面进行分析：
1. 漏洞成因（详细说明漏洞的技术原理）
2. 漏洞影响（可能造成的安全风险）
3. 整改建议（具体的修复方案）
4. 修复优先级（建议的修复顺序）

请使用结构化的格式返回分析结果，使用中文回复。
`, vulnerabilityID, target, requestPacket, responsePacket)

	// 调用AI API
	result, err := callAIApi(cfg, prompt)
	if err != nil {
		return nil, err
	}

	// 构建分析结果
	analysis := &AnalysisResult{
		Success:       true,
		Vulnerability: vulnerabilityID,
		Target:        target,
		Description:   result,
		Timestamp:     time.Now().Format("2006-01-02 15:04:05"),
		Confidence:    "中",
	}

	return analysis, nil
}

// callAIApi 调用AI API
func callAIApi(cfg *Config, prompt string) (string, error) {
	var jsonData []byte
	var err error
	var authHeader string

	// 根据提供商构建不同的请求体
	switch cfg.Provider {
	case "deepseek":
		requestBody := map[string]interface{}{
			"model": cfg.Model,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"stream": false,
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)
	case "openai":
		// OpenAI API
		requestBody := map[string]interface{}{
			"model": cfg.Model,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"temperature": 0.7,
			"max_tokens":  2000,
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "anthropic":
		// Anthropic Claude API
		requestBody := map[string]interface{}{
			"model": cfg.Model,
			"messages": []map[string]string{
				{
					"role":    "user",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。\n\n" + prompt,
				},
			},
			"temperature": 0.7,
			"max_tokens":  2000,
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "google":
		// Google Gemini API
		requestBody := map[string]interface{}{
			"contents": []map[string]interface{}{
				{
					"parts": []map[string]string{
						{
							"text": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。\n\n" + prompt,
						},
					},
				},
			},
			"generationConfig": map[string]interface{}{
				"temperature":     0.7,
				"maxOutputTokens": 2000,
			},
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "baidu":
		// 百度文心一言API (需要应用密钥)
		requestBody := map[string]interface{}{
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"temperature": 0.7,
			"max_tokens":  2000,
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "kimi":
		// Moonshot Kimi API (兼容OpenAI格式)
		requestBody := map[string]interface{}{
			"model": cfg.Model,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"temperature": 0.7,
			"max_tokens":  2000,
			"stream":      false,
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "zhipu":
		// 智谱 GLM-4.5-Flash API (兼容OpenAI格式)
		requestBody := map[string]interface{}{
			"model": cfg.Model,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。",
				},
				{
					"role":    "assistant",
					"content": "当然，要修复就要懂原理，所以尽量也要提供专业的漏洞原理。",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"thinking": map[string]string{
				"type": "enabled",
			},
			"stream":      false,
			"max_tokens":  65536,
			"temperature": 1.0,
		}
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "huggingface":
		// Hugging Face API (免费)
		// 对于文本生成模型，直接发送字符串即可
		requestBody := prompt
		jsonData, err = json.Marshal(requestBody)
		authHeader = fmt.Sprintf("Bearer %s", cfg.APIKey)

	case "ollama":
		// Ollama本地模型 (不需要API Key)
		requestBody := map[string]interface{}{
			"model": cfg.Model,
			"messages": []map[string]string{
				{
					"role":    "system",
					"content": "你是一位资深的网络安全专家，擅长分析各类漏洞并提供专业的修复建议。",
				},
				{
					"role":    "user",
					"content": prompt,
				},
			},
			"stream": false,
		}
		jsonData, err = json.Marshal(requestBody)
		// Ollama本地不需要API Key
		authHeader = ""

	default:
		return "", fmt.Errorf("不支持的AI服务提供商: %s", cfg.Provider)
	}

	if err != nil {
		return "", fmt.Errorf("序列化请求体失败: %v", err)
	}

	// 创建请求
	req, err := http.NewRequest("POST", cfg.APIURL, bytes.NewBuffer(jsonData))
	if err != nil {
		return "", fmt.Errorf("创建请求失败: %v", err)
	}

	// 设置请求头
	req.Header.Set("Content-Type", "application/json")
	if authHeader != "" {
		req.Header.Set("Authorization", authHeader)
	}

	// 带重试机制发送请求
	maxRetries := 3
	client := &http.Client{Timeout: 90 * time.Second}

	for i := 0; i < maxRetries; i++ {
		resp, err := client.Do(req)
		if err != nil {
			// 超时错误也进行重试
			if i < maxRetries-1 {
				waitTime := time.Duration(1<<uint(i)) * time.Second
				time.Sleep(waitTime)
				continue
			}
			return "", fmt.Errorf("发送请求失败: %v", err)
		}

		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()

		if err != nil {
			return "", fmt.Errorf("读取响应失败: %v", err)
		}

		// 检查响应状态
		if resp.StatusCode == http.StatusOK {
			// 请求成功，解析响应
			var response map[string]interface{}
			if err := json.Unmarshal(body, &response); err != nil {
				return "", fmt.Errorf("解析响应失败: %v", err)
			}

			// 提取返回内容
			switch cfg.Provider {
			case "openai", "kimi", "zhipu", "deepseek":
				if choices, ok := response["choices"].([]interface{}); ok && len(choices) > 0 {
					if choice, ok := choices[0].(map[string]interface{}); ok {
						if message, ok := choice["message"].(map[string]interface{}); ok {
							if content, ok := message["content"].(string); ok {
								return content, nil
							}
						}
					}
				}

			case "anthropic":
				if content, ok := response["content"].([]interface{}); ok && len(content) > 0 {
					if contentItem, ok := content[0].(map[string]interface{}); ok {
						if text, ok := contentItem["text"].(string); ok {
							return text, nil
						}
					}
				}

			case "google":
				if candidates, ok := response["candidates"].([]interface{}); ok && len(candidates) > 0 {
					if candidate, ok := candidates[0].(map[string]interface{}); ok {
						if content, ok := candidate["content"].(map[string]interface{}); ok {
							if parts, ok := content["parts"].([]interface{}); ok && len(parts) > 0 {
								if part, ok := parts[0].(map[string]interface{}); ok {
									if text, ok := part["text"].(string); ok {
										return text, nil
									}
								}
							}
						}
					}
				}

			case "baidu":
				if result, ok := response["result"].(string); ok {
					return result, nil
				}

			case "huggingface":
				// Hugging Face返回的是字符串
				if generatedText, ok := response["generated_text"].(string); ok {
					return generatedText, nil
				}
				// 尝试另一种格式
				if responseArr, ok := response["responses"].([]interface{}); ok && len(responseArr) > 0 {
					if responseStr, ok := responseArr[0].(string); ok {
						return responseStr, nil
					}
				}

			case "ollama":
				if message, ok := response["message"].(map[string]interface{}); ok {
					if content, ok := message["content"].(string); ok {
						return content, nil
					}
				}
			}
			return "", fmt.Errorf("无法提取AI响应内容")
		} else if resp.StatusCode == http.StatusTooManyRequests {
			// 429错误，需要重试
			if i < maxRetries-1 {
				// 使用指数退避策略
				waitTime := time.Duration(1<<uint(i)) * time.Second
				time.Sleep(waitTime)
				continue
			}
			return "", fmt.Errorf("API请求频率过高，已达到最大重试次数，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		} else {
			// 其他错误状态码
			return "", fmt.Errorf("API请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
		}
	}

	return "", fmt.Errorf("请求失败，已达到最大重试次数")
}
