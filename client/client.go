package client

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/goquery"
	"golang.org/x/net/proxy"
	"golang.org/x/net/publicsuffix"
)

// ClientConfig 客户端配置
// 用于设置客户端的全局配置，如超时时间、是否跳过证书验证、是否遵循重定向等。
// 默认值为:
// TimeOut: 5 * time.Second
// InsecureSkipVerify: 默认跳过证书验证
// FollowRedirects: false (默认不跟随重定向)
// DisableCompression: true 默认禁用压缩
// MaxRedirects: 5
type ClientConfig struct {
	TimeOut             time.Duration     // 超时时间
	InsecureSkipVerify  bool              // 是否跳过证书验证 (默认false，不跳过)
	FollowRedirects     bool              // 是否遵循重定向 (默认false，不跟随)
	MaxRedirects        int               // 最大重定向次数 (默认5)
	DisableCompression  bool              // 是否禁用压缩 (默认false，不禁用压缩)
	KeepAlive           time.Duration     // 保持连接时间 (默认5 * time.Second)
	Retries             int               // 重试次数(默认0，不重试)
	RetryInterval       time.Duration     // 重试间隔(默认1s)
	RetryOn5xx          bool              // 是否在5xx错误时重试(默认true)
	UserAgent           string            // 默认用User-Agent
	DefaultHeader       map[string]string // 默认请求头
	MaxIdleConns        int               // 最大空闲连接数
	MaxIdleConnsPerHost int               // 每个主机的最大空闲连接数
	IdleConnTimeout     time.Duration     // 空闲连接超时时间

	ProxyURL string // 代理URL
}

type RequestConfig struct {
	TimeOut            time.Duration     // 超时时间, 单位秒
	Params             url.Values        // 请求参数
	Headers            map[string]string // 请求头
	Cookies            []*http.Cookie    // 请求cookie
	Body               interface{}       // 请求体
	InsecureSkipVerify bool              // 是否跳过证书验证
	FollowRedirects    bool              // 是否遵循重定向
	ContentType        string            // 手动指定请求体类型
}

type RequestPacket struct {
	Method     string            // 请求方法
	URL        string            // 请求URL
	Headers    map[string]string // 请求头
	Cookies    []*http.Cookie    // 请求cookie
	Body       string            // 请求体
	BodyBytes  []byte            // 请求体字节
	Timeout    time.Duration     // 超时时间
	Params     url.Values        // 请求参数
	RawRequest string            // 原始请求
}

type ResponseConfig struct {
	StatusCode int            // 响应状态码
	Headers    http.Header    // 响应头
	Cookies    []*http.Cookie // 响应cookie
	Body       string         // 响应体
	BodyBytes  []byte         // 响应体字节
	Error      error          // 错误信息
	RequestURL string         // 请求URL

	RequestPacket  *RequestPacket  // 请求包
	ResponsePacket *ResponsePacket // 响应包
}

type ResponsePacket struct {
	StatusCode    int            // 响应状态码
	Status        string         // 响应状态描述
	Headers       http.Header    // 响应头
	Cookies       []*http.Cookie // 响应Cookies
	BodyBytes     []byte         // 响应体
	Body          string         // 响应体字符串
	ContentType   string         // 内容类型
	ContentLength int64          // 内容长度
	Server        string         // 服务器信息
	ResponseTime  time.Duration  // 响应时间
	RequestPacket *RequestPacket // 对应的请求包
	RawResponse   string         // 原始HTTP响应格式
}

// MarshalJSON 自定义JSON序列化方法
func (r *RequestPacket) MarshalJSON() ([]byte, error) {
	// 创建一个包含所有字段的map
	data := map[string]interface{}{
		"method":      r.Method,
		"url":         r.URL,
		"headers":     r.Headers,
		"cookies":     r.Cookies,
		"body":        r.Body,
		"params":      r.Params,
		"raw_request": r.RawRequest,
	}
	return json.Marshal(data)
}

// MarshalJSON 自定义JSON序列化方法
func (r *ResponsePacket) MarshalJSON() ([]byte, error) {
	// 创建一个包含所有字段的map
	data := map[string]interface{}{
		"status_code":    r.StatusCode,
		"status":         r.Status,
		"headers":        r.Headers,
		"cookies":        r.Cookies,
		"body":           r.Body,
		"content_type":   r.ContentType,
		"content_length": r.ContentLength,
		"server":         r.Server,
		"response_time":  r.ResponseTime,
		"raw_response":   r.RawResponse,
	}
	return json.Marshal(data)
}

type Client struct {
	Config           *ClientConfig           // 客户端配置
	Client           *http.Client            // HTTP客户端
	Transport        *http.Transport         // HTTP传输层
	clientCache      map[string]*http.Client // 客户端缓存，键为配置的哈希值
	maxCacheSize     int                     // 最大缓存大小
	cacheAccessOrder []string                // 缓存访问顺序，用于LRU清理
	mu               sync.RWMutex            // 并发安全锁
}

// parseProxyURL 解析代理URL，处理包含特殊字符的用户名和密码
func parseProxyURL(rawURL string) (*url.URL, error) {
	// 首先尝试直接解析
	proxyURL, err := url.Parse(rawURL)
	if err == nil && proxyURL.User != nil {
		// 解析成功且包含用户信息，直接返回
		return proxyURL, nil
	}

	// 解析失败或不包含用户信息，尝试处理特殊情况
	// 查找@符号的位置，确定用户信息和主机部分
	atIndex := strings.LastIndex(rawURL, "@")
	if atIndex == -1 {
		// 没有@符号，直接返回原始解析结果
		return proxyURL, err
	}

	// 分离用户信息部分和主机部分
	userInfoPart := rawURL[:atIndex]
	hostPart := rawURL[atIndex+1:]

	// 查找用户信息部分中的://，确定协议
	schemeEnd := strings.Index(userInfoPart, "://")
	if schemeEnd == -1 {
		// 没有协议，使用http作为默认
		return url.Parse(rawURL)
	}

	scheme := userInfoPart[:schemeEnd+3]
	credentials := userInfoPart[schemeEnd+3:]

	// 查找凭据中的冒号，分离用户名和密码
	colonIndex := strings.Index(credentials, ":")
	var username, password string
	if colonIndex == -1 {
		// 只有用户名，没有密码
		username = credentials
	} else {
		// 分离用户名和密码
		username = credentials[:colonIndex]
		password = credentials[colonIndex+1:]
	}

	// 对用户名和密码进行URL编码
	encodedUsername := url.QueryEscape(username)
	encodedPassword := url.QueryEscape(password)

	// 重新构建代理URL
	newURL := fmt.Sprintf("%s%s:%s@%s", scheme, encodedUsername, encodedPassword, hostPart)
	return url.Parse(newURL)
}

func proxyConfig(transport *http.Transport, config *ClientConfig) error {
	if config.ProxyURL == "" {
		return nil
	}

	// 基础拨号器
	baseDialer := &net.Dialer{
		Timeout:   config.TimeOut,
		KeepAlive: config.KeepAlive,
		DualStack: true, // 是否使用双栈, 默认使用IPv4
	}

	// 解析代理URL，处理包含特殊字符的用户名和密码
	proxyURL, err := parseProxyURL(config.ProxyURL)
	// fmt.Println(proxyURL)
	if err != nil {
		return fmt.Errorf("failed to parse proxy URL: %w", err)
	}

	// 验证代理URL是否包含主机部分
	if proxyURL.Host == "" {
		return errors.New("proxy URL missing host")
	}

	// 根据协议设置代理
	switch proxyURL.Scheme {
	case "http", "https":
		// HTTP/HTTPS代理，自动处理认证
		transport.Proxy = http.ProxyURL(proxyURL)
	case "socks5", "socks5h":
		// SOCKS5代理，处理认证信息
		var auth *proxy.Auth
		if proxyURL.User != nil {
			username := proxyURL.User.Username()
			password, _ := proxyURL.User.Password()
			if username != "" {
				auth = &proxy.Auth{
					User:     username,
					Password: password,
				}
			}
		}

		// 创建SOCKS5拨号器
		dialer, err := proxy.SOCKS5("tcp", proxyURL.Host, auth, baseDialer)
		if err != nil {
			return fmt.Errorf("failed to create SOCKS5 dialer: %w", err)
		}

		// 替换传输层拨号器
		transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
			return dialer.Dial(network, addr)
		}
	default:
		return fmt.Errorf("unsupported proxy scheme: %s", proxyURL.Scheme)
	}
	return nil
}

// isConnectionError 检查是否是连接错误
func isConnectionError(err error) bool {
	var netErr net.Error
	if errors.As(err, &netErr) {
		return true
	}
	// 检查常见的连接错误
	if strings.Contains(err.Error(), "connection") || strings.Contains(err.Error(), "timeout") || strings.Contains(err.Error(), "refused") {
		return true
	}
	return false
}

func NewClient(config *ClientConfig) (*Client, error) {
	if config == nil {
		return nil, errors.New("config is nil")
	}

	// 设置默认值 - 只对数值类型设置默认值，bool类型使用用户设置的值
	if config.TimeOut == 0 {
		config.TimeOut = 5 * time.Second
	}
	if config.KeepAlive == 0 {
		config.KeepAlive = 30 * time.Second
	}
	if config.MaxRedirects == 0 {
		config.MaxRedirects = 5
	}
	if config.RetryInterval <= 0 {
		config.RetryInterval = 1 * time.Second
	}
	if config.MaxIdleConns == 0 {
		config.MaxIdleConns = 100
	}
	if config.MaxIdleConnsPerHost == 0 {
		config.MaxIdleConnsPerHost = 10
	}
	if config.IdleConnTimeout == 0 {
		config.IdleConnTimeout = 90 * time.Second
	}
	if config.UserAgent == "" {
		config.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
	}
	if config.DefaultHeader == nil {
		config.DefaultHeader = make(map[string]string)
	}

	// 构建TSL配置
	tlsCfg := &tls.Config{
		InsecureSkipVerify: config.InsecureSkipVerify, // 是否跳过证书验证, 默认不跳过
		MinVersion:         tls.VersionTLS12,
	}

	transport := &http.Transport{
		TLSClientConfig:     tlsCfg,
		DisableCompression:  config.DisableCompression, // 是否禁用压缩, 默认不禁用
		MaxIdleConns:        config.MaxIdleConns,
		MaxIdleConnsPerHost: config.MaxIdleConnsPerHost,
		IdleConnTimeout:     config.IdleConnTimeout,
		DialContext: (&net.Dialer{
			Timeout:   config.TimeOut,
			KeepAlive: config.KeepAlive,
		}).DialContext,
	}

	// 配置Cookie Jar
	jar, err := cookiejar.New(&cookiejar.Options{
		PublicSuffixList: publicsuffix.List,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create cookiejar: %w", err)
	}

	// 重定向策略
	var redirect func(req *http.Request, via []*http.Request) error
	if config.FollowRedirects {
		// 允许重定向
		redirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= config.MaxRedirects { // 最大重定向次数
				return errors.New("too many redirects")
			}
			for k, v := range via[0].Header { // 复制重定向请求头
				req.Header[k] = v
			}
			return nil
		}
	} else {
		// 不允许重定向
		redirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	// 配置代理
	if err := proxyConfig(transport, config); err != nil {
		return nil, fmt.Errorf("failed to configure proxy: %w", err)
	}

	// 构建client
	client := &http.Client{
		Timeout:       config.TimeOut,
		Transport:     transport,
		Jar:           jar,
		CheckRedirect: redirect,
	}

	return &Client{
		Config:           config,
		Client:           client,
		Transport:        transport,
		clientCache:      make(map[string]*http.Client),
		maxCacheSize:     100, // 默认最大缓存大小为100
		cacheAccessOrder: make([]string, 0),
	}, nil
}

// 构建请求 （处理params/body/header/cookie）
func (c *Client) buildRequest(method string, rawURL string, requestConfig *RequestConfig) (*http.Request, error) {
	// 解析URL
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, err
	}
	// 处理参数
	if requestConfig != nil && requestConfig.Params != nil && len(requestConfig.Params) > 0 {
		u.RawQuery = requestConfig.Params.Encode()
	}
	// 处理body
	var body io.Reader
	var contentType string
	if requestConfig != nil && requestConfig.Body != nil {
		contentType = requestConfig.ContentType
		switch b := requestConfig.Body.(type) {
		case string:
			body = strings.NewReader(b)
			if contentType == "" {
				contentType = "text/plain; charset=utf-8"
			}
		case []byte:
			body = bytes.NewReader(b)
			if contentType == "" {
				contentType = "application/octet-stream"
			}
		case io.Reader:
			body = b
			if contentType == "" {
				contentType = "application/octet-stream"
			}
		case map[string]string:
			values := url.Values{}
			for k, v := range b {
				values.Add(k, v)
			}
			body = strings.NewReader(values.Encode())
			if contentType == "" {
				contentType = "application/x-www-form-urlencoded; charset=utf-8"
			}
		default:
			var jsonData []byte
			jsonData, err = json.Marshal(b)
			if err != nil {
				return nil, err
			}
			body = bytes.NewReader(jsonData)
			if contentType == "" {
				contentType = "application/json; charset=utf-8"
			}
		}
	}
	// 创建基础请求
	req, err := http.NewRequest(method, u.String(), body)
	if err != nil {
		return nil, err
	}
	// 处理基础请求头
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("User-Agent", c.Config.UserAgent)
	for k, v := range c.Config.DefaultHeader {
		// 对于包含特殊字符的请求头（如点号、连字符等），保持原始大小写
		if strings.Contains(k, ".") || strings.Contains(k, "-") {
			if req.Header == nil {
				req.Header = make(http.Header)
			}
			req.Header[k] = []string{v}
		} else {
			req.Header.Set(k, v)
		}
	}

	// 处理本次请求头
	if requestConfig != nil && requestConfig.Headers != nil && len(requestConfig.Headers) > 0 {
		for k, v := range requestConfig.Headers {
			// 对于包含特殊字符的请求头（如点号、连字符等），保持原始大小写
			if strings.Contains(k, ".") || strings.Contains(k, "-") {
				// 直接修改底层的Header map，避免自动大写
				if req.Header == nil {
					req.Header = make(http.Header)
				}
				req.Header[k] = []string{v}
			} else {
				req.Header.Set(k, v)
			}
		}

		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		if requestConfig.Cookies != nil {
			for _, c := range requestConfig.Cookies {
				req.AddCookie(c)
			}
		}
	}
	return req, nil
}

// buildClient 构建请求客户端
func (c *Client) buildClient(requestConfig *RequestConfig) (*http.Client, error) {
	// 基础配置复制全局配置
	timeout := c.Config.TimeOut
	redirects := c.Client.CheckRedirect
	tlsCfg := c.Transport.TLSClientConfig // 始终使用全局TLS配置作为基础

	// 创建TLS配置的副本，避免共享修改
	tlsCfgCopy := &tls.Config{
		InsecureSkipVerify: tlsCfg.InsecureSkipVerify,
		MinVersion:         tls.VersionTLS12,
	}

	// 处理TSL配置
	if requestConfig != nil && requestConfig.InsecureSkipVerify {
		tlsCfgCopy.InsecureSkipVerify = true
	}

	// 重定向策略
	if requestConfig != nil {
		if !requestConfig.FollowRedirects {
			redirects = func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
		}
	}

	// 超时
	if requestConfig != nil && requestConfig.TimeOut > 0 {
		timeout = requestConfig.TimeOut
	}

	// 生成缓存键 - 包含更多配置参数
	cacheKey := fmt.Sprintf("%d_%v_%v_%v", timeout, redirects == nil, tlsCfgCopy.InsecureSkipVerify, c.Config.DisableCompression)

	// 检查缓存（读锁）
	c.mu.RLock()
	client, ok := c.clientCache[cacheKey]
	c.mu.RUnlock()

	if ok {
		// 更新访问顺序（写锁）
		c.mu.Lock()
		c.updateCacheAccessOrder(cacheKey)
		c.mu.Unlock()
		return client, nil
	}

	// 创建新的Transport使用副本TLS配置
	transportCopy := &http.Transport{
		TLSClientConfig:     tlsCfgCopy,
		DisableCompression:  c.Transport.DisableCompression,
		MaxIdleConns:        c.Transport.MaxIdleConns,
		MaxIdleConnsPerHost: c.Transport.MaxIdleConnsPerHost,
		IdleConnTimeout:     c.Transport.IdleConnTimeout,
		DialContext:         c.Transport.DialContext,
		Proxy:               c.Transport.Proxy,
	}

	// 构建client
	client = &http.Client{
		Timeout:       timeout,
		Transport:     transportCopy,
		Jar:           c.Client.Jar,
		CheckRedirect: redirects,
	}

	// 缓存客户端（写锁）
	c.mu.Lock()
	defer c.mu.Unlock()

	// 再次检查缓存（可能在获取锁期间已被其他goroutine添加）
	if existingClient, exists := c.clientCache[cacheKey]; exists {
		c.updateCacheAccessOrder(cacheKey)
		return existingClient, nil
	}

	// 检查缓存大小，如果超过限制，删除最久未使用的缓存
	if len(c.clientCache) >= c.maxCacheSize && c.maxCacheSize > 0 {
		// 删除最久未使用的缓存（访问顺序的第一个元素）
		if len(c.cacheAccessOrder) > 0 {
			oldestKey := c.cacheAccessOrder[0]
			delete(c.clientCache, oldestKey)
			// 移除访问顺序中的第一个元素
			c.cacheAccessOrder = c.cacheAccessOrder[1:]
		}
	}

	// 缓存客户端
	c.clientCache[cacheKey] = client
	// 添加到访问顺序末尾
	c.cacheAccessOrder = append(c.cacheAccessOrder, cacheKey)

	return client, nil
}

// doRequest 发送请求并返回响应体
func (c *Client) doRequest(req *http.Request, requestConfig *RequestConfig) (*ResponseConfig, error) {
	// 记录开始请求时间
	startTime := time.Now()

	// 先读取并保存请求体，以便后续生成请求数据包
	var requestBody []byte
	var err error
	if req.Body != nil {
		requestBody, err = io.ReadAll(req.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read request body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(requestBody)) // 重置请求体
	}

	// 构建本次请求客户端
	client, err := c.buildClient(requestConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build client: %w", err)
	}

	// 重试逻辑
	var resp *http.Response
	retryCount := 0
	maxRetryCount := c.Config.Retries

	for retryCount <= maxRetryCount {
		resp, err = client.Do(req)
		if err == nil {
			if !c.Config.RetryOn5xx || resp.StatusCode < 500 || resp.StatusCode >= 600 {
				break // 非5xx错误，直接返回
			}
			// 5xx错误，重试
			err = fmt.Errorf("server error: status code %d", resp.StatusCode)
			resp.Body.Close() // 关闭响应体
		} else {
			// 检查是否是可重试的错误
			var netErr net.Error
			if !errors.As(err, &netErr) && !isConnectionError(err) {
				return nil, fmt.Errorf("request failed (non-retryable): %w", err)
			}
		}
		if retryCount == maxRetryCount {
			return nil, fmt.Errorf("request failed after %d retries for URL %s: %w", maxRetryCount, req.URL.String(), err)
		}
		// 指数退避策略
		backoffTime := c.Config.RetryInterval * time.Duration(math.Pow(2, float64(retryCount)))
		time.Sleep(backoffTime)
		retryCount++
	}

	if resp == nil {
		return nil, fmt.Errorf("request failed for URL %s: %w", req.URL.String(), err)
	}

	// 解析响应体
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	//计算响应时间
	responseTime := time.Since(startTime)

	// 构建响应配置
	responseConfig := &ResponseConfig{
		StatusCode: resp.StatusCode,
		Body:       string(body),
		BodyBytes:  body,
		Headers:    resp.Header,
		Cookies:    resp.Cookies(),
		Error:      nil,
		RequestURL: req.URL.String(),
	}

	reqHeaders := make(map[string]string)
	for k, v := range req.Header {
		reqHeaders[k] = v[0]
	}
	reqConfig := &RequestConfig{
		Headers: reqHeaders,
		TimeOut: c.Config.TimeOut,
		Params:  req.URL.Query(),
	}
	// 构建数据请求包
	requestPacket := BuildRequestPacket(req.Method, req.URL.String(), reqConfig, requestBody)

	responsePacket := responseConfig.BuildReponsePacket(requestPacket, responseTime)

	responseConfig.ResponsePacket = responsePacket
	responseConfig.RequestPacket = requestPacket

	return responseConfig, nil
}

// sendRequest 发送请求的通用方法
func (c *Client) sendRequest(method string, url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	var reqConfig *RequestConfig
	if len(requestConfig) > 0 {
		reqConfig = requestConfig[0]
	}
	req, err := c.buildRequest(method, url, reqConfig)
	if err != nil {
		return nil, err
	}
	return c.doRequest(req, reqConfig)
}

// DoStream 发送请求并返回原始响应，支持流式处理大文件
func (c *Client) DoStream(method string, url string, requestConfig ...*RequestConfig) (*http.Response, error) {
	var reqConfig *RequestConfig
	if len(requestConfig) > 0 {
		reqConfig = requestConfig[0]
	}

	// 构建请求
	req, err := c.buildRequest(method, url, reqConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build request: %w", err)
	}

	// 构建客户端
	client, err := c.buildClient(reqConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to build client: %w", err)
	}

	// 发送请求
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed for URL %s: %w", url, err)
	}

	return resp, nil
}

func (c *Client) Get(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodGet, url, requestConfig...)
}

func (c *Client) Post(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodPost, url, requestConfig...)
}

func (c *Client) Put(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodPut, url, requestConfig...)
}

func (c *Client) Delete(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodDelete, url, requestConfig...)
}

func (c *Client) Head(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodHead, url, requestConfig...)
}

func (c *Client) Options(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodOptions, url, requestConfig...)
}

func (c *Client) Trace(url string, requestConfig ...*RequestConfig) (*ResponseConfig, error) {
	return c.sendRequest(http.MethodTrace, url, requestConfig...)
}

func BuildRequestPacket(method string, urlStr string, reqConfig *RequestConfig, body []byte) *RequestPacket {
	headers := make(map[string]string)
	if reqConfig != nil {
		for k, v := range reqConfig.Headers {
			headers[k] = v
		}
	}

	bodyStr := ""
	if body != nil {
		bodyStr = string(body)
	}

	// 生成原始HTTP请求格式
	urlObj, err := url.Parse(urlStr)
	if err != nil {
		return nil
	}
	path := urlObj.Path
	if path == "" {
		path = "/"
	}

	var rawRequest strings.Builder
	rawRequest.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
	if urlStr != "" {
		rawRequest.WriteString(fmt.Sprintf("Host: %s\r\n", urlObj.Host))
	}

	for k, v := range headers {
		rawRequest.WriteString(fmt.Sprintf("%s: %s\r\n", k, v))
	}

	if body != nil {
		rawRequest.WriteString(fmt.Sprintf("Content-Length: %d\r\n", len(body)))
	}

	// 添加请求体
	if body != nil {
		// 添加空行
		rawRequest.WriteString("\r\n")
		rawRequest.WriteString(bodyStr)
	}

	return &RequestPacket{
		Method:     method,
		URL:        urlStr,
		Headers:    headers,
		Body:       bodyStr,
		BodyBytes:  body,
		Cookies:    reqConfig.Cookies,
		Timeout:    reqConfig.TimeOut,
		Params:     reqConfig.Params,
		RawRequest: rawRequest.String(),
	}
}

func (r *ResponseConfig) BuildReponsePacket(req *RequestPacket, respTime time.Duration) *ResponsePacket {
	var contentLength int64
	if r.Headers != nil {
		if cl := r.Headers.Get("Content-Length"); cl != "" {
			if len, err := strconv.ParseInt(cl, 10, 64); err == nil {
				contentLength = len
			}
		}
	}

	// 生成原始HTTP响应格式
	var rawResponse strings.Builder
	rawResponse.WriteString(fmt.Sprintf("HTTP/1.1 %d %s\r\n", r.StatusCode, http.StatusText(r.StatusCode)))
	// 添加所有响应头
	if r.Headers != nil {
		for k, v := range r.Headers {
			for _, vv := range v {
				rawResponse.WriteString(fmt.Sprintf("%s: %s\r\n", k, vv))
			}
		}
	}
	// 添加空行
	rawResponse.WriteString("\r\n")
	// 添加响应体
	if r.Body != "" {
		rawResponse.WriteString(r.Body)
	}
	return &ResponsePacket{
		StatusCode:    r.StatusCode,
		Status:        http.StatusText(r.StatusCode),
		Headers:       r.Headers,
		Cookies:       r.Cookies,
		Body:          r.Body,
		BodyBytes:     r.BodyBytes,
		ContentType:   r.Headers.Get("Content-Type"),
		ContentLength: contentLength,
		Server:        r.Headers.Get("Server"),
		ResponseTime:  respTime,
		RequestPacket: req,
		RawResponse:   rawResponse.String(),
	}
}

func (c *Client) SetTimeout(timeout time.Duration) {
	c.Config.TimeOut = timeout
	c.Client.Timeout = timeout
}

func (c *Client) SetIdleConnTimeout(idleConnTimeout time.Duration) {
	c.Config.IdleConnTimeout = idleConnTimeout
	c.Transport.IdleConnTimeout = idleConnTimeout
}

func (c *Client) SetDisableCompression(disable bool) {
	c.Transport.DisableCompression = disable
	c.Config.DisableCompression = disable
	c.ClearCache() // 配置更新，清理缓存
}

func (c *Client) SetMaxIdleConns(maxIdleConns int) {
	c.Config.MaxIdleConns = maxIdleConns
	c.Transport.MaxIdleConns = maxIdleConns
	c.ClearCache() // 配置更新，清理缓存
}

func (c *Client) SetMaxIdleConnsPerHost(maxIdleConnsPerHost int) {
	c.Config.MaxIdleConnsPerHost = maxIdleConnsPerHost
	c.Transport.MaxIdleConnsPerHost = maxIdleConnsPerHost
	c.ClearCache() // 配置更新，清理缓存
}

func (c *Client) SetInsecureSkipVerify(insecureSkipVerify bool) {
	c.Config.InsecureSkipVerify = insecureSkipVerify
	c.Transport.TLSClientConfig.InsecureSkipVerify = insecureSkipVerify
	c.ClearCache() // 配置更新，清理缓存
}

func (c *Client) SetFollowRedirects(followRedirects bool) {
	c.Config.FollowRedirects = followRedirects
	if followRedirects {
		c.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			if len(via) >= c.Config.MaxRedirects {
				return errors.New("redirect loop")
			}
			for _, v := range via {
				if v.URL.Path == req.URL.Path {
					return errors.New("redirect loop")
				}
			}
			return nil
		}
	} else {
		c.Client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	c.ClearCache() // 配置更新，清理缓存
}

// SetMaxRedirects 设置最大重定向次数
func (c *Client) SetMaxRedirects(maxRedirects int) {
	if maxRedirects <= 0 {
		maxRedirects = 10
	}
	c.Config.MaxRedirects = maxRedirects
	c.ClearCache() // 配置更新，清理缓存
}

// SetRetryOn5xx 设置是否重试5xx错误码
func (c *Client) SetRetryOn5xx(retryOn5xx bool) {
	c.Config.RetryOn5xx = retryOn5xx
	c.ClearCache() // 配置更新，清理缓存
}

// SetRetryInterval 设置重试间隔
func (c *Client) SetRetryInterval(retryInterval time.Duration) {
	c.Config.RetryInterval = retryInterval
	c.ClearCache() // 配置更新，清理缓存
}

// SetRetries 设置重试次数
func (c *Client) SetRetries(Retries int) {
	if Retries <= 0 {
		Retries = 3
	}
	c.Config.Retries = Retries
	c.ClearCache() // 配置更新，清理缓存
}

// SetKeepAlive 设置长连接保持时间
func (c *Client) SetKeepAlive(keepAlive time.Duration) {
	c.Config.KeepAlive = keepAlive
	c.Transport.DialContext = (&net.Dialer{
		Timeout:   c.Config.TimeOut,
		KeepAlive: keepAlive,
	}).DialContext
	c.ClearCache() // 配置更新，清理缓存
}

// SetProxy 设置代理
func (c *Client) SetProxy(proxy string) error {
	c.Config.ProxyURL = proxy
	err := proxyConfig(c.Transport, c.Config)
	if err == nil {
		c.ClearCache() // 配置更新，清理缓存
	}
	return err
}

// SetUserAgent
func (c *Client) SetUserAgent(userAgent string) {
	c.Config.UserAgent = userAgent
	c.ClearCache() // 配置更新，清理缓存
}

// AddHeaders 添加请求头
func (c *Client) AddHeaders(key, value string) {
	if c.Config.DefaultHeader == nil {
		c.Config.DefaultHeader = make(map[string]string)
	}
	c.Config.DefaultHeader[key] = value
}

// updateCacheAccessOrder 更新缓存访问顺序，将指定的缓存键移到末尾（表示最近使用）
func (c *Client) updateCacheAccessOrder(cacheKey string) {
	// 查找cacheKey在访问顺序中的位置
	for i, key := range c.cacheAccessOrder {
		if key == cacheKey {
			// 移除该键
			c.cacheAccessOrder = append(c.cacheAccessOrder[:i], c.cacheAccessOrder[i+1:]...)
			break
		}
	}
	// 将cacheKey添加到末尾
	c.cacheAccessOrder = append(c.cacheAccessOrder, cacheKey)
}

// ClearCache 清理客户端缓存
func (c *Client) ClearCache() {
	c.mu.Lock()
	defer c.mu.Unlock()

	// 关闭缓存中客户端的空闲连接
	for _, client := range c.clientCache {
		if transport, ok := client.Transport.(*http.Transport); ok {
			transport.CloseIdleConnections()
		}
	}

	// 清理缓存
	for key := range c.clientCache {
		delete(c.clientCache, key)
	}

	// 清空访问顺序
	c.cacheAccessOrder = make([]string, 0)
}

// Close 关闭客户端，释放所有资源
func (c *Client) Close() {
	c.Transport.CloseIdleConnections() // 关闭所有空闲连接
	c.ClearCache()                     // 清理缓存
}

// ParseJSON 解析JSON响应体
func (r *ResponseConfig) ParseJSON(v any) error {
	return json.Unmarshal(r.BodyBytes, v)
}

// ParseXML 解析XML响应体
func (r *ResponseConfig) ParseXML(v any) error {
	return xml.Unmarshal(r.BodyBytes, v)
}

// ParseHTML 解析HTML响应体
func (r *ResponseConfig) ParseHTML() *goquery.Document {
	doc, err := goquery.NewDocumentFromReader(strings.NewReader(r.Body))
	if err != nil {
		return nil
	}
	doc.Find("body").Each(func(i int, s *goquery.Selection) {
		r.Body += s.Text() + "\n"
	})
	return doc
}

// ToString 转换为字符串
func (r *RequestPacket) ToString() string {
	return r.RawRequest
}

// ToString 转换为字符串
func (r *ResponsePacket) ToString() string {
	return r.RawResponse
}

// ToStringWithLimit 返回响应包的字符串表示，可选择截取指定长度
func (r *ResponsePacket) ToStringWithLimit(maxLength int) string {
	if maxLength <= 0 || len(r.RawResponse) <= maxLength {
		return r.RawResponse
	}
	return r.RawResponse[:maxLength] + "..."
}
