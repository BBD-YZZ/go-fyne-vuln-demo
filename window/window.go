package window

import (
	"vuln-scan/client"
	"vuln-scan/config"
	"vuln-scan/dnslog"
	"vuln-scan/logger"
	"vuln-scan/webhook"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

type Window struct {
	App    fyne.App
	Window fyne.Window
	Title  string
	Height float32
	Width  float32

	// Top
	TargetInput  *widget.Entry
	VulnSelect   *widget.Select
	CheckButton  *widget.Button
	ClearButton  *widget.Button
	CookiesInput *widget.Entry

	// Center
	LoggerContainer *fyne.Container
	LoggerScroll    *container.Scroll

	// Bottom
	TimeLabel            *widget.Label
	ProyxCircle          *canvas.Circle
	ProxyLabel           *widget.Label
	ProxyContainer       *fyne.Container
	StatusLabel          *widget.Label
	DnsLogCircle         *canvas.Circle
	DnsLogLabel          *widget.Label
	DnsLogContainer      *fyne.Container
	InfomationLabel      *widget.Label
	WelcomeLabel         *widget.Label
	DisclaimerLabel      *widget.Label
	FormLabel            *widget.Label
	MessagePushCircle    *canvas.Circle
	MessagePushLabel     *widget.Label
	MessagePushContainer *fyne.Container

	AILLabel          *widget.Label
	AICircle          *canvas.Circle
	AICircleContainer *fyne.Container

	// Image       *fyne.StaticResource
	WechatImage *canvas.Image

	ProxyConfig        *client.ProxyConfig
	CeyeConfig         *dnslog.CeyeConfig
	MessagePushConfig  *webhook.WebhookConfig
	MessagePushEnabled bool

	Tabs              *container.AppTabs
	RequestContainer  *fyne.Container
	RequestScroll     *container.Scroll
	ResponseContainer *fyne.Container
	ResponseScroll    *container.Scroll

	CeyeContainer *fyne.Container
	CeyeScroll    *container.Scroll
	CeyeInfoLabel *widget.Label
	CeyeCard      *widget.Card
	CeyeTabItem   *container.TabItem

	Logger logger.ColoredLogger

	// AI配置
	AIAnalysisEnabled bool
	AIApiKey          string
	AIApiURL          string
	AIModel           string
	AIProvider        string

	// AI对话机器人
	DialogContainer  *fyne.Container
	DialogScroll     *container.Scroll
	DialogInput      *widget.Entry
	DialogSendButton *widget.Button
	DialogTabItem    *container.TabItem

	// 日志配置
	LogEnabled       bool
	LogConsoleOutput bool
	LogFileOutput    bool

	ResultEntry  *widget.Entry
	ResultScroll *container.Scroll
	ResultCard   *widget.Card
}

func NewWindow(app fyne.App, title string, height float32, width float32) *Window {
	window := &Window{
		App:    app,
		Title:  title,
		Height: height,
		Width:  width,
	}

	// 加载配置文件
	cfg, err := config.LoadConfig()
	if err != nil {
		// 如果加载失败，使用默认配置
		window.ProxyConfig = &client.ProxyConfig{
			Enable:   false,
			Type:     client.HTTP,
			Host:     "",
			Port:     "",
			Username: "",
			Password: "",
		}

		window.CeyeConfig = &dnslog.CeyeConfig{
			Type:    dnslog.DNS,
			Enabled: false,
			Token:   "",
			Domain:  "",
		}

		window.MessagePushConfig = &webhook.WebhookConfig{
			Platform:   "",
			URL:        "",
			Token:      "",
			Secret:     "",
			IsAt:       false,
			IsAtAll:    true,
			AtAccounts: []string{},
		}
		window.MessagePushEnabled = false

		// 默认AI配置
		window.AIAnalysisEnabled = false
		window.AIApiKey = ""
		window.AIApiURL = "https://api.openai.com/v1/chat/completions"
		window.AIModel = "gpt-3.5-turbo"
		window.AIProvider = "openai"
	} else {
		// 使用加载的配置，但不加载启用状态
		window.ProxyConfig = &client.ProxyConfig{
			Enable:   false, // 程序启动时默认禁用
			Type:     cfg.Proxy.Type,
			Host:     cfg.Proxy.Host,
			Port:     cfg.Proxy.Port,
			Username: cfg.Proxy.Username,
			Password: cfg.Proxy.Password,
		}

		window.CeyeConfig = &dnslog.CeyeConfig{
			Type:    cfg.Ceye.Type,
			Enabled: false, // 程序启动时默认禁用
			Token:   cfg.Ceye.Token,
			Domain:  cfg.Ceye.Domain,
		}

		window.MessagePushConfig = &webhook.WebhookConfig{
			Platform:   cfg.MessagePush.Platform,
			URL:        cfg.MessagePush.URL,
			Token:      cfg.MessagePush.Token,
			Secret:     cfg.MessagePush.Secret,
			IsAt:       false,
			IsAtAll:    true,
			AtAccounts: []string{},
		}
		window.MessagePushEnabled = false // 程序启动时默认禁用

		// 加载AI配置，但不加载启用状态
		window.AIAnalysisEnabled = false // 程序启动时默认禁用
		window.AIApiKey = cfg.AI.APIKey
		window.AIApiURL = cfg.AI.APIURL
		window.AIModel = cfg.AI.Model
		window.AIProvider = cfg.AI.Provider
	}

	window.Logger = logger.NewColoredLogger()
	window.Logger.SetMinLevel(logger.Info)

	// 初始化日志配置
	window.LogEnabled = true        // 程序启动时默认启用日志
	window.LogConsoleOutput = false // 程序启动时日志默认不输出到控制台
	window.LogFileOutput = true     // 程序启动时日志默认输出到文件

	// 应用日志配置
	window.Logger.SetEnable(window.LogEnabled)
	window.Logger.SetConsoleOutput(window.LogConsoleOutput)
	window.Logger.SetFileOutput(window.LogFileOutput, "./vuln-scan.log")

	window.CreateWindow()
	// window.Logger.Info("程序启动完成")

	return window
}

func (w *Window) CreateWindow() {
	// w.Logger.Info("程序启动中...")
	w.Window = w.App.NewWindow(w.Title)
	w.Window.Resize(fyne.NewSize(w.Width, w.Height))
	w.Window.SetFixedSize(true)
	w.Window.CenterOnScreen()

	top := CreateTopArea(w)
	center := CreateCenterArea(w)
	bottom := CreateBottomArea(w)

	// 设置默认选中的漏洞类型
	w.VulnSelect.SetSelectedIndex(0)
	content := container.NewBorder(top, bottom, nil, nil, center)

	w.Window.SetMaster() // 设置主窗口
	w.Window.SetCloseIntercept(func() {
		// w.Logger.Info("程序关闭中...")
		w.App.Quit()
		// w.Logger.Info("程序关闭完成")
	})

	w.Window.SetMainMenu(CreateMenu(w))
	w.Window.SetContent(content)
	go StartUpdateTimeAndFormLabel(w)
}
