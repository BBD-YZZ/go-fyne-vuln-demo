package window

import (
	"encoding/base64"
	"fmt"
	"image/color"
	"strings"
	"sync"
	"time"
	"vuln-scan/client"
	"vuln-scan/config"
	"vuln-scan/dnslog"
	"vuln-scan/images"
	"vuln-scan/tools"
	"vuln-scan/vulnerability"
	"vuln-scan/webhook"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/widget"
)

func CreateMenu(win *Window) *fyne.MainMenu {
	openFile := fyne.NewMenuItem("打开文件", func() {
		// // 打开文件逻辑
		// go OpenFile(win)
		ShowMessage(win.Window, "温馨提示", "当前功能已隐藏，暂不支持", nil, func() {
			// 点击确认按钮后的逻辑
		}, 2)
	})

	saveFile := fyne.NewMenuItem("保存文件", func() {
		ShowMessage(win.Window, "温馨提示", "当前功能已隐藏，暂不支持", nil, func() {
			// 点击确认按钮后的逻辑
		}, 2)
		// go SaveFile(win)
	})

	operationMenu := fyne.NewMenu("操作菜单", openFile, saveFile)

	proxyMenu := fyne.NewMenuItem("代理设置", func() {
		// 代理和DNS日志逻辑
		go SetProxy(win)
	})

	dnslogMenu := fyne.NewMenuItem("CEYE设置", func() {
		// DNS日志设置逻辑
		go SetDnslog(win)
	})

	messageWebhook := fyne.NewMenuItem("消息推送", func() {
		go MessagePush(win)
	})

	aiMenu := fyne.NewMenuItem("AI    设置", func() {
		go SetAI(win)
	})

	logMenu := fyne.NewMenuItem("日志设置", func() {
		go SetLog(win)
	})

	setMenu := fyne.NewMenu("设置菜单", proxyMenu, dnslogMenu, messageWebhook, aiMenu, logMenu)

	toolsMenu := fyne.NewMenuItem("关于工具", func() {
		// 关于逻辑
		go About(win)
	})

	aboutMenu := fyne.NewMenu("关于菜单", toolsMenu)

	menu := fyne.NewMainMenu(operationMenu, setMenu, aboutMenu)
	return menu
}

func SetProxy(win *Window) {
	var popUp *widget.PopUp

	// 代理设置部分
	enableCheck := widget.NewCheck("启用代理", func(enabled bool) {
		// 启用代理逻辑
	})
	enableCheck.SetChecked(win.ProxyConfig.Enable)

	typeSelect := widget.NewSelect([]string{string(client.HTTP), string(client.SOCKS5)}, func(selected string) {
		// 代理类型选择逻辑
	})
	typeMapping := map[string]string{
		"http":   string(client.HTTP),
		"socks5": string(client.SOCKS5),
	}
	selectedType := string(win.ProxyConfig.Type)
	if proxyType, ok := typeMapping[selectedType]; ok {
		typeSelect.SetSelected(proxyType)
	} else {
		typeSelect.SetSelected(string(client.HTTP))
	}

	hostEntry := widget.NewEntry()
	hostEntry.SetPlaceHolder("请输入代理主机")
	hostEntry.SetText(win.ProxyConfig.Host)
	portEntry := widget.NewEntry()
	portEntry.SetPlaceHolder("请输入代理端口")
	portEntry.SetText(win.ProxyConfig.Port)

	userEntry := widget.NewEntry()
	userEntry.SetPlaceHolder("请输入代理用户名")
	userEntry.SetText(win.ProxyConfig.Username)
	passEntry := widget.NewEntry()
	passEntry.SetPlaceHolder("请输入代理密码")
	passEntry.SetText(win.ProxyConfig.Password)

	leftContainer := container.NewGridWithColumns(1,
		container.NewBorder(nil, nil, widget.NewLabel("状态控制:"), nil, enableCheck),
		container.NewBorder(nil, nil, widget.NewLabel("服务地址:"), nil, hostEntry),
		container.NewBorder(nil, nil, widget.NewLabel("服务端口:"), nil, portEntry),
	)

	rightContainer := container.NewGridWithColumns(1,
		container.NewBorder(nil, nil, widget.NewLabel("代理类型:"), nil, typeSelect),
		container.NewBorder(nil, nil, widget.NewLabel("用户名称:"), nil, userEntry),
		container.NewBorder(nil, nil, widget.NewLabel("用户密码:"), nil, passEntry),
	)

	formContainer := container.NewHSplit(
		container.NewPadded(leftContainer),
		container.NewPadded(rightContainer),
	)
	formContainer.SetOffset(0.5)

	title := widget.NewLabel("🌐 代理服务配置")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	// 先定义saveButton
	saveButton := widget.NewButton("", func() {
		// 保存设置逻辑
		go SaveProxy(win, enableCheck, typeSelect, hostEntry, portEntry, userEntry, passEntry)
	})
	saveButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	// 然后定义enableCheck，并在回调中更新按钮文本
	enableCheck.OnChanged = func(enabled bool) {
		if enableCheck.Checked {
			saveButton.SetText("启用代理")
		} else {
			saveButton.SetText("取消代理")
		}
	}

	// 初始化按钮文本
	if enableCheck.Checked {
		saveButton.SetText("启用代理")
	} else {
		saveButton.SetText("取消代理")
	}

	closeButton := widget.NewButton("关闭界面", func() {
		// 关闭设置逻辑
		popUp.Hide()
	})
	closeButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	proxyContent := container.NewBorder(
		container.NewVBox(
			title,
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			container.NewHBox(), // 占位，稍后替换
		),
		nil, nil,
		formContainer,
	)

	proxyButton := container.NewHBox(
		layout.NewSpacer(),
		saveButton,
		layout.NewSpacer(),
		closeButton,
		layout.NewSpacer(),
	)

	allProxyContent := container.NewBorder(
		nil, proxyButton, nil, nil,
		proxyContent,
	)

	popUp = widget.NewModalPopUp(allProxyContent, win.Window.Canvas())
	// 计算居中位置
	windowSize := win.Window.Canvas().Size()
	popUpSize := fyne.NewSize(600, 200)
	x := (windowSize.Width - popUpSize.Width) / 2
	y := (windowSize.Height - popUpSize.Height) / 2
	position := fyne.NewPos(x, y)

	fyne.Do(func() {
		popUp.ShowAtPosition(position) // 居中显示
		popUp.Resize(popUpSize)        // 设置弹出窗口大小
	})
}

func MessagePush(win *Window) {
	var popUp *widget.PopUp

	enableCheck := widget.NewCheck("启用消息推送", func(enabled bool) {
		// 启用消息推送逻辑
	})
	enableCheck.SetChecked(win.MessagePushEnabled)
	enableCheckForm := widget.NewForm(
		widget.NewFormItem("状态控制:", enableCheck),
	)

	// 创建配置项
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("请输入Webhook URL")
	urlEntry.SetText(win.MessagePushConfig.URL)
	urlEntryForm := widget.NewForm(
		widget.NewFormItem("推送链接:", urlEntry),
	)

	tokenEntry := widget.NewEntry()
	tokenEntry.SetPlaceHolder("请输入Token")
	tokenEntry.SetText(win.MessagePushConfig.Token)
	tokenEntryForm := widget.NewForm(
		widget.NewFormItem("推送验证:", tokenEntry),
	)

	secretEntry := widget.NewEntry()
	secretEntry.SetPlaceHolder("请输入签名密钥")
	secretEntry.SetText(win.MessagePushConfig.Secret)
	secretEntryForm := widget.NewForm(
		widget.NewFormItem("签名密钥:", secretEntry),
	)

	// 创建平台选择下拉菜单
	webHookSelect := widget.NewSelect([]string{"华为WeLink", "企业微信", "钉钉", "飞书"}, func(selected string) {
		// 根据选择的平台更新配置界面
		updateMessagePushUI(selected, urlEntryForm, tokenEntryForm, secretEntryForm)
	})

	// 根据保存的配置设置选中项
	switch win.MessagePushConfig.Platform {
	case webhook.PlatformWeLink:
		webHookSelect.SetSelectedIndex(0)
	case webhook.PlatformWeChat:
		webHookSelect.SetSelectedIndex(1)
	case webhook.PlatformDingTalk:
		webHookSelect.SetSelectedIndex(2)
	case webhook.PlatformFeishu:
		webHookSelect.SetSelectedIndex(3)
	default:
		webHookSelect.SetSelectedIndex(0)
	}
	webHookSelectForm := widget.NewForm(
		widget.NewFormItem("平台类型:", webHookSelect),
	)

	// 创建标题
	title := widget.NewLabel("🍩 消息推送配置")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	// 创建内容容器
	content := container.NewGridWithColumns(1,
		enableCheckForm,
		webHookSelectForm,
		urlEntryForm,
		tokenEntryForm,
		secretEntryForm,
	)

	// 创建按钮
	saveButton := widget.NewButton("保存配置", func() {
		go SaveMessagePush(win, enableCheck, webHookSelect, urlEntry, tokenEntry, secretEntry)
		popUp.Hide()
	})
	saveButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	closeButton := widget.NewButton("关闭界面", func() {
		popUp.Hide()
	})
	closeButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	// 创建按钮容器
	buttons := container.NewHBox(
		layout.NewSpacer(),
		saveButton,
		layout.NewSpacer(),
		closeButton,
		layout.NewSpacer(),
	)

	// 创建完整内容
	allContent := container.NewBorder(
		container.NewVBox(
			title,
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			buttons,
		),
		nil, nil, container.NewVBox(content),
	)

	popUp = widget.NewModalPopUp(allContent, win.Window.Canvas())

	// 计算居中位置
	windowSize := win.Window.Canvas().Size()
	popUpSize := fyne.NewSize(600, 350)
	x := (windowSize.Width - popUpSize.Width) / 2
	y := (windowSize.Height - popUpSize.Height) / 2
	position := fyne.NewPos(x, y)

	fyne.Do(func() {
		popUp.ShowAtPosition(position)
		popUp.Resize(popUpSize)
	})
}

// updateMessagePushUI 根据选择的平台更新配置界面
func updateMessagePushUI(selected string, urlEntry, tokenEntry, secretEntry *widget.Form) {
	switch selected {
	case "企业微信":
		urlEntry.Show()
		tokenEntry.Hide()
		secretEntry.Hide()
	case "华为WeLink":
		urlEntry.Show()
		tokenEntry.Hide()
		secretEntry.Hide()
	case "钉钉":
		urlEntry.Show()
		tokenEntry.Hide()
		secretEntry.Show()
	case "飞书":
		urlEntry.Show()
		tokenEntry.Hide()
		secretEntry.Hide()
	}
}

// SaveMessagePush 保存消息推送配置
func SaveMessagePush(win *Window, enableCheck *widget.Check, webHookSelect *widget.Select, urlEntry, tokenEntry, secretEntry *widget.Entry) {
	platformStr := webHookSelect.Selected
	url := urlEntry.Text
	token := tokenEntry.Text
	secret := secretEntry.Text

	// 转换平台类型
	var platform webhook.PlatformType
	switch platformStr {
	case "企业微信":
		platform = webhook.PlatformWeChat
	case "华为WeLink":
		platform = webhook.PlatformWeLink
	case "钉钉":
		platform = webhook.PlatformDingTalk
	case "飞书":
		platform = webhook.PlatformFeishu
	default:
		platform = webhook.PlatformWeChat
	}

	// 更新配置
	win.MessagePushConfig.Platform = platform
	win.MessagePushConfig.URL = url
	win.MessagePushConfig.Token = token
	win.MessagePushConfig.Secret = secret
	win.MessagePushEnabled = enableCheck.Checked

	// 保存配置到文件
	saveConfig(win)

	fyne.Do(func() {
		if win.MessagePushEnabled {
			ShowSuccess(win.Window, "代理设置", "  代理已启用", nil, 1)
			win.MessagePushCircle.StrokeColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.MessagePushCircle.FillColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.MessagePushCircle.Refresh()
			win.MessagePushLabel.SetText(fmt.Sprintf("消息推送: %s", platformStr))
			win.MessagePushLabel.Refresh()
			win.MessagePushContainer.Refresh()
		} else {
			ShowSuccess(win.Window, "消息推送设置", "  消息推送已禁用", nil, 1)
			win.MessagePushCircle.StrokeColor = color.RGBA{R: 200, G: 0, B: 0, A: 255}
			win.MessagePushCircle.FillColor = color.RGBA{R: 200, G: 0, B: 0, A: 255}
			win.MessagePushCircle.Refresh()
			win.MessagePushLabel.SetText("消息推送: 已禁用")
			win.MessagePushLabel.Refresh()
			win.MessagePushContainer.Refresh()
			win.MessagePushEnabled = false
			// win.MessagePushConfig.Platform = webhook.PlatformWeLink
			// win.MessagePushConfig.URL = ""
			// win.MessagePushConfig.Token = ""
			// win.MessagePushConfig.Secret = ""
		}
	})

	// 保存到文件（可选）
	// TODO: 实现配置持久化

	// ShowSuccess(win.Window, "保存成功", "消息推送配置已保存", nil, 2)
}

func SetDnslog(win *Window) {
	var popUp *widget.PopUp
	// DNS日志设置部分
	enableCheck := widget.NewCheck("启用CEYE", func(enabled bool) {
		// 启用DNS日志逻辑
	})
	enableCheck.SetChecked(win.CeyeConfig.Enabled)

	typeSelect := widget.NewSelect([]string{string(dnslog.HTTP), string(dnslog.DNS)}, func(selected string) {
		// 代理类型选择逻辑
	})

	typeSelect.SetSelected(string(dnslog.DNS))

	tokenEntry := widget.NewEntry()
	tokenEntry.SetPlaceHolder("请输入Ceye的Token")
	tokenEntry.SetText(win.CeyeConfig.Token)
	domainEntry := widget.NewEntry()
	domainEntry.SetPlaceHolder("请输入Ceye的Domain")
	domainEntry.SetText(win.CeyeConfig.Domain)

	CeyeContent := container.NewGridWithColumns(1,
		container.NewBorder(nil, nil, widget.NewLabel("CEYE状态:"), nil, enableCheck),
		container.NewBorder(nil, nil, widget.NewLabel("CEYE类型:"), nil, typeSelect),
		container.NewBorder(nil, nil, widget.NewLabel("CEYE认证:"), nil, tokenEntry),
		container.NewBorder(nil, nil, widget.NewLabel("CEYE域名:"), nil, domainEntry),
	)

	title := widget.NewLabel("🔍 CEYE配置")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	saveButton := widget.NewButton("", func() {
		// 保存设置逻辑
		go SaveDNSLog(win, enableCheck, typeSelect, tokenEntry, domainEntry)
	})
	saveButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	// 然后定义enableCheck，并在回调中更新按钮文本
	enableCheck.OnChanged = func(enabled bool) {
		if enableCheck.Checked {
			saveButton.SetText("保存配置")
		} else {
			saveButton.SetText("取消配置")
		}
	}

	// 初始化按钮文本
	if enableCheck.Checked {
		saveButton.SetText("保存配置")
	} else {
		saveButton.SetText("取消配置")
	}

	closeButton := widget.NewButton("关闭界面", func() {
		// 关闭设置逻辑
		popUp.Hide()
	})
	closeButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	dnslogContent := container.NewBorder(
		container.NewVBox(
			title,
			widget.NewSeparator(),
		),
		container.NewVBox(
			// widget.NewSeparator(),
			CeyeContent,
			widget.NewSeparator(),
		),
		nil, nil,
	)

	dnslogButton := container.NewHBox(
		layout.NewSpacer(),
		saveButton,
		layout.NewSpacer(),
		closeButton,
		layout.NewSpacer(),
	)

	allDnslogContent := container.NewBorder(
		nil, dnslogButton, nil, nil,
		dnslogContent,
	)

	popUp = widget.NewModalPopUp(allDnslogContent, win.Window.Canvas())
	// 计算居中位置
	windowSize := win.Window.Canvas().Size()
	popUpSize := fyne.NewSize(600, 200)
	x := (windowSize.Width - popUpSize.Width) / 2
	y := (windowSize.Height - popUpSize.Height) / 2
	position := fyne.NewPos(x, y)

	fyne.Do(func() {
		popUp.ShowAtPosition(position) // 居中显示
		popUp.Resize(popUpSize)        // 设置弹出窗口大小
	})
}

func OpenFile(win *Window) {
	openFileDialog := dialog.NewFileOpen(func(file fyne.URIReadCloser, err error) {
		if err != nil || file == nil {
			return
		}
		defer file.Close()

		f := file.URI().Path()

		// 打开文件逻辑
		fileContent, err := tools.ReadFileForLines(f)
		if err != nil {
			ShowError(win.Window, "打开文件", err.Error(), nil, 2)
			return
		}

		// 过滤空行和无效URL
		var targets []string
		for _, line := range fileContent {
			if line != "" && tools.IsValidURL(line) {
				targets = append(targets, line)
			}
		}

		if len(targets) == 0 {
			ShowError(win.Window, "打开文件", "文件中没有有效的目标URL", nil, 2)
			return
		}

		// 显示批量扫描确认对话框
		confirmDialog := dialog.NewConfirm("批量扫描", fmt.Sprintf("发现 %d 个有效目标，是否开始批量扫描？", len(targets)), func(confirm bool) {
			if confirm {
				// 开始批量扫描
				go BatchScan(win, targets)
			}
		}, win.Window)
		confirmDialog.Show()
	}, win.Window)

	if currentPath, err := tools.GetRootPath(); err == nil {
		var lister fyne.ListableURI
		if lister, err = storage.ListerForURI(storage.NewFileURI(currentPath)); err == nil {
			openFileDialog.SetLocation(lister)
		} else {
			ShowError(win.Window, "打开文件", err.Error(), nil, 2)
			return
		}
	} else {
		ShowError(win.Window, "打开文件", err.Error(), nil, 2)
		return
	}
	openFileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
	openFileDialog.Show()
}

// saveConfig 保存所有配置到文件（不保存启用状态）
func saveConfig(win *Window) {
	cfg := &config.Config{
		Proxy: config.ProxyConfig{
			Type:     win.ProxyConfig.Type,
			Host:     win.ProxyConfig.Host,
			Port:     win.ProxyConfig.Port,
			Username: win.ProxyConfig.Username,
			Password: win.ProxyConfig.Password,
		},
		Ceye: config.CeyeConfig{
			Type:   win.CeyeConfig.Type,
			Token:  win.CeyeConfig.Token,
			Domain: win.CeyeConfig.Domain,
		},
		MessagePush: config.MessagePushConfig{
			Platform: win.MessagePushConfig.Platform,
			URL:      win.MessagePushConfig.URL,
			Token:    win.MessagePushConfig.Token,
			Secret:   win.MessagePushConfig.Secret,
		},
		AI: config.AIConfig{
			APIKey:   win.AIApiKey,
			APIURL:   win.AIApiURL,
			Model:    win.AIModel,
			Provider: win.AIProvider,
		},
	}
	err := config.SaveConfig(cfg)
	if err != nil {
		win.Logger.Errorf("保存配置失败: %v", err)
	}
}

func SaveProxy(win *Window, enable *widget.Check, typeSelect *widget.Select, hostEntry, portEntry, usernameEntry, passwordEntry *widget.Entry) {
	// 保存代理设置逻辑
	win.ProxyConfig.Enable = enable.Checked
	win.ProxyConfig.Type = strings.TrimSpace(typeSelect.Selected)
	win.ProxyConfig.Host = strings.TrimSpace(hostEntry.Text)
	win.ProxyConfig.Port = strings.TrimSpace(portEntry.Text)
	win.ProxyConfig.Username = strings.TrimSpace(usernameEntry.Text)
	win.ProxyConfig.Password = strings.TrimSpace(passwordEntry.Text)

	if win.ProxyConfig.Enable && !win.ProxyConfig.CheckProxyConfig() {
		ShowError(win.Window, "代理设置", "  配置无效", nil, 1)
		return
	}

	// 保存配置到文件
	saveConfig(win)

	fyne.Do(func() {
		if win.ProxyConfig.Enable {
			ShowSuccess(win.Window, "代理设置", "  代理已启用", nil, 1)
			proxyURL := win.ProxyConfig.GetProxyUrl()
			win.ProyxCircle.StrokeColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.ProyxCircle.FillColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.ProyxCircle.Refresh()
			win.ProxyLabel.SetText(fmt.Sprintf("代理已开启: %s", proxyURL))
			win.ProxyLabel.Refresh()
			win.ProxyContainer.Refresh()
		} else {
			ShowSuccess(win.Window, "代理设置", "  代理已禁用", nil, 1)
			win.ProyxCircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			win.ProyxCircle.FillColor = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			win.ProyxCircle.Refresh()
			win.ProxyLabel.SetText("代理状态: 已禁用")
			win.ProxyLabel.Refresh()
			win.ProxyContainer.Refresh()
			win.ProxyConfig.Enable = false
			// win.ProxyConfig.Host = ""
			// win.ProxyConfig.Port = ""
			// win.ProxyConfig.Username = ""
			// win.ProxyConfig.Password = ""
			// typeSelect.SetSelectedIndex(0)
			// win.ProxyConfig.Type = string(client.HTTP)
			// hostEntry.SetText("")
			// portEntry.SetText("")
			// usernameEntry.SetText("")
			// passwordEntry.SetText("")
		}
	})
}

func SaveDNSLog(win *Window, enable *widget.Check, typeSelect *widget.Select, tokenEntry, domainEntry *widget.Entry) {
	// 保存DNS日志设置逻辑
	win.CeyeConfig.Enabled = enable.Checked
	win.CeyeConfig.Type = strings.TrimSpace(typeSelect.Selected)
	win.CeyeConfig.Token = strings.TrimSpace(tokenEntry.Text)
	win.CeyeConfig.Domain = strings.TrimSpace(domainEntry.Text)

	if win.CeyeConfig.Enabled && !win.CeyeConfig.IsValid() {
		ShowError(win.Window, "CEYE配置", "  配置无效", nil, 1)
		return
	}

	// 保存配置到文件
	saveConfig(win)

	fyne.Do(func() {
		if win.CeyeConfig.Enabled {
			ShowSuccess(win.Window, "CEYE配置", "  配置已保存", nil, 1)
			domain := win.CeyeConfig.GetCeyeFilterDoamin()
			win.DnsLogCircle.StrokeColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.DnsLogCircle.FillColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.DnsLogCircle.Refresh()
			// win.DnsLogCircle.Hide() // 默认隐藏
			win.DnsLogLabel.SetText(fmt.Sprintf("CEYE已配置: %s", domain))
			win.DnsLogLabel.Refresh()
			win.DnsLogContainer.Refresh()
		} else {
			ShowSuccess(win.Window, "CEYE配置", "  配置已保存", nil, 1)
			win.DnsLogCircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			win.DnsLogCircle.FillColor = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			win.DnsLogCircle.Refresh()
			win.DnsLogLabel.SetText("CEYE状态: 已禁用")
			win.DnsLogLabel.Refresh()
			win.DnsLogContainer.Refresh()
			win.CeyeConfig.Enabled = false
			// typeSelect.SetSelectedIndex(0)
			// tokenEntry.SetText("")
			// domainEntry.SetText("")
		}
	})
}

func About(win *Window) {
	// 关于逻辑
	var popUp *widget.PopUp
	iconImageBytes, err := base64.StdEncoding.DecodeString(images.Icon_base64)
	var IconImage *canvas.Image
	if err == nil {
		iconImageResource := fyne.NewStaticResource("icon.png", iconImageBytes)
		IconImage = canvas.NewImageFromResource(iconImageResource)
		IconImage.FillMode = canvas.ImageFillStretch
		IconImage.SetMinSize(fyne.NewSize(160, 160))
		IconImage.Resize(fyne.NewSize(160, 160))
	}

	aboutRichText := widget.NewRichTextFromMarkdown("")
	aboutRichText.Wrapping = fyne.TextWrapWord
	bg1 := canvas.NewRectangle(color.RGBA{R: 0, G: 0, B: 0, A: 255})
	aboutresultContent := container.NewStack(bg1, aboutRichText)
	aboutresultC := container.NewBorder(nil, nil, nil, nil, aboutresultContent)
	aboutScroll := container.NewScroll(aboutresultC)
	aboutScroll.SetMinSize(fyne.NewSize(0, 130))
	aboutScroll.ScrollToBottom()
	aboutRichText.AppendMarkdown("### 免责声明")
	aboutRichText.AppendMarkdown("* 本工具仅用于学习和研究，不承担任何法律责任。")
	aboutRichText.AppendMarkdown("* 在使用工具时，应遵守法律法规，确保行为合法合规。")
	aboutRichText.AppendMarkdown("* 如果您使用本工具扫描目标系统漏洞，您的使用行为将被视为对本声明全部内容的认可。")

	toolsRichText := widget.NewRichTextFromMarkdown("")
	toolsRichText.Wrapping = fyne.TextWrapWord
	bg2 := canvas.NewRectangle(color.RGBA{R: 0, G: 0, B: 0, A: 255})
	resultContent := container.NewStack(bg2, toolsRichText)
	resultC := container.NewBorder(nil, nil, nil, nil, resultContent)
	toolsScroll := container.NewScroll(resultC)
	toolsScroll.SetMinSize(fyne.NewSize(0, 130))
	toolsScroll.ScrollToBottom()
	toolsRichText.AppendMarkdown("### 工具说明")
	toolsRichText.AppendMarkdown("* CVE-2022-22963漏洞扫描工具，旨在帮你快速发现目标系统是否存在漏洞。")
	toolsRichText.AppendMarkdown("* 支持目标系统：Windows")
	toolsRichText.AppendMarkdown("* 支持漏洞类型：CVE-2022-22963等")
	toolsRichText.AppendMarkdown("* 支持http和socks5代理")
	toolsRichText.AppendMarkdown("* [下载](http://baidu.com)")

	leftContainer := container.NewBorder(container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 50)), layout.NewSpacer())),
		container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(5, 50)), layout.NewSpacer())),
		container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(50, 20)), layout.NewSpacer())),
		container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(50, 20)), layout.NewSpacer())),
		container.NewVBox(
			container.NewCenter(widget.NewLabel("欢迎使用")),
			container.NewCenter(IconImage),
			layout.NewSpacer(),
			container.NewCenter(widget.NewLabel("做安全我们是认真的")),
		),
	)

	aboutCard := widget.NewCard("", "免责声明", aboutScroll)
	toolsCard := widget.NewCard("", "工具说明", toolsScroll)
	rightContainer := container.NewVBox(aboutCard, toolsCard)

	closeBtn := widget.NewButton("   关        闭  ", func() {
		popUp.Hide()
	})
	// closeBtn.Importance = widget.Importance(widget.Adaptive)
	// closeBtn.Importance = widget.Importance(widget.Horizontal)
	closeBtn.Importance = widget.Importance(widget.ButtonAlignLeading)
	allContainer := container.NewBorder(nil, container.NewVBox(container.NewHBox(layout.NewSpacer(), closeBtn, layout.NewSpacer()), container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 5)), layout.NewSpacer()))), nil, nil, container.NewBorder(nil, nil, leftContainer, nil, rightContainer))
	popUp = widget.NewModalPopUp(allContainer, win.Window.Canvas())
	// 计算居中位置
	windowSize := win.Window.Canvas().Size()
	popUpSize := fyne.NewSize(600, 200)
	x := (windowSize.Width - popUpSize.Width) / 2
	y := (windowSize.Height - popUpSize.Height) / 2
	position := fyne.NewPos(x, y)

	fyne.Do(func() {
		popUp.ShowAtPosition(position) // 居中显示
		popUp.Resize(popUpSize)        // 设置弹出窗口大小
	})
}

func SaveFile(win *Window) {
	// 保存文件逻辑
	saveFileDialog := dialog.NewFileSave(func(writer fyne.URIWriteCloser, err error) {
		if err != nil || writer == nil {
			return
		}
		defer writer.Close()

		file_path := writer.URI().Path()
		if file_path == "" {
			ShowError(win.Window, "保存文件失败", "请选择保存路径", nil, 2)
			return
		}
		if !strings.HasSuffix(strings.ToLower(file_path), ".txt") {
			ShowError(win.Window, "保存文件失败", "文件名必须以.txt结尾", nil, 2)
			return
		}
		content := []string{
			"漏洞扫描结果",
			"目标系统：",
			"目标IP：",
			"目标端口：",
			"目标端口：",
		}
		// 写入文件
		if err := tools.WriteToFileForLines(file_path, content); err != nil {
			ShowError(win.Window, "保存文件", err.Error(), nil, 2)
			return
		}
		ShowSuccess(win.Window, "保存文件", fmt.Sprintf("文件已保存到：%s", file_path), nil, 2)

	}, win.Window)
	if currentPath, err := tools.GetRootPath(); err == nil {
		var lister fyne.ListableURI
		if lister, err = storage.ListerForURI(storage.NewFileURI(currentPath)); err == nil {
			saveFileDialog.SetLocation(lister)
		} else {
			ShowError(win.Window, "保存文件失败", err.Error(), nil, 2)
			return
		}
	} else {
		ShowError(win.Window, "保存文件失败", err.Error(), nil, 2)
		return
	}
	saveFileDialog.SetFilter(storage.NewExtensionFileFilter([]string{".txt"}))
	saveFileDialog.SetFileName(time.Now().Format("20060102150405") + "vuln.txt")
	fyne.Do(func() {
		saveFileDialog.Show()
	})
}

// SetAI AI分析设置界面
func SetAI(win *Window) {
	var popUp *widget.PopUp

	// AI设置部分
	enableCheck := widget.NewCheck("启用AI分析", func(enabled bool) {
		// 启用AI分析逻辑
	})
	enableCheck.SetChecked(win.AIAnalysisEnabled)

	apiKeyEntry := widget.NewEntry()
	apiKeyEntry.SetPlaceHolder("请输入AI API Key")
	apiKeyEntry.SetText(win.AIApiKey)

	apiURLEntry := widget.NewEntry()
	apiURLEntry.SetPlaceHolder("请输入AI API URL")
	if win.AIApiURL == "" {
		apiURLEntry.SetText("https://api.openai.com/v1/chat/completions")
	} else {
		apiURLEntry.SetText(win.AIApiURL)
	}

	modelEntry := widget.NewEntry()
	modelEntry.SetPlaceHolder("请输入AI模型")
	if win.AIModel == "" {
		modelEntry.SetText("gpt-3.5-turbo")
	} else {
		modelEntry.SetText(win.AIModel)
	}

	// AI服务提供商选择
	providerSelect := widget.NewSelect([]string{"OpenAI", "Google Gemini", "Deepseek", "百度AI", "Moonshot Kimi", "智谱AI", "Hugging Face Free", "Ollama Local"}, func(selected string) {
		// 根据选择的提供商设置默认值
		switch selected {
		case "OpenAI":
			apiURLEntry.SetText("https://api.openai.com/v1/chat/completions")
			modelEntry.SetText("gpt-3.5-turbo")
		case "Google Gemini":
			apiURLEntry.SetText("https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent")
			modelEntry.SetText("gemini-pro")
		case "百度AI":
			apiURLEntry.SetText("https://aip.baidubce.com/rpc/2.0/ai_custom/v1/wenxinworkshop/chat/completions")
			modelEntry.SetText("ERNIE-Bot-4")
		case "Moonshot Kimi":
			apiURLEntry.SetText("https://api.moonshot.cn/v1/chat/completions")
			modelEntry.SetText("moonshot-v1-8k")
		case "智谱AI":
			apiURLEntry.SetText("https://open.bigmodel.cn/api/paas/v4/chat/completions")
			modelEntry.SetText("glm-5")
		case "Hugging Face Free":
			apiURLEntry.SetText("https://api-inference.huggingface.co/models/google/flan-t5-large")
			modelEntry.SetText("google/flan-t5-large")
		case "Ollama Local":
			apiURLEntry.SetText("http://localhost:11434/api/chat")
			modelEntry.SetText("llama3")
		case "Deepseek":
			apiURLEntry.SetText("https://api.deepseek.cn/v1/chat/completions")
			modelEntry.SetText("deepseek-3.2")
		}
	})
	// 设置默认选择
	if win.AIProvider == "" {
		providerSelect.SetSelected("OpenAI")
	} else {
		switch win.AIProvider {
		case "openai":
			providerSelect.SetSelected("OpenAI")
		case "google":
			providerSelect.SetSelected("Google Gemini")
		case "baidu":
			providerSelect.SetSelected("百度AI")
		case "kimi":
			providerSelect.SetSelected("Moonshot Kimi")
		case "zhipu":
			providerSelect.SetSelected("智谱AI")
		case "huggingface":
			providerSelect.SetSelected("Hugging Face Free")
		case "ollama":
			providerSelect.SetSelected("Ollama Local")
		case "deepseek":
			providerSelect.SetSelected("Deepseek")
		default:
			providerSelect.SetSelected("OpenAI")
		}
	}

	// 创建表单内容
	content := container.NewGridWithColumns(1,
		container.NewBorder(nil, nil, widget.NewLabel("AI  状态控制:"), nil, enableCheck),
		container.NewBorder(nil, nil, widget.NewLabel("AI  服务提供:"), nil, providerSelect),
		container.NewBorder(nil, nil, widget.NewLabel("API key输入:"), nil, apiKeyEntry),
		container.NewBorder(nil, nil, widget.NewLabel("API连接地址:"), nil, apiURLEntry),
		container.NewBorder(nil, nil, widget.NewLabel("AI  模型输入:"), nil, modelEntry),
	)

	title := widget.NewLabel("🤖 AI分析配置")
	title.TextStyle = fyne.TextStyle{Bold: true}
	title.Alignment = fyne.TextAlignCenter

	// 创建按钮
	saveButton := widget.NewButton("保存配置", func() {
		go SaveAI(win, enableCheck, providerSelect, apiKeyEntry, apiURLEntry, modelEntry)
		popUp.Hide()
	})
	saveButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	closeButton := widget.NewButton("关闭界面", func() {
		popUp.Hide()
	})
	closeButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	// 创建按钮容器
	buttons := container.NewHBox(
		layout.NewSpacer(),
		saveButton,
		layout.NewSpacer(),
		closeButton,
		layout.NewSpacer(),
	)

	// 创建完整内容
	allContent := container.NewBorder(
		container.NewVBox(
			title,
			widget.NewSeparator(),
		),
		container.NewVBox(
			widget.NewSeparator(),
			buttons,
		),
		nil, nil, container.NewVBox(content),
	)

	popUp = widget.NewModalPopUp(allContent, win.Window.Canvas())

	// 计算居中位置
	windowSize := win.Window.Canvas().Size()
	popUpSize := fyne.NewSize(600, 350)
	x := (windowSize.Width - popUpSize.Width) / 2
	y := (windowSize.Height - popUpSize.Height) / 2
	position := fyne.NewPos(x, y)

	fyne.Do(func() {
		popUp.ShowAtPosition(position)
		popUp.Resize(popUpSize)
	})
}

// SaveAI 保存AI分析配置
func SaveAI(win *Window, enableCheck *widget.Check, providerSelect *widget.Select, apiKeyEntry, apiURLEntry, modelEntry *widget.Entry) {
	win.AIAnalysisEnabled = enableCheck.Checked
	win.AIApiKey = apiKeyEntry.Text
	win.AIApiURL = apiURLEntry.Text
	win.AIModel = modelEntry.Text

	// 保存AI服务提供商
	switch providerSelect.Selected {
	case "OpenAI":
		win.AIProvider = "openai"
	case "Google Gemini":
		win.AIProvider = "google"
	case "百度AI":
		win.AIProvider = "baidu"
	case "Moonshot Kimi":
		win.AIProvider = "kimi"
	case "智谱AI":
		win.AIProvider = "zhipu"
	case "Hugging Face Free":
		win.AIProvider = "huggingface"
	case "Ollama Local":
		win.AIProvider = "ollama"
	case "Deepseek":
		win.AIProvider = "deepseek"
	default:
		win.AIProvider = "openai"
	}
	saveConfig(win)
	fyne.Do(func() {
		if win.AIAnalysisEnabled {
			ShowSuccess(win.Window, "AI分析设置", "AI分析已启用", nil, 1)
			win.AICircle.StrokeColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.AICircle.FillColor = color.RGBA{R: 0, G: 200, B: 0, A: 255}
			win.AICircle.Refresh()
			// win.DnsLogCircle.Hide() // 默认隐藏
			win.AILLabel.SetText(fmt.Sprintf("AI    分析: %s", win.AIProvider))
			win.AILLabel.Refresh()
			win.AICircleContainer.Refresh()
		} else {
			ShowSuccess(win.Window, "AI分析设置", "AI分析已禁用", nil, 1)
			win.AICircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			win.AICircle.FillColor = color.RGBA{R: 255, G: 0, B: 0, A: 255}
			win.AICircle.Refresh()
			// win.DnsLogCircle.Hide() // 默认隐藏
			win.AILLabel.SetText("AI    分析: 已禁用")
			win.AILLabel.Refresh()
			win.AICircleContainer.Refresh()
		}
	})
}

// SetLog 日志设置
func SetLog(win *Window) {
	var popUp *widget.PopUp

	// 日志总开关
	enableCheck := widget.NewCheck("", func(enabled bool) {
		// 启用日志逻辑
	})
	enableCheck.SetChecked(win.LogEnabled)
	enableForm := widget.NewForm(
		widget.NewFormItem("日志开关:", enableCheck),
	)

	// 控制台输出
	consoleCheck := widget.NewCheck("", func(enabled bool) {
		// 控制台输出逻辑
	})
	consoleCheck.SetChecked(win.LogConsoleOutput)
	consoleForm := widget.NewForm(
		widget.NewFormItem("到控制台:", consoleCheck),
	)

	// 文件输出
	fileCheck := widget.NewCheck("", func(enabled bool) {
		// 文件输出逻辑
	})
	fileCheck.SetChecked(win.LogFileOutput)
	fileForm := widget.NewForm(
		widget.NewFormItem("文件输出:", fileCheck),
	)

	// 保存按钮
	saveButton := widget.NewButton("保    存", func() {
		// 保存日志配置
		saveLog(win, enableCheck, consoleCheck, fileCheck)
		popUp.Hide()
	})
	saveButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	// 取消按钮
	cancelButton := widget.NewButton("取    消", func() {
		popUp.Hide()
	})
	cancelButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	// 按钮容器
	buttons := container.NewHBox(
		layout.NewSpacer(),
		saveButton,
		cancelButton,
		layout.NewSpacer(),
	)

	// 主容器
	content := container.NewVBox(
		container.NewCenter(widget.NewLabel("日志设置")),
		widget.NewSeparator(),
		enableForm,
		consoleForm,
		fileForm,
		layout.NewSpacer(),
		widget.NewSeparator(),
		buttons,
	)

	// 创建弹出窗口
	popUp = widget.NewModalPopUp(content, win.Window.Canvas())
	popUpSize := fyne.NewSize(400, 250)
	popUp.Resize(popUpSize)

	// 计算居中位置
	windowSize := win.Window.Canvas().Size()
	position := fyne.NewPos(
		(windowSize.Width-popUpSize.Width)/2,
		(windowSize.Height-popUpSize.Height)/2,
	)

	popUp.ShowAtPosition(position) // 居中显示
}

// saveLog 保存日志配置
func saveLog(win *Window, enableCheck, consoleCheck, fileCheck *widget.Check) {
	win.LogEnabled = enableCheck.Checked
	win.LogConsoleOutput = consoleCheck.Checked
	win.LogFileOutput = fileCheck.Checked

	// 应用日志配置
	win.Logger.SetEnable(win.LogEnabled)
	win.Logger.SetConsoleOutput(win.LogConsoleOutput)
	win.Logger.SetFileOutput(win.LogFileOutput, "./vuln-scan.log")

	// 显示成功消息
	fyne.Do(func() {
		ShowSuccess(win.Window, "日志设置", "日志配置已保存", nil, 1)
	})

	// 记录日志
	win.Logger.Infof("日志配置已更新: 启用=%v, 控制台输出=%v, 文件输出=%v",
		win.LogEnabled, win.LogConsoleOutput, win.LogFileOutput)
}

// BatchScan 批量扫描函数
func BatchScan(win *Window, targets []string) {
	// 清空日志
	fyne.Do(func() {
		win.Tabs.SelectIndex(0)
		win.Tabs.Refresh()
		win.RequestContainer.RemoveAll()
		win.RequestContainer.Refresh()
		win.ResponseContainer.RemoveAll()
		win.ResponseContainer.Refresh()
		win.CeyeContainer.RemoveAll()
		win.CeyeContainer.Refresh()
		win.ResultEntry.SetText("")
		win.ResultEntry.Refresh()
	})

	vuln := win.VulnSelect.Selected
	if vuln == "" {
		fyne.Do(func() {
			ShowError(win.Window, "批量扫描", "请选择漏洞类型", nil, 2)
		})
		return
	}

	// 检查CEYE配置（如果需要）
	var ceyeDomain string
	if vuln == "CVE-2022-22963" || vuln == "CVE-XXXX-XXX2" {
		if win.CeyeConfig.Enabled {
			ceyeDomain = win.CeyeConfig.GetCeyeFilterDoamin()
		} else {
			fyne.Do(func() {
				ShowError(win.Window, "批量扫描", fmt.Sprintf("%s漏洞需要配合DNSLOG验证，请配置CEYE后进行验证", vuln), nil, 2)
			})
			return
		}
	}

	// 准备代理配置
	var proxyUrl string
	if win.ProxyConfig.Enable {
		proxyUrl = win.ProxyConfig.GetProxyUrl()
	}

	// 显示开始扫描信息
	AppendLogInfo("INFO", fmt.Sprintf("开始批量扫描，共 %d 个目标，漏洞类型：%s", len(targets), vuln), win.LoggerScroll, win.LoggerContainer, 100)
	win.Logger.Infof("开始批量扫描，共 %d 个目标，漏洞类型：%s", len(targets), vuln)

	// 限制并发数
	maxConcurrent := 3
	semaphore := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	// 用于统计结果
	totalScanned := 0
	totalVulnerable := 0
	totalFailed := 0

	// 扫描开始时间
	startTime := time.Now()

	for _, target := range targets {
		wg.Add(1)
		go func(t string) {
			defer wg.Done()

			// 获取信号量
			semaphore <- struct{}{}
			defer func() { <-semaphore }()

			// 扫描单个目标
			AppendLogInfo("INFO", fmt.Sprintf("开始扫描目标: %s", t), win.LoggerScroll, win.LoggerContainer, 100)
			win.Logger.Infof("开始扫描目标: %s", t)

			// 执行漏洞扫描
			var re vulnerability.ScanResult
			var err error

			switch vuln {
			case "CVE-2022-22963":
				cve202222963 := vulnerability.NewCVE202222963(vuln, t, proxyUrl, ceyeDomain)
				re, err = cve202222963.Start()
			case "QVD-2026-14149":
				rs := vulnerability.NewQVD202614149(vuln, t, proxyUrl)
				re, err = rs.Start()
			case "CVE-XXXX-XXX2":
				// 这里可以添加其他漏洞的扫描逻辑
				AppendLogInfo("ERROR", fmt.Sprintf("漏洞类型 %s 暂不支持批量扫描", vuln), win.LoggerScroll, win.LoggerContainer, 100)
				win.Logger.Errorf("漏洞类型 %s 暂不支持批量扫描", vuln)
				return
			default:
				AppendLogInfo("ERROR", fmt.Sprintf("未知漏洞类型: %s", vuln), win.LoggerScroll, win.LoggerContainer, 100)
				win.Logger.Errorf("未知漏洞类型: %s", vuln)
				return
			}

			if err != nil {
				AppendLogInfo("ERROR", fmt.Sprintf("扫描目标 %s 失败: %v", t, err), win.LoggerScroll, win.LoggerContainer, 100)
				win.Logger.Errorf("扫描目标 %s 失败: %v", t, err)
				totalFailed++
				return
			}

			// 处理CVE-2022-22963的CEYE验证
			if vuln == "CVE-2022-22963" {
				// 使用重试机制查询CEYE记录
				var success bool
				var record []dnslog.CeyeRecord

				// 最多重试3次，每次间隔1秒
				maxRetries := 3
				for i := 0; i < maxRetries; i++ {
					success, record, err = dnslog.CheckCeyeRecord(win.CeyeConfig, ceyeDomain)
					if err != nil {
						AppendLogInfo("ERROR", fmt.Sprintf("查询CEYE记录失败: %v", err), win.LoggerScroll, win.LoggerContainer, 100)
						win.Logger.Errorf("查询CEYE记录失败: %v", err)
						totalFailed++
						return
					}
					if success && len(record) > 0 {
						break
					}
					if i < maxRetries-1 {
						time.Sleep(1 * time.Second)
					}
				}

				if success && len(record) > 0 {
					AppendLogInfo("SUCCESS", fmt.Sprintf("目标 %s 存在 %s 漏洞", t, vuln), win.LoggerScroll, win.LoggerContainer, 100)
					win.Logger.Infof("目标 %s 存在 %s 漏洞", t, vuln)
					totalVulnerable++

					// 显示请求和响应
					AppendToLabel(string(re.VulnResults.VulnRequestPacket), win.RequestScroll, win.RequestContainer)
					AppendToLabel(string(re.VulnResults.VulnResponsePacket), win.ResponseScroll, win.ResponseContainer)
					AppendToResultEntry(win, re.String())
					AppendToResultEntry(win, "\n\n")
					// 显示多个请求-响应对
					if len(re.VulnResults.RequestResponses) > 0 {
						AppendRequestResponses(win, re.VulnResults.RequestResponses)
					} else {
						// 向后兼容，显示单个请求-响应
						AppendToResultEntry(win, "请求包:\n")
						AppendToResultEntry(win, fmt.Sprintf("%s\n", string(re.VulnResults.VulnRequestPacket)))
						AppendToResultEntry(win, "\n\n")
						AppendToResultEntry(win, "响应包:\n")
						AppendToResultEntry(win, fmt.Sprintf("%s\n", string(re.VulnResults.VulnResponsePacket)))
					}
					// 格式化并显示CEYE记录
					for i, item := range record {
						recordStr := fmt.Sprintf("目标 %s 记录 %d:\n", t, i+1)
						recordStr += fmt.Sprintf("    ID: %s\n", item.ID)
						recordStr += fmt.Sprintf("    名称: %s\n", item.Name)
						recordStr += fmt.Sprintf("    类型: %s\n", item.Type)
						recordStr += fmt.Sprintf("    来源IP: %s\n", item.RemoteAddr)
						recordStr += fmt.Sprintf("    创建时间: %s\n", item.CreatedAt)

						AppendToLabel(recordStr, win.CeyeScroll, win.CeyeContainer)
					}
				} else {
					AppendLogInfo("FAILED", fmt.Sprintf("目标 %s 未发现 %s 漏洞", t, vuln), win.LoggerScroll, win.LoggerContainer, 100)
					win.Logger.Infof("目标 %s 未发现 %s 漏洞", t, vuln)
				}
			} else {
				// 处理其他漏洞的结果
				if re.VulnResults.Success {
					AppendLogInfo("SUCCESS", fmt.Sprintf("目标 %s 存在 %s 漏洞", t, vuln), win.LoggerScroll, win.LoggerContainer, 100)
					win.Logger.Infof("目标 %s 存在 %s 漏洞", t, vuln)
					totalVulnerable++
					AppendToResultEntry(win, fmt.Sprintf("目标 %s 存在 %s 漏洞", t, vuln))
					AppendToResultEntry(win, re.String())
					AppendToResultEntry(win, "\n\n")
					// 显示多个请求-响应对
					if len(re.VulnResults.RequestResponses) > 0 {
						AppendRequestResponses(win, re.VulnResults.RequestResponses)
					} else {
						// 向后兼容，显示单个请求-响应
						AppendToResultEntry(win, "请求包:\n")
						AppendToResultEntry(win, fmt.Sprintf("%s\n", string(re.VulnResults.VulnRequestPacket)))
						AppendToResultEntry(win, "\n\n")
						AppendToResultEntry(win, "响应包:\n")
						AppendToResultEntry(win, fmt.Sprintf("%s\n", string(re.VulnResults.VulnResponsePacket)))
					}
					// 显示请求和响应
					AppendToLabel(string(re.VulnResults.VulnRequestPacket), win.RequestScroll, win.RequestContainer)
					AppendToLabel(string(re.VulnResults.VulnResponsePacket), win.ResponseScroll, win.ResponseContainer)
				} else {
					AppendLogInfo("FAILED", fmt.Sprintf("目标 %s 未发现 %s 漏洞", t, vuln), win.LoggerScroll, win.LoggerContainer, 100)
					win.Logger.Infof("目标 %s 未发现 %s 漏洞", t, vuln)
				}
			}

			// 统一处理AI分析和消息推送
			ProcessVulnerabilityResult(win, re, vuln, t, proxyUrl)
			totalScanned++

			// 显示当前进度
			AppendLogInfo("INFO", fmt.Sprintf("扫描进度: %d/%d", totalScanned, len(targets)), win.LoggerScroll, win.LoggerContainer, 100)
		}(target)
	}

	// 等待所有扫描完成
	wg.Wait()

	// 计算扫描时间
	scanDuration := time.Since(startTime)

	// 显示扫描结果
	AppendLogInfo("INFO", fmt.Sprintf("批量扫描完成，共扫描 %d 个目标，发现 %d 个漏洞，失败 %d 个，耗时 %v",
		totalScanned, totalVulnerable, totalFailed, scanDuration),
		win.LoggerScroll, win.LoggerContainer, 100)
	win.Logger.Infof("批量扫描完成，共扫描 %d 个目标，发现 %d 个漏洞，失败 %d 个，耗时 %v",
		totalScanned, totalVulnerable, totalFailed, scanDuration)

	// 显示通知
	fyne.Do(func() {
		ShowSuccess(win.Window, "批量扫描",
			fmt.Sprintf("批量扫描完成\n共扫描: %d 个目标\n发现漏洞: %d 个\n失败: %d 个\n耗时: %v",
				totalScanned, totalVulnerable, totalFailed, scanDuration),
			nil, 3)
	})
}
