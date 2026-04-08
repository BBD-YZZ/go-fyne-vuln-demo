package window

import (
	"fmt"
	"image/color"
	"time"
	"vuln-scan/ai"
	"vuln-scan/dnslog"
	"vuln-scan/tools"
	"vuln-scan/vulnerability"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func CreateTopArea(win *Window) fyne.CanvasObject {
	win.TargetInput = widget.NewEntry()
	win.TargetInput.SetPlaceHolder("请输入目标地址")
	target_form := widget.NewForm(widget.NewFormItem("目标地址", win.TargetInput))

	win.CheckButton = widget.NewButton("开始任务", func() {
		// 检查漏洞
		go CheckButtonFunc(win)
	})
	win.CheckButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	win.ClearButton = widget.NewButton("清空日志", func() {
		// 清除输入框
		win.LoggerContainer.RemoveAll()
		win.LoggerContainer.Refresh()
	})
	win.ClearButton.Importance = widget.Importance(widget.ButtonAlignLeading)

	win.CookiesInput = widget.NewEntry()
	win.CookiesInput.SetPlaceHolder("请输入Cookie")
	cookies_form := widget.NewForm(widget.NewFormItem("认证信息", win.CookiesInput))

	win.VulnSelect = widget.NewSelect([]string{"CVE-2022-22963", "QVD-2026-14149", "CVE-XXXX-XXX2"}, func(selected string) {
		switch selected {
		case "CVE-2022-22963":
			cookies_form.Hide()
			// 需要CEYE，显示CEYE标签页
			fyne.Do(func() {
				tabs := win.Tabs.Items
				hasCeyeTab := false
				for _, tab := range tabs {
					if tab.Text == "CEYE结果" {
						hasCeyeTab = true
						break
					}
				}
				if !hasCeyeTab {
					win.Tabs.Append(win.CeyeTabItem)
					win.Tabs.Refresh()
				}
			})
		case "QVD-2026-14149":
			cookies_form.Hide()
			// 不需要CEYE，隐藏CEYE标签页
			fyne.Do(func() {
				tabs := win.Tabs.Items
				for i, tab := range tabs {
					if tab.Text == "CEYE结果" {
						win.Tabs.RemoveIndex(i)
						win.Tabs.Refresh()
						break
					}
				}
			})
		default:
			win.CookiesInput.SetPlaceHolder(fmt.Sprintf("%s需要认证信息，请输入Cookie", selected))
			cookies_form.Show()
			// 需要CEYE，显示CEYE标签页
			fyne.Do(func() {
				tabs := win.Tabs.Items
				hasCeyeTab := false
				for _, tab := range tabs {
					if tab.Text == "CEYE结果" {
						hasCeyeTab = true
						break
					}
				}
				if !hasCeyeTab {
					win.Tabs.Append(win.CeyeTabItem)
					win.Tabs.Refresh()
				}
			})
		}
	})
	vuln_form := widget.NewForm(widget.NewFormItem("漏洞类型", win.VulnSelect))

	container := container.NewGridWithColumns(1,
		container.NewBorder(nil, nil, nil, container.NewHBox(win.CheckButton, win.ClearButton), container.NewBorder(nil, nil, nil, container.NewGridWrap(fyne.NewSize(300, 30), vuln_form), target_form)),
		cookies_form,
	)
	return container
}

func CheckButtonFunc(win *Window) {
	fyne.Do(func() {
		win.Tabs.SelectIndex(0)
		win.Tabs.Refresh()
		win.CeyeContainer.RemoveAll()
		win.CeyeContainer.Refresh()
		win.RequestContainer.RemoveAll()
		win.RequestContainer.Refresh()
		win.ResponseContainer.RemoveAll()
		win.ResponseContainer.Refresh()
		win.ResultEntry.SetText("")
		win.ResultEntry.Refresh()
	})

	target := win.TargetInput.Text
	vuln := win.VulnSelect.Selected

	if target == "" || !tools.IsValidURL(target) {
		win.Logger.Error("请输入有效的目标地址")
		ShowError(win.Window, "检查漏洞", "请输入有效的目标地址", nil, 2)
		AppendLogInfo("ERROR", "请输入有效的目标地址", win.LoggerScroll, win.LoggerContainer, 100)
		return
	}

	// AppendLogInfo("INFO", fmt.Sprintf("扫描设置--目标：%s", target), win.LoggerScroll, win.LoggerContainer, 100)
	AppendColorText(fmt.Sprintf(" [*] 扫描设置--目标：%s", target), color.RGBA{R: 0, G: 255, B: 255, A: 255}, win.LoggerScroll, win.LoggerContainer)
	win.Logger.Infof("目标地址: %s", target)
	var proxyUrl string
	if win.ProxyConfig.Enable {
		proxyUrl = win.ProxyConfig.GetProxyUrl()
		// AppendLogInfo("INFO", fmt.Sprintf("扫描设置--代理：%s", proxyUrl), win.LoggerScroll, win.LoggerContainer, 100)
		AppendColorText(fmt.Sprintf(" [*] 扫描设置--代理：%s", proxyUrl), color.RGBA{R: 0, G: 255, B: 255, A: 255}, win.LoggerScroll, win.LoggerContainer)
		win.Logger.Infof("使用代理: %s", proxyUrl)
	} else {
		proxyUrl = ""
		win.Logger.Infof("本次检查不使用代理")
		// AppendLogInfo("INFO", "扫描设置--代理：未开启", win.LoggerScroll, win.LoggerContainer, 100)
		AppendColorText(" [*] 扫描设置--代理：未开启", color.RGBA{R: 0, G: 255, B: 255, A: 255}, win.LoggerScroll, win.LoggerContainer)
	}

	var ceyeDomain string
	if win.CeyeConfig.Enabled {
		ceyeDomain = win.CeyeConfig.GetCeyeFilterDoamin()
		win.Logger.Infof("CEYE域名: %s", ceyeDomain)
		// AppendLogInfo("INFO", fmt.Sprintf("扫描设置--Dnslog：%s", ceyeDomain), win.LoggerScroll, win.LoggerContainer, 100)
		AppendColorText(fmt.Sprintf(" [*] 扫描设置--Dnslog：%s", ceyeDomain), color.RGBA{R: 0, G: 255, B: 255, A: 255}, win.LoggerScroll, win.LoggerContainer)
	} else {
		ceyeDomain = ""
		win.Logger.Infof("CEYE域名: %s", ceyeDomain)
		// AppendLogInfo("INFO", "扫描设置--Dnslog：未开启", win.LoggerScroll, win.LoggerContainer, 100)
		AppendColorText(" [*] 扫描设置--Dnslog：未开启", color.RGBA{R: 0, G: 255, B: 255, A: 255}, win.LoggerScroll, win.LoggerContainer)
	}

	options := vulnerability.FieldOptions{
		IncludeSuccess:    true,
		IncludeVulnStatus: true,
		IncludeVulnDetail: true,
		IncludeStatistics: true,
		IncludeAIAnalysis: true,
	}

	switch vuln {
	case "CVE-2022-22963":
		AppendLogInfo("INFO", fmt.Sprintf("开始扫描漏洞：%s", vuln), win.LoggerScroll, win.LoggerContainer, 100)
		win.Logger.Infof("漏洞类型: %s", vuln)
		if ceyeDomain == "" {
			win.Logger.Infof("%s漏洞需要配合DNSLOG验证，请配置CEYE后进行验证", vuln)
			AppendLogInfo("WARNING", fmt.Sprintf("%s漏洞需要配合DNSLOG验证，请配置CEYE后进行验证", vuln), win.LoggerScroll, win.LoggerContainer, 100)
			return
		}
		cve202222963 := vulnerability.NewCVE202222963(vuln, target, proxyUrl, ceyeDomain)
		re, err := cve202222963.Start()
		if err != nil {
			win.Logger.Errorf("检查漏洞失败: %s", err.Error())
			AppendLogInfo("ERROR", "检查漏洞失败, 错误详情请查看日志文件", win.LoggerScroll, win.LoggerContainer, 100)
			return
		}

		// 使用重试机制查询CEYE记录
		var success bool
		var record []dnslog.CeyeRecord

		// 最多重试3次，每次间隔1秒
		maxRetries := 3
		for i := 0; i < maxRetries; i++ {
			success, record, err = dnslog.CheckCeyeRecord(win.CeyeConfig, ceyeDomain)
			if err != nil {
				win.Logger.Errorf("检查漏洞失败: %s", err.Error())
				AppendLogInfo("ERROR", "检查漏洞失败, 错误详情请查看日志文件", win.LoggerScroll, win.LoggerContainer, 100)
				return
			}
			if success && len(record) > 0 {
				break
			}
			if i < maxRetries-1 {
				AppendLogInfo("INFO", fmt.Sprintf("正在查询CEYE记录，第%d次尝试，请稍等……", i+1), win.LoggerScroll, win.LoggerContainer, 100)
				time.Sleep(1 * time.Second)
			}
		}

		if success && len(record) > 0 {
			win.Logger.Infof("%s存在%s漏洞", target, vuln)
			AppendLogInfo("SUCCESS", fmt.Sprintf("扫描漏洞--结果：%s存在%s漏洞", target, vuln), win.LoggerScroll, win.LoggerContainer, 100)
			if err != nil {
				win.Logger.Errorf("检查漏洞失败: %s", err.Error())
				AppendLogInfo("ERROR", "检查漏洞失败, 错误详情请查看日志文件", win.LoggerScroll, win.LoggerContainer, 100)
				return
			}
			AppendToResultEntry(win, fmt.Sprintf("%s存在%s漏洞，共发现%d条CEYE记录\n", target, vuln, len(record)))
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
			AppendToLabel(string(re.VulnResults.VulnRequestPacket), win.RequestScroll, win.RequestContainer)
			AppendToLabel(string(re.VulnResults.VulnResponsePacket), win.ResponseScroll, win.ResponseContainer)
			// AppendToLabel(re.StringWithFilter(options), win.LoggerScroll, win.LoggerContainer)
			ShowNotification(fmt.Sprintf("目标%s存在%s漏洞，共发现%d条CEYE记录", target, vuln, len(record)))
			// 格式化并显示CEYE记录
			for i, item := range record {
				recordStr := fmt.Sprintf("记录 %d:\n", i+1)
				recordStr += fmt.Sprintf("    ID: %s\n", item.ID)
				recordStr += fmt.Sprintf("    名称: %s\n", item.Name)
				recordStr += fmt.Sprintf("    类型: %s\n", item.Type)
				recordStr += fmt.Sprintf("    来源IP: %s\n", item.RemoteAddr)
				recordStr += fmt.Sprintf("    创建时间: %s\n", item.CreatedAt)

				AppendToLabel(recordStr, win.CeyeScroll, win.CeyeContainer)
			}
		} else {
			AppendLogInfo("FAILED", fmt.Sprintf("扫描漏洞--结果：%s未发现%s漏洞", target, vuln), win.LoggerScroll, win.LoggerContainer, 100)
		}
		// 统一处理AI分析和消息推送
		ProcessVulnerabilityResult(win, re, vuln, target, proxyUrl)
	case "QVD-2026-14149":
		AppendLogInfo("INFO", fmt.Sprintf("开始扫描漏洞：%s", vuln), win.LoggerScroll, win.LoggerContainer, 100)
		rs := vulnerability.NewQVD202614149(vuln, target, proxyUrl)
		re, err := rs.Start()
		if err != nil {
			win.Logger.Errorf("检查漏洞失败: %s", err.Error())
			AppendLogInfo("ERROR", "检查漏洞失败, 错误详情请查看日志文件", win.LoggerScroll, win.LoggerContainer, 100)
			return
		}

		if re.VulnResults.Success {
			AppendToResultEntry(win, fmt.Sprintf("%s存在%s漏洞", target, vuln))
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
			AppendLogInfo("SUCCESS", fmt.Sprintf("扫描漏洞--结果：%s存在%s漏洞", target, vuln), win.LoggerScroll, win.LoggerContainer, 100)
			AppendToLabel(string(re.VulnResults.VulnRequestPacket), win.RequestScroll, win.RequestContainer)
			AppendToLabel(string(re.VulnResults.VulnResponsePacket), win.ResponseScroll, win.ResponseContainer)
			AppendToLabel(re.StringWithFilter(options), win.LoggerScroll, win.LoggerContainer)
		} else {
			AppendLogInfo("FAILED", fmt.Sprintf("扫描漏洞--结果：%s未发现%s漏洞", target, vuln), win.LoggerScroll, win.LoggerContainer, 100)
			win.Logger.Infof("%s未发现%s漏洞", target, vuln)
		}

		// 统一处理AI分析和消息推送
		ProcessVulnerabilityResult(win, re, vuln, target, proxyUrl)
	case "CVE-XXXX-XXX2":
		var ceyeDomain string
		if win.CeyeConfig.Enabled {
			ceyeDomain = win.CeyeConfig.GetCeyeFilterDoamin()
		} else {
			ceyeDomain = ""
		}
		if ceyeDomain != "" {
			AppendLogInfo("INFO", fmt.Sprintf("使用Ceye域名: %s", ceyeDomain), win.LoggerScroll, win.LoggerContainer, 100)
		} else {
			AppendLogInfo("ERROR", fmt.Sprintf("未配置CEYE, %s漏洞必须配合DNSLOG来使用!", vuln), win.LoggerScroll, win.LoggerContainer, 100)
			return
		}
		AppendLogInfo("INFO", fmt.Sprintf("扫描漏洞--漏洞：%s", vuln), win.LoggerScroll, win.LoggerContainer, 100)
	}
}

// SendDialogMessage 发送对话消息
func SendDialogMessage(win *Window, message string) {
	// 显示用户消息
	userLabel := widget.NewLabel(fmt.Sprintf("[用户] %s", message))
	userLabel.TextStyle = fyne.TextStyle{Bold: true}
	fyne.Do(func() {
		win.DialogContainer.Add(userLabel)
		win.DialogContainer.Refresh()
		win.DialogScroll.ScrollToBottom()
	})

	// 显示AI正在输入
	typingLabel := widget.NewLabel("[AI] 正在输入...")
	typingLabel.TextStyle = fyne.TextStyle{Italic: true}
	fyne.Do(func() {
		win.DialogContainer.Add(typingLabel)
		win.DialogContainer.Refresh()
		win.DialogScroll.ScrollToBottom()
	})

	// 调用AI API
	aiConfig := &ai.Config{
		Enabled:  true,
		APIKey:   win.AIApiKey,
		APIURL:   win.AIApiURL,
		Model:    win.AIModel,
		Provider: win.AIProvider,
	}

	// 构建对话提示词
	prompt := fmt.Sprintf(`
用户提问：%s

请作为一位资深的网络安全专家，友好地回答用户的问题。如果问题与网络安全、漏洞分析、安全加固等相关，请提供专业的建议和指导。
如果是一般性问题，请根据你的知识提供准确的回答。
请使用中文回复，保持友好和专业的语气。
`, message)

	result, err := ai.AnalyzeVulnerability(aiConfig, "Dialog", "UserQuery", "", prompt)
	if err != nil {
		// 移除正在输入提示
		fyne.Do(func() {
			win.DialogContainer.Remove(typingLabel)
			win.DialogContainer.Refresh()
		})

		// 显示错误消息
		errorLabel := widget.NewLabel(fmt.Sprintf("[AI] 回答失败: %v", err))
		errorLabel.TextStyle = fyne.TextStyle{Bold: true}
		fyne.Do(func() {
			win.DialogContainer.Add(errorLabel)
			win.DialogContainer.Refresh()
			win.DialogScroll.ScrollToBottom()
		})
		return
	}

	// 移除正在输入提示
	fyne.Do(func() {
		win.DialogContainer.Remove(typingLabel)
		win.DialogContainer.Refresh()
	})

	// 显示AI回复
	aiLabel := widget.NewLabel(fmt.Sprintf("[AI] %s", result.Description))
	fyne.Do(func() {
		win.DialogContainer.Add(aiLabel)
		win.DialogContainer.Refresh()
		win.DialogScroll.ScrollToBottom()
	})
}
