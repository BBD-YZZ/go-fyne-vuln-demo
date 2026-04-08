package window

import (
	"fmt"
	"image/color"
	"time"
	"unicode/utf8"
	"vuln-scan/ai"
	"vuln-scan/vulnerability"
	"vuln-scan/webhook"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func ShowMessage(window fyne.Window, title string, message string, colortext *canvas.Text, callback func(), duration time.Duration) {
	var info *canvas.Text
	if colortext == nil {
		info = canvas.NewText(fmt.Sprintf("🔊    %s", message), theme.ForegroundColor())
	} else {
		info = canvas.NewText(fmt.Sprintf("🔊    %s", message), colortext.Color)
	}
	info.Alignment = fyne.TextAlignTrailing
	info.TextStyle = fyne.TextStyle{Bold: true}
	info.TextSize = theme.TextSize() * 1

	// content := container.NewVBox(widget.NewLabel(title), layout.NewSpacer(), info)
	content := container.NewBorder(container.NewVBox(widget.NewLabel(title), layout.NewSpacer()), nil, layout.NewSpacer(), info)

	pop := widget.NewModalPopUp(content, window.Canvas())
	fyne.Do(func() {
		pop.Show()
	})

	if duration > 0 {
		go func() {
			time.Sleep(duration * time.Second)
			fyne.Do(func() {
				pop.Hide()
				if callback != nil {
					callback()
				}
			})
		}()
	}
}

func ShowError(window fyne.Window, title string, message string, callback func(), duration time.Duration) {
	ShowMessage(window, title, message, canvas.NewText(message, theme.ErrorColor()), callback, duration)
}

func ShowSuccess(window fyne.Window, title string, message string, callback func(), duration time.Duration) {
	ShowMessage(window, title, message, canvas.NewText(message, theme.SuccessColor()), callback, duration)
}

func ShowInfo(window fyne.Window, title string, message string, callback func(), duration time.Duration) {
	ShowMessage(window, title, message, canvas.NewText(message, theme.ForegroundColor()), callback, duration)
}

func ShowWarning(window fyne.Window, title string, message string, callback func(), duration time.Duration) {
	ShowMessage(window, title, message, canvas.NewText(message, color.RGBA{R: 255, G: 165, B: 0, A: 255}), callback, duration)
}

func AppendContentToLabel(label *widget.Label, content string, scroll *container.Scroll, length int) {
	currentText := label.Text
	var newText string

	if utf8.RuneCountInString(content) > length {
		// 找到第length个字符的位置
		var totalSize int
		for i := 0; i < length; i++ {
			_, size := utf8.DecodeRuneInString(content[totalSize:])
			totalSize += size
		}
		content = content[:totalSize] + "……"
	}

	if currentText == "" {
		newText = content
	} else {
		newText = fmt.Sprintf("%s\n%s", currentText, content)
	}
	label.SetText(newText)
	label.Wrapping = fyne.TextWrapWord
	label.TextStyle = fyne.TextStyle{Bold: true}
	fyne.Do(func() {
		label.Refresh()
		scroll.ScrollToBottom()
		scroll.Refresh()
	})
}

func getColorByLevel(level string) color.Color {
	switch level {
	case "INFO":
		return color.RGBA{R: 0, G: 255, B: 0, A: 255} // 绿色
	case "ERROR":
		return color.RGBA{R: 255, G: 0, B: 0, A: 255} // 红色
	case "WARNING":
		return color.RGBA{R: 255, G: 165, B: 0, A: 255} // 橙色
	case "VULN":
		return color.RGBA{R: 0, G: 191, B: 255, A: 255} // 蓝色
	case "SUCCESS":
		return color.RGBA{R: 255, G: 0, B: 255, A: 255} // 粉色
	case "FAILED":
		return color.RGBA{R: 199, G: 21, B: 133, A: 255} // 紫色
	default:
		return color.RGBA{R: 255, G: 255, B: 255, A: 255} // 白色
	}
}

func AppendLogInfo(level string, content string, scroll *container.Scroll, logContainer *fyne.Container, length int) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	// 创建一个水平布局的容器，确保每个日志条目内部的元素在同一行
	hbox := container.NewHBox()

	// 时间戳 - 白色
	timeText := canvas.NewText(timestamp+" -", color.RGBA{R: 255, G: 255, B: 255, A: 255})
	timeText.TextSize = 14

	// 级别 - 带颜色
	levelText := canvas.NewText(level, getColorByLevel(level))
	levelText.TextSize = 15

	// 内容 - 白色，使用canvas.NewText
	if utf8.RuneCountInString(content) > length {
		// 找到第length个字符的位置
		var totalSize int
		for i := 0; i < length; i++ {
			_, size := utf8.DecodeRuneInString(content[totalSize:])
			totalSize += size
		}
		content = content[:totalSize] + "……"
	}
	contentText := canvas.NewText(fmt.Sprintf("- %s", content), color.RGBA{R: 255, G: 255, B: 255, A: 255})
	contentText.TextSize = 14

	// 添加所有元素到容器
	hbox.Add(timeText)
	hbox.Add(levelText)
	hbox.Add(contentText)

	// 添加到日志容器（VBox）
	logContainer.Add(hbox)

	// 限制日志条目数量，保留最近的100条
	maxEntries := 100
	if len(logContainer.Objects) > maxEntries {
		// 移除最旧的条目
		oldEntry := logContainer.Objects[0]
		logContainer.Remove(oldEntry)
	}
	fyne.Do(func() {
		logContainer.Refresh()
		// 滚动到底部
		scroll.ScrollToBottom()
		scroll.Refresh()
	})
}

func AppendToLabel(content string, scroll *container.Scroll, labelContainer *fyne.Container) {
	// 限制单条内容长度，防止过大的内容导致卡顿
	maxContentLength := 2000
	if utf8.RuneCountInString(content) > maxContentLength {
		var totalSize int
		for i := 0; i < maxContentLength; i++ {
			_, size := utf8.DecodeRuneInString(content[totalSize:])
			totalSize += size
		}
		content = content[:totalSize] + "……(响应过长,自动截取2000个字符)"
	}

	// 创建新的日志条目（直接添加到容器，不使用HBox包装）
	label := widget.NewLabel(content)
	label.Wrapping = fyne.TextWrapWord

	// 添加到容器
	fyne.Do(func() {
		labelContainer.Add(label)
	})

	// 限制日志条目数量，保留最近的100条
	maxEntries := 100
	if len(labelContainer.Objects) > maxEntries {
		// 移除最旧的条目
		oldEntry := labelContainer.Objects[0]
		labelContainer.Remove(oldEntry)
	}

	// 在UI线程中更新界面
	fyne.Do(func() {
		labelContainer.Refresh()
		scroll.ScrollToBottom()
		scroll.Refresh()
	})
}

// AppendToRichText 将内容追加到自动创建的RichText组件中
func AppendToRichText(content string, scroll *container.Scroll, labelContainer *fyne.Container) {
	// 检查是否已经有RichText组件
	var richText *widget.RichText
	hasRichText := false

	// 遍历容器中的所有对象，查找RichText组件
	for _, obj := range labelContainer.Objects {
		if rt, ok := obj.(*widget.RichText); ok {
			richText = rt
			hasRichText = true
			break
		}
	}

	// 如果没有RichText组件，创建一个新的
	if !hasRichText {
		richText = widget.NewRichText()

		// // 设置RichText的高度，使其显示更多内容
		// richText.Resize(fyne.NewSize(0, 300))

		// 添加到容器
		fyne.Do(func() {
			labelContainer.Add(richText)
			labelContainer.Refresh()
			scroll.Refresh()
		})
	}

	// 获取当前内容
	currentSegments := richText.Segments

	// 将新内容转换为segments
	var newSegments []widget.RichTextSegment

	newSegments = append(newSegments, &widget.TextSegment{Text: content})

	// 更新RichText内容
	fyne.Do(func() {
		richText.Segments = append(currentSegments, newSegments...)
		// richText.Wrapping = fyne.TextWrapWord
		richText.Refresh()
		labelContainer.Refresh()
		scroll.ScrollToBottom()
		scroll.Refresh()
	})
}

func Notification(content string) {
	fyne.CurrentApp().SendNotification(&fyne.Notification{
		Title:   "",
		Content: content,
	})
}

func ShowNotification(content string, value ...interface{}) {
	Notification(fmt.Sprintf(content, value...))
}

// ProcessVulnerabilityResult 统一处理漏洞扫描结果
func ProcessVulnerabilityResult(win *Window, re vulnerability.ScanResult, vuln string, target string, proxyUrl string) {
	// 1. 处理AI分析
	if win.AIAnalysisEnabled && re.VulnResults.Success {
		go func() {
			AppendLogInfo("INFO", "正在使用AI分析漏洞信息，请稍等...", win.LoggerScroll, win.LoggerContainer, 100)

			aiConfig := &ai.Config{
				Enabled:  true,
				APIKey:   win.AIApiKey,
				APIURL:   win.AIApiURL,
				Model:    win.AIModel,
				Provider: win.AIProvider,
			}

			analysisResult, err := ai.AnalyzeVulnerability(aiConfig, vuln, target,
				string(re.VulnResults.VulnRequestPacket),
				string(re.VulnResults.VulnResponsePacket))
			if err != nil {
				AppendLogInfo("ERROR", fmt.Sprintf("AI分析失败: %v", err), win.LoggerScroll, win.LoggerContainer, 100)
				win.Logger.Errorf("AI分析失败: %v", err)
			} else {
				re.VulnResults.AIAnalysis = analysisResult
				AppendLogInfo("SUCCESS", "AI分析完成", win.LoggerScroll, win.LoggerContainer, 100)
				win.Logger.Infof("AI 分析的结果：\n %v", analysisResult.Description)
				AppendToRichText(analysisResult.Description, win.LoggerScroll, win.LoggerContainer)
				AppendToResultEntry(win, analysisResult.Description)
			}
		}()
	}

	// 2. 处理消息推送
	if win.MessagePushEnabled {
		go func() {
			messageInfo := ""
			if re.VulnResults.Success {
				messageInfo = re.VulnResults.VulnRequestPacket
			}
			fmt.Println(messageInfo)
			err := webhook.SendVulnerabilityAlert(win.MessagePushConfig, proxyUrl, target, vuln, messageInfo)
			if err != nil {
				win.Logger.Errorf("发送消息推送失败: %v", err)
				AppendLogInfo("ERROR", fmt.Sprintf("发送消息推送失败: %v", err), win.LoggerScroll, win.LoggerContainer, 100)
			} else {
				win.Logger.Infof("消息推送发送成功")
				AppendLogInfo("INFO", "消息推送发送成功", win.LoggerScroll, win.LoggerContainer, 100)
			}
		}()
	}
}

func AppendToResultEntry1(content string, resultEntry *widget.Entry, scroll *container.Scroll) {
	fyne.Do(func() {
		var maxLines = 500

		resultEntry.Append(content)

		text := resultEntry.Text

		lines := 0
		for i := range text {
			if text[i] == '\n' {
				lines++
			}
		}
		// 最后一行如果不是空行也算一行
		if len(text) > 0 && text[len(text)-1] != '\n' {
			lines++
		}

		// 如果超过最大行数，删除前面的行
		if lines > maxLines {
			// 计算需要保留的起始位置
			linesToRemove := lines - maxLines
			removeCount := 0
			startIndex := 0

			for i := range text {
				if text[i] == '\n' {
					removeCount++
					if removeCount == linesToRemove {
						startIndex = i + 1
						break
					}
				}
			}

			// 截取文本
			if startIndex > 0 {
				resultEntry.SetText(text[startIndex:])
			}
		}

		// 滚动到底部

		resultEntry.Wrapping = fyne.TextWrapWord
		resultEntry.Refresh()
		scroll.ScrollToBottom()
		scroll.Refresh()
	})
}

// AppendToResultEntry 向ResultEntry添加内容并限制行数
func AppendToResultEntry(win *Window, content string) {
	// 使用fyne.Do确保所有UI操作都在主线程中执行
	fyne.Do(func() {
		// 最大行数限制
		maxLines := 500

		// 添加内容
		win.ResultEntry.Append(content)

		// 获取当前文本
		text := win.ResultEntry.Text

		// 计算行数
		lines := 0
		for i := range text {
			if text[i] == '\n' {
				lines++
			}
		}
		// 最后一行如果不是空行也算一行
		if len(text) > 0 && text[len(text)-1] != '\n' {
			lines++
		}

		// 如果超过最大行数，删除前面的行
		if lines > maxLines {
			// 计算需要保留的起始位置
			linesToRemove := lines - maxLines
			removeCount := 0
			startIndex := 0

			for i := range text {
				if text[i] == '\n' {
					removeCount++
					if removeCount == linesToRemove {
						startIndex = i + 1
						break
					}
				}
			}

			// 截取文本
			if startIndex > 0 {
				win.ResultEntry.SetText(text[startIndex:])
			}
		}

		// 滚动到底部
		win.ResultEntry.Wrapping = fyne.TextWrapWord
		win.ResultEntry.Refresh()
		win.ResultScroll.Refresh()
	})
}

// AppendRequestResponses 向ResultEntry添加多个请求-响应对
func AppendRequestResponses(win *Window, responses []vulnerability.RequestResponse) {
	// 使用fyne.Do确保所有UI操作都在主线程中执行
	fyne.Do(func() {
		// 最大行数限制
		maxLines := 500

		// 添加多个请求-响应对
		for _, rr := range responses {
			// 添加请求序号
			win.ResultEntry.Append(fmt.Sprintf("请求 #%d:\n", rr.Index))
			// 添加请求包
			win.ResultEntry.Append("请求包:\n")
			win.ResultEntry.Append(rr.RequestPacket)
			win.ResultEntry.Append("\n\n")
			// 添加响应包
			win.ResultEntry.Append("响应包:\n")
			win.ResultEntry.Append(rr.ResponsePacket)
			win.ResultEntry.Append("\n\n")
		}

		// 获取当前文本
		text := win.ResultEntry.Text

		// 计算行数
		lines := 0
		for i := range text {
			if text[i] == '\n' {
				lines++
			}
		}
		// 最后一行如果不是空行也算一行
		if len(text) > 0 && text[len(text)-1] != '\n' {
			lines++
		}

		// 如果超过最大行数，删除前面的行
		if lines > maxLines {
			// 计算需要保留的起始位置
			linesToRemove := lines - maxLines
			removeCount := 0
			startIndex := 0

			for i := range text {
				if text[i] == '\n' {
					removeCount++
					if removeCount == linesToRemove {
						startIndex = i + 1
						break
					}
				}
			}

			// 截取文本
			if startIndex > 0 {
				win.ResultEntry.SetText(text[startIndex:])
			}
		}

		// 滚动到底部
		win.ResultEntry.Wrapping = fyne.TextWrapWord
		win.ResultEntry.Refresh()
		win.ResultScroll.Refresh()
	})
}

func AppendColorText(text string, colorRBG color.RGBA, scroll *container.Scroll, ColorContainer *fyne.Container) {
	hbox := container.NewHBox()
	colorText := canvas.NewText(text, colorRBG)
	colorText.TextSize = 14
	fyne.Do(func() {
		hbox.Add(colorText)
		ColorContainer.Add(hbox)
		ColorContainer.Refresh()
		scroll.ScrollToBottom()
		scroll.Refresh()
	})
}
