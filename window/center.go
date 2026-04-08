package window

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

func CreateCenterArea(w *Window) fyne.CanvasObject {
	w.LoggerContainer = container.NewVBox()
	w.LoggerContainer.Resize(fyne.NewSize(0, 300))
	bg := canvas.NewRectangle(color.Black)
	logContent := container.NewStack(bg, w.LoggerContainer)
	logContainer := container.NewBorder(nil, nil, nil, nil, logContent)

	w.LoggerScroll = container.NewScroll(logContainer)
	w.LoggerScroll.Resize(fyne.NewSize(0, 300))
	w.LoggerScroll.Show()
	w.LoggerScroll.ScrollToBottom()
	logCard := widget.NewCard("", "检测日志:", w.LoggerScroll)

	// 请求详情
	w.RequestContainer = container.NewVBox()
	w.RequestContainer.Resize(fyne.NewSize(0, 300))
	bg2 := canvas.NewRectangle(color.Black)
	reqContent := container.NewStack(bg2, w.RequestContainer)
	requestContent := container.NewBorder(nil, nil, nil, nil, reqContent)
	w.RequestScroll = container.NewScroll(requestContent)
	w.RequestScroll.Resize(fyne.NewSize(0, 300))
	w.RequestScroll.ScrollToBottom()
	requestCard := widget.NewCard("", "请求详情:", w.RequestScroll)

	// 响应详情
	w.ResponseContainer = container.NewVBox()
	w.ResponseContainer.Resize(fyne.NewSize(0, 300))
	bg3 := canvas.NewRectangle(color.Black)
	respContent := container.NewStack(bg3, w.ResponseContainer)
	reponseContent := container.NewBorder(nil, nil, nil, nil, respContent)
	w.ResponseScroll = container.NewScroll(reponseContent)
	w.ResponseScroll.Resize(fyne.NewSize(0, 300))
	w.ResponseScroll.ScrollToBottom()
	responseCard := widget.NewCard("", "响应详情:", w.ResponseScroll)

	httpContent := container.NewHSplit(
		requestCard,
		responseCard,
	)
	httpContent.SetOffset(0.5)

	// Ceye详情
	w.CeyeContainer = container.NewVBox()
	w.CeyeContainer.Resize(fyne.NewSize(0, 300))
	bg4 := canvas.NewRectangle(color.Black)
	ceyeContent := container.NewStack(bg4, w.CeyeContainer)
	ceyeContentC := container.NewBorder(nil, nil, nil, nil, ceyeContent)
	w.CeyeScroll = container.NewScroll(ceyeContentC)
	w.CeyeScroll.Resize(fyne.NewSize(0, 300))
	w.CeyeScroll.ScrollToBottom()
	w.CeyeCard = widget.NewCard("", "CEYE结果:", w.CeyeScroll)

	// 结果详情
	w.ResultEntry = widget.NewMultiLineEntry()
	w.ResultEntry.SetPlaceHolder("必要时复制结果")
	w.ResultEntry.Wrapping = fyne.TextWrapWord
	w.ResultEntry.OnCursorChanged = func() {
		w.ResultEntry.CursorRow = len(w.ResultEntry.Text) - 1
	}
	w.ResultScroll = container.NewScroll(w.ResultEntry)
	w.ResultScroll.Resize(fyne.NewSize(0, 300))
	w.ResultScroll.ScrollToBottom()
	w.ResultCard = widget.NewCard("", "结果详情:", w.ResultScroll)

	// 创建标签页，默认不显示CEYE结果
	w.Tabs = container.NewAppTabs(
		container.NewTabItemWithIcon("检测日志", theme.HomeIcon(), logCard),
		container.NewTabItemWithIcon("响应详情", theme.ListIcon(), httpContent),
		container.NewTabItemWithIcon("结果详情", theme.InfoIcon(), w.ResultCard),
	)

	// 创建CEYE卡片，但默认不显示
	w.CeyeTabItem = container.NewTabItemWithIcon("CEYE结果", theme.MediaVideoIcon(), w.CeyeCard)

	// // AI对话机器人
	// w.DialogContainer = container.NewVBox()
	// w.DialogContainer.Resize(fyne.NewSize(500, 300))
	// bg5 := canvas.NewRectangle(color.Black)
	// dialogContent := container.NewStack(bg5, w.DialogContainer)
	// dialogContentC := container.NewBorder(nil, nil, nil, nil, dialogContent)
	// w.DialogScroll = container.NewScroll(dialogContentC)
	// w.DialogScroll.Resize(fyne.NewSize(500, 300))
	// w.DialogScroll.ScrollToBottom()

	// // 对话输入区域
	// w.DialogInput = widget.NewEntry()
	// w.DialogInput.SetPlaceHolder("请输入消息...")
	// w.DialogSendButton = widget.NewButton("发送", func() {
	// 	message := w.DialogInput.Text
	// 	if message != "" {
	// 		go SendDialogMessage(w, message)
	// 		w.DialogInput.SetText("")
	// 	}
	// })

	// dialogInputContainer := container.NewBorder(nil, nil, nil, w.DialogSendButton, w.DialogInput)
	// dialogCard := widget.NewCard("", "AI对话机器人", container.NewBorder(nil, dialogInputContainer, nil, nil, w.DialogScroll))

	// w.DialogTabItem = container.NewTabItem("AI对话", dialogCard)
	// w.Tabs.Append(w.DialogTabItem)

	return w.Tabs
}
