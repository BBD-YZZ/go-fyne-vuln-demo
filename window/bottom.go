package window

import (
	"encoding/base64"
	"fmt"
	"image/color"
	"time"
	"vuln-scan/images"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/layout"
	"fyne.io/fyne/v2/widget"
)

func CreateBottomArea(win *Window) fyne.CanvasObject {
	// rootPath, err := tools.GetRootPath()
	// if err != nil {
	// 	return nil
	// }

	// imagePath := fmt.Sprintf("%s/images/%s", rootPath, "wechat.png")
	// wechatImage, err := os.ReadFile(imagePath)
	// if err != nil {
	// 	return nil
	// }
	// win.Image = fyne.NewStaticResource("wechat.png", wechatImage)
	// img := canvas.NewImageFromResource(win.Image)
	// img.FillMode = canvas.ImageFillStretch
	// img.SetMinSize(fyne.NewSize(120, 120))
	// img.Resize(fyne.NewSize(120, 120))

	wechatImageBytes, err := base64.StdEncoding.DecodeString(images.WeChart_base64)
	if err == nil {
		wechatImageResource := fyne.NewStaticResource("wechat.png", wechatImageBytes)
		win.WechatImage = canvas.NewImageFromResource(wechatImageResource)
		win.WechatImage.FillMode = canvas.ImageFillStretch
		win.WechatImage.SetMinSize(fyne.NewSize(120, 120))
		win.WechatImage.Resize(fyne.NewSize(120, 120))
	}

	win.TimeLabel = widget.NewLabel(fmt.Sprintf("北京时间：%s", time.Now().Format("2006-01-02 15:04:05")))
	win.InfomationLabel = widget.NewLabel("这是一个漏洞介绍工具，用于介绍漏洞的详细信息。")

	win.WelcomeLabel = widget.NewLabel("XXXX漏洞扫描工具")
	win.DisclaimerLabel = widget.NewLabel("本工具仅用于学习和研究，不承担任何法律责任。")
	authLabel := widget.NewLabel("作者： YanZhou")
	addressLabel := widget.NewLabel("地址： 信息安全管理部")
	contactLabel := widget.NewLabel("联系我们： 1234567890")

	win.ProyxCircle = canvas.NewCircle(color.RGBA{R: 255, G: 0, B: 0, A: 255})
	win.ProyxCircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255} // color.Gray{0x99}
	win.ProyxCircle.StrokeWidth = 2
	// win.ProyxCircle.Hide() // 默认隐藏
	win.ProxyLabel = widget.NewLabel("代理状态: 已禁用")
	win.ProxyContainer = container.NewHBox(container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 10)), win.ProyxCircle)), win.ProxyLabel)

	win.StatusLabel = widget.NewLabel("联系我们")

	win.DnsLogCircle = canvas.NewCircle(color.RGBA{R: 255, G: 0, B: 0, A: 255})
	win.DnsLogCircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255} // color.Gray{0x99}
	win.DnsLogCircle.StrokeWidth = 2
	// win.DnsLogCircle.Hide() // 默认隐藏
	win.DnsLogLabel = widget.NewLabel("CEYE状态: 已禁用")
	win.DnsLogContainer = container.NewHBox(container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 10)), win.DnsLogCircle)), win.DnsLogLabel)

	win.MessagePushCircle = canvas.NewCircle(color.RGBA{R: 255, G: 0, B: 0, A: 255})
	win.MessagePushCircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255} // color.Gray{0x99}
	win.MessagePushCircle.StrokeWidth = 2
	// win.MessagePushCircle.Hide() // 默认隐藏
	win.MessagePushLabel = widget.NewLabel("消息推送: 已禁用")
	win.MessagePushContainer = container.NewHBox(container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 10)), win.MessagePushCircle)), win.MessagePushLabel)

	win.AILLabel = widget.NewLabel("AI    分析: 已禁用")
	win.AICircle = canvas.NewCircle(color.RGBA{R: 255, G: 0, B: 0, A: 255})
	win.AICircle.StrokeColor = color.RGBA{R: 255, G: 0, B: 0, A: 255} // color.Gray{0x99}
	win.AICircle.StrokeWidth = 2
	// win.AICircle.Hide() // 默认隐藏
	win.AICircleContainer = container.NewHBox(container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 10)), win.AICircle)), win.AILLabel)

	win.FormLabel = widget.NewLabel("大漠孤烟直，长河落日圆。")

	leftPanel := container.NewBorder(container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(10, 30)), layout.NewSpacer())),
		container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(5, 0)), layout.NewSpacer())),
		container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(50, 20)), layout.NewSpacer())),
		container.NewCenter(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(50, 20)), layout.NewSpacer())),
		container.NewVBox(
			container.NewCenter(win.StatusLabel),
			container.NewCenter(win.WechatImage),
		))

	push := container.NewHSplit(

		container.NewHBox(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(5, 0)), layout.NewSpacer()), container.NewCenter(win.MessagePushContainer)),
		container.NewHBox(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(5, 0)), layout.NewSpacer()), container.NewCenter(win.DnsLogContainer)),
	)
	push.SetOffset(0.3)

	ai := container.NewHSplit(
		container.NewHBox(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(5, 0)), layout.NewSpacer()), container.NewCenter(win.AICircleContainer)),
		container.NewHBox(fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(5, 0)), layout.NewSpacer()), container.NewCenter(win.ProxyContainer)),
	)
	ai.SetOffset(0.3)

	// 创建状态管理容器，使用VBox垂直排列多个HBox
	statusContainer := container.NewVBox(
		widget.NewSeparator(),
		push,
		widget.NewSeparator(),
		ai,
		widget.NewSeparator(),
	)

	rightPanel := widget.NewForm(
		widget.NewFormItem("欢迎使用:", container.NewHBox(win.WelcomeLabel, authLabel, addressLabel, contactLabel)),
		widget.NewFormItem("漏洞介绍:", win.InfomationLabel),
		widget.NewFormItem("免责声明:", win.DisclaimerLabel),
		widget.NewFormItem("状态管理:", statusContainer),
		widget.NewFormItem("扫榻相迎:", container.NewBorder(nil, nil, nil, win.TimeLabel, win.FormLabel)),
	)

	bottom := container.NewBorder(widget.NewSeparator(), layout.NewSpacer(), leftPanel, nil, rightPanel)
	return bottom
}

// 扫描标语列表
var banners = []string{
	"估客昼眠知浪静，舟人夜语觉潮生。",
	"春江潮水连海平，海上明月共潮生。",
	"白日依山尽，黄河入海流。",
	"大漠孤烟直，长河落日圆。",
	"飞流直下三千尺，疑是银河落九天。",
	"孤舟蓑笠翁, 独钓寒江雪。",
	"忽如一夜春风来，千树万树梨花开。",
	"春眠不觉晓, 处处闻啼鸟。",
	"锄禾日当午，汗滴禾下土。",
	"君不见，黄河之水天上来，奔流到海不复回。",
	"日照香炉生紫烟，遥看瀑布挂前川。",
	"身无彩凤双飞翼，心有灵犀一点通。",
	"此时相望不相闻，愿逐月华流照君。",
	"疏影横斜水清浅，暗香浮动月黄昏。",
	"正是江南好风景，落花时节又逢君。",
	"我见众生皆草木，唯独见你是青山。",
	"无边落木萧萧下，不尽长江滚滚来。",
	"仰天大笑出门去，我辈岂是蓬蒿人。",
	"等闲识得东风面，万紫千红总是春。",
	"故人西辞黄鹤楼，烟花三月下扬州。",
}

func StartUpdateTimeAndFormLabel(win *Window) {
	go func() {
		for {
			time.Sleep(1 * time.Second)
			fyne.Do(func() {
				win.TimeLabel.SetText(fmt.Sprintf("北京时间：%s", time.Now().Format("2006-01-02 15:04:05")))
			})
		}
	}()

	go func() {
		index := 0
		for {
			time.Sleep(3 * time.Second)
			// 直接更新UI，Fyne会自动处理线程安全
			fyne.Do(func() {
				win.FormLabel.SetText(banners[index])
			})
			index = (index + 1) % len(banners)
		}
	}()
}
