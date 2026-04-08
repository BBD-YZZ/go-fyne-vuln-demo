package main

import (
	"encoding/base64"
	"image/color"
	"vuln-scan/images"
	"vuln-scan/window"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/theme"
)

// 自定义深色主题
type CustomDarkTheme struct {
}

func (c CustomDarkTheme) Color(name fyne.ThemeColorName, variant fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 深灰色背景
	case theme.ColorNameButton:
		return color.RGBA{R: 45, G: 45, B: 45, A: 255} // 按钮背景
	case theme.ColorNameDisabledButton:
		return color.RGBA{R: 60, G: 60, B: 60, A: 255} // 禁用按钮背景
	case theme.ColorNameHover:
		return color.RGBA{R: 55, G: 55, B: 55, A: 255} // 悬停背景
	case theme.ColorNameFocus:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 焦点颜色, 蓝色
	case theme.ColorNameInputBackground:
		return color.RGBA{R: 45, G: 45, B: 45, A: 255} // 输入框背景
	case theme.ColorNamePrimary:
		return color.RGBA{R: 0, G: 120, B: 255, A: 255} // 主色调
	case theme.ColorNameError:
		return color.RGBA{R: 255, G: 50, B: 50, A: 255} // 错误颜色
	case theme.ColorNameForeground:
		return color.RGBA{R: 220, G: 220, B: 220, A: 255} // 前景色（文本）
	case theme.ColorNameDisabled:
		return color.RGBA{R: 120, G: 120, B: 120, A: 255} // 禁用颜色
	case theme.ColorNameMenuBackground:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 菜单背景
	case theme.ColorNameHeaderBackground:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 头部背景
	case theme.ColorNameOverlayBackground:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 遮罩背景
	case fyne.ThemeColorName(theme.IconNameColorPalette):
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 图标颜色
	case theme.ColorNamePressed:
		return color.RGBA{R: 30, G: 30, B: 30, A: 255} // 按钮按下背景
	default:
		return theme.DefaultTheme().Color(name, variant)
	}
}

func (c CustomDarkTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (c CustomDarkTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (c CustomDarkTheme) Size(name fyne.ThemeSizeName) float32 {
	return theme.DefaultTheme().Size(name)
}

func main() {
	app := app.NewWithID("vuln-scan")

	// 设置自定义深色主题
	app.Settings().SetTheme(CustomDarkTheme{})

	// 设置应用图标（在窗口创建前）
	imageBytes, err := base64.StdEncoding.DecodeString(images.Icon_base64)
	if err == nil {
		app.SetIcon(fyne.NewStaticResource("icon", imageBytes))
	}

	window := window.NewWindow(app, "Vuln Scan", 700, 1000)

	// 设置窗口图标
	if err == nil {
		window.Window.SetIcon(fyne.NewStaticResource("icon", imageBytes))
	}

	window.Window.ShowAndRun()
}
