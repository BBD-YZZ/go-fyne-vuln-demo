package tools

import (
	"bufio"
	"bytes"
	"fmt"
	"math/rand"
	"net"
	"net/url"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"unicode"
)

func GenerateStr(length int) string {
	if length <= 0 {
		return ""
	}

	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	var sb strings.Builder
	for i := 0; i < length; i++ {
		sb.WriteByte(charset[rand.Intn(len(charset))])
	}
	return sb.String()
}

func ExecCommand(cmd string) (string, error) {
	var out bytes.Buffer
	var errout bytes.Buffer

	var command *exec.Cmd
	if runtime.GOOS == "windows" {
		command = exec.Command("cmd", "/c", cmd)
	} else {
		command = exec.Command("sh", "-c", cmd)
	}
	command.Stdout = &out
	command.Stderr = &errout

	if err := command.Run(); err != nil {
		return "", fmt.Errorf("command %s failed: %w, %s", cmd, err, errout.String())
	}

	return out.String(), nil
}

func GetRootPath() (string, error) {
	path, err := os.Getwd()
	if err != nil {
		return "", err
	}
	return path, nil
}

func ReadFileForLines(filePath string) ([]string, error) {
	file, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
		return nil, nil
	}
	defer file.Close()
	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		fmt.Println(err)
		return nil, nil
	}
	return lines, nil
}

func WriteToFileForLines(filePath string, content []string) error {
	file, err := os.Create(filePath)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, line := range content {
		if _, err := writer.WriteString(line + "\n"); err != nil {
			return err
		}
	}
	return writer.Flush()
}

func IsIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil // && ip.IsGlobalUnicast() // 判断是否为全局单播地址
}

func ISIPv4(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.To4() != nil
}

func IsPrivateIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && ip.IsPrivate()
}

func IsPublicIP(s string) bool {
	ip := net.ParseIP(strings.TrimSpace(s))
	return ip != nil && !ip.IsPrivate() && !ip.IsLoopback()
}

// IsValidURL 检查字符串是否为有效的URL
func IsValidURL(s string) bool {
	_, err := url.ParseRequestURI(s) // 解析URL
	return err == nil
}

func IsPort(s string) bool {
	port, err := strconv.Atoi(strings.TrimSpace(s))
	return err == nil && port >= 0 && port <= 65535
}

func IsValidUrl(s string) bool {
	s = strings.TrimSpace(s)

	parsed, err := url.Parse(s)
	if err != nil {
		return false
	}

	if parsed.Scheme == "" || parsed.Host == "" {
		return false
	}

	validSchemes := []string{"http", "https", "ftp", "ftps", "ws", "wss"}
	isSchemeValid := false
	for _, validScheme := range validSchemes {
		if strings.ToLower(parsed.Scheme) == validScheme {
			isSchemeValid = true
			break
		}
	}

	if !isSchemeValid {
		return false
	}

	return true
}

func IsValidDomain(s string) bool {
	s = strings.TrimSpace(s)

	// 域名长度必须在1到253之间字符
	if len(s) < 1 || len(s) > 253 {
		return false
	}

	// 不能包含协议、端口、路径分隔符
	if strings.Contains(s, "://") ||
		strings.Contains(s, "/") ||
		strings.Contains(s, ":") ||
		strings.Contains(s, "?") ||
		strings.Contains(s, "#") ||
		strings.Contains(s, "@") {
		return false
	}

	// 不能以点开头或结尾
	if strings.HasPrefix(s, ".") || strings.HasSuffix(s, ".") {
		return false
	}

	// 不能包含非法字符
	if strings.ContainsAny(s, "()*+,-./:;?[]_{|}~") {
		return false
	}

	// 不能包含连续的点
	if strings.Contains(s, "..") {
		return false
	}

	// 域名必须包含至少一个点
	labels := strings.Split(s, ".")
	if len(labels) < 2 {
		return false
	}

	// 每个标签长度必须在1到63之间字符
	for i, label := range labels {
		if len(label) < 1 || len(label) > 63 {
			return false
		}
		// 每个标签只能包含字母、数字和短横线
		for j, c := range label {
			if j == 0 || j == len(label)-1 {
				if c != '-' {
					return false
				}
			}
			if !(unicode.IsLetter(c) || unicode.IsDigit(c) || c == '-') {
				return false
			}
		}
		// 第一个标签不能以短横线开头
		if i == 0 && label[0] == '-' {
			return false
		}
		// 最后一个标签不能以短横线结尾
		if i == len(labels)-1 && label[len(label)-1] == '-' {
			return false
		}
		// 最后一个标签不能全部为数字
		if i == len(labels)-1 {
			allDigits := true
			for _, c := range label {
				if !unicode.IsDigit(c) {
					allDigits = false
					break
				}
			}
			if !allDigits {
				return false
			}
		}
	}

	return true
}

func IsDomain(s string) bool {
	// 域名正则（RFC 1035标准）
	domainRegex := regexp.MustCompile(`^([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$`)
	return domainRegex.MatchString(s)
}

func IsDomainOrIP(s string) bool {
	return IsDomain(s) || IsIP(s)
}
