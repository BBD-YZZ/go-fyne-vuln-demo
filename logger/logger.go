package logger

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/text/message"
)

// ANSI 颜色码
const (
	Reset  = "\033[0m"
	Red    = "\033[31m"
	Green  = "\033[32m"
	Yellow = "\033[33m"
	Blue   = "\033[34m"
	Purple = "\033[35m"
	Cyan   = "\033[36m"
	White  = "\033[37m"
)

const MaxLogLine = 1000 // 最大日志条目数

type LogLevel int

const (
	Info LogLevel = iota
	Warning
	Error
	Fatal
)

func (l LogLevel) String() string {
	switch l {
	case Info:
		return "INFO"
	case Warning:
		return "WARNING"
	case Error:
		return "ERROR"
	case Fatal:
		return "FATAL"
	default:
		return "UNKNOWN"
	}
}

type ColoredLogger interface {
	Info(msg string)
	Error(msg string)
	Warning(msg string)
	Fatal(msg string)
	Log(level LogLevel, msg string)

	Infof(format string, args ...interface{})
	Errorf(format string, args ...interface{})
	Warningf(format string, args ...interface{})
	Fatalf(format string, args ...interface{})
	Logf(level LogLevel, format string, args ...interface{})

	// SetConsoleOutput 设置是否输出到控制台
	SetConsoleOutput(enable bool)
	// SetFileOutput 设置是否输出到文件
	SetFileOutput(enable bool, filePath string)
	// SetMinLevel 设置最低日志级别
	SetMinLevel(level LogLevel)
	// SetEnable 设置是否启用日志记录
	SetEnable(enable bool)
	// SetLogRotation 设置日志轮转配置
	SetLogRotation(enable bool, maxFileSize int64, rotationInterval time.Duration)
	// SetAsync 设置是否启用异步写入
	SetAsync(enable bool)
	// SetMaxBackups 设置最大备份文件数
	SetMaxBackups(maxBackups int)
	// SetMaxLogLine 设置最大日志条目数
	SetMaxLogLine(maxLogLine int)
	// LoadConfig 从配置文件加载日志配置
	LoadConfig(configPath string) error
	// GetLogEntryByTimeRange 返回指定时间范围内的所有日志条目
	GetLogEntryByTimeRange(startTime, endTime time.Time) []LogEntry
	// GetLogEntryByTimeRangeAndLevel 返回指定时间范围内和日志级别的所有日志条目
	GetLogEntryByTimeRangeAndLevel(startTime, endTime time.Time, level LogLevel) []LogEntry
	// GetLastNumLogEntry 返回最近的num条日志条目
	GetLastNumLogEntry(num int) []LogEntry
	// GetLogEntryByLevel 返回指定日志级别的所有日志条目
	GetLogEntryByLevel(level LogLevel) []LogEntry

	// GetAllLogEntries 返回所有日志条目
	GetAllLogEntries() []LogEntry
	// Close 关闭日志记录器
	Close() error

	// GetLogEntryByIndex 返回指定索引的日志条目
	GetLogEntryByIndex(index int) (LogEntry, error)

	// GetLogEntryCount 返回日志条目总数
	GetLogEntryCount() int

	// ClearLogEntries 清空所有日志条目
	ClearLogEntries()

	// GetLastNumLogEntryByLevel 返回最近的num条指定日志级别的日志条目
	GetLastNumLogEntryByLevel(num int, level LogLevel) []LogEntry

	// GetLastNumLogEntryByLevelAndTimeRange 返回指定时间范围内和日志级别的最近的num条日志条目
	GetLastNumLogEntryByLevelAndTimeRange(num int, level LogLevel, startTime, endTime time.Time) []LogEntry

	// GetLogsFromFile 返回从文件中读取的所有日志条目
	GetLogsFromFile() ([]LogEntry, error)

	// GetLastNumLogFromFile 返回从文件中读取的最近的num条日志条目
	GetLastNumLogFromFile(num int) ([]LogEntry, error)
	// GetStatistics 获取日志统计信息
	GetStatistics() LogStatistics
}

// LogEntry 日志条目结构体
type LogEntry struct {
	TimeStamp time.Time // 日志时间戳
	Level     LogLevel  // 日志级别
	Message   string    // 日志消息
	FileName  string    // 日志文件名
	LineNum   int       // 日志行号
	Function  string    // 日志函数名
}

type LogConfig struct {
	ConsoleOutPut    bool          `json:"console_output"`
	FileOutPut       bool          `json:"file_output"`       // 是否输出到文件
	FilePath         string        `json:"file_path"`         // 日志文件路径
	MaxLogLine       int           `json:"max_log_line"`      // 最大日志条目数
	MinLevel         string        `json:"min_level"`         // 最小日志级别
	EnableAsync      bool          `json:"enable_async"`      // 是否启用异步写入
	EnableRotation   bool          `json:"enable_rotation"`   // 是否启用日志轮转
	MaxFileSize      int64         `json:"max_file_size"`     // 最大日志文件大小
	RotationInterval time.Duration `json:"rotation_interval"` // 日志轮转时间间隔
	MaxBackups       int           `json:"max_backups"`       // 最大备份文件数
}

// LogStatistics 日志统计信息结构体
type LogStatistics struct {
	WriteCount       int64 // 日志写入次数
	WriteFailure     int64 // 日志写入失败次数
	AsyncQueueMax    int   // 异步队列最大大小
	FileOpenCount    int64 // 文件打开次数
	FileWriteCount   int64 // 文件写入次数
	FileRotateCount  int64 // 文件轮转次数
	QueueCurrentSize int   // 当前队列大小
}

// threadSafeLogEntrys 线程安全的日志条目结构体
type threadSafeLogEntrys struct {
	logEntrys        []LogEntry    // 线程安全的日志条目数组
	mu               sync.RWMutex  // 读写互斥锁，用于保护日志条目数组的并发访问
	consoleOutPut    bool          // 是否输出到控制台
	fileOutPut       bool          // 是否输出到文件
	filePath         string        // 日志文件路径
	minLevel         LogLevel      // 最小日志级别
	maxLogLine       int           // 最大日志条目数
	maxFileSize      int64         // 最大日志文件大小
	enable           bool          // 是否启用日志记录
	enableRotation   bool          // 是否启用日志轮转
	lastRotation     time.Time     // 上次日志轮转时间
	rotationInterval time.Duration // 日志轮转时间间隔
	logChan          chan LogEntry // 日志通道, 用于异步接受日志
	enableAsync      bool          // 是否启用异步日志记录

	muFile     sync.Mutex // 文件操作专用锁
	file       *os.File   // 保持文件句柄，避免频繁打开关闭
	maxBackups int        // 最大备份文件数

	// 统计信息
	writeCount      int64 // 日志写入次数
	writeFailure    int64 // 日志写入失败次数
	asyncQueueMax   int   // 异步队列最大大小
	fileOpenCount   int64 // 文件打开次数
	fileWriteCount  int64 // 文件写入次数
	fileRotateCount int64 // 文件轮转次数
}

func NewColoredLogger() ColoredLogger {
	logger := &threadSafeLogEntrys{
		logEntrys:        make([]LogEntry, 0),       // 日志条目数组
		mu:               sync.RWMutex{},            // 读写互斥锁，用于保护日志条目数组的并发访问
		consoleOutPut:    true,                      // 默认输出到控制台
		fileOutPut:       false,                     // 默认不输出到文件
		filePath:         "",                        // 默认日志文件路径为空
		minLevel:         Info,                      // 默认最小日志级别为Info
		maxLogLine:       MaxLogLine,                // 默认最大日志条目数为1000
		maxFileSize:      10 * 1024 * 1024,          // 默认最大日志文件大小为10M
		enable:           true,                      // 默认启用日志记录
		enableRotation:   false,                     // 默认不启用日志轮转
		lastRotation:     time.Now(),                // 默认上次日志轮转时间为当前时间
		rotationInterval: 24 * time.Hour,            // 默认日志轮转时间间隔为24小时
		logChan:          make(chan LogEntry, 1000), // 日志通道, 用于异步接受日志，增加容量减少阻塞
		enableAsync:      false,                     // 默认不启用异步日志记录
		maxBackups:       5,                         // 默认最大备份文件数为5
		muFile:           sync.Mutex{},              // 文件操作专用锁
		file:             nil,                       // 默认文件句柄为空

		// 统计信息初始化
		writeCount:      0, // 日志写入次数
		writeFailure:    0, // 日志写入失败次数
		asyncQueueMax:   0, // 异步队列最大大小
		fileOpenCount:   0, // 文件打开次数
		fileWriteCount:  0, // 文件写入次数
		fileRotateCount: 0, // 文件轮转次数
	}
	// 启动日志处理 goroutine
	go logger.processLogs()
	return logger
}

func (l *threadSafeLogEntrys) getCallerInfo() (string, int, string) {
	// 跳过日志库内部的调用，找到真正的调用者
	skip := 3 // 初始跳过3层
	var file string
	var line int
	var function string

	for {
		pc, f, l, ok := runtime.Caller(skip)
		if !ok {
			return "???", 0, "???"
		}
		funcName := runtime.FuncForPC(pc).Name()

		// 检查是否是日志库内部的函数
		// 我们需要跳过所有LogManagement包中的函数
		if !strings.Contains(funcName, "logger") {
			file = f
			line = l
			function = funcName
			break
		}

		// 如果是日志库内部的函数，继续跳过
		skip++
	}

	// 只保留文件名
	for i := len(file) - 1; i >= 0; i-- {
		if file[i] == '/' || file[i] == '\\' {
			file = file[i+1:]
			break
		}
	}
	return file, line, function
}

// printToConsole 打印日志到控制台
func (l *threadSafeLogEntrys) printToConsole(logEntry LogEntry) {
	color := ""
	switch logEntry.Level {
	case Info:
		color = Green
	case Warning:
		color = Yellow
	case Error:
		color = Red
	case Fatal:
		color = Purple
	default:
		color = White
	}
	fmt.Printf("[%s]%s %s%s %s:%d %s %s\n", logEntry.TimeStamp.Format("2006-01-02 15:04:05"), color, logEntry.Level, Reset, logEntry.FileName, logEntry.LineNum, logEntry.Function, logEntry.Message)
}

func (l *threadSafeLogEntrys) shouldRotate() bool {
	// 检查日志是否需要轮转
	if !l.enableRotation || l.filePath == "" || l.rotationInterval <= 0 {
		return false
	}
	if l.maxFileSize <= 0 {
		return false
	}
	// 检查文件大小
	fileInfo, err := os.Stat(l.filePath)
	if err == nil && fileInfo.Size() >= l.maxFileSize {
		return true
	}

	// 检查时间间隔
	if time.Since(l.lastRotation) >= l.rotationInterval {
		return true
	}
	return false
}

// shouldRotateWithLock 检查是否需要轮转日志文件（带锁版本）
func (l *threadSafeLogEntrys) shouldRotateWithLock() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.shouldRotate()
}

// cleanupOldLogs 清理旧的日志备份文件
func (l *threadSafeLogEntrys) cleanupOldLogs() {
	if l.maxBackups <= 0 {
		l.maxBackups = 5 // 默认保留5个备份
	}

	dir := filepath.Dir(l.filePath)
	baseName := filepath.Base(l.filePath)

	// 查找所有备份文件
	pattern := filepath.Join(dir, fmt.Sprintf("%s.*.rotate*", baseName))
	files, err := filepath.Glob(pattern)
	if err != nil {
		l.handleError(err, "查找轮转日志文件失败")
		return
	}

	// 按修改时间排序（从旧到新）
	sort.Slice(files, func(i, j int) bool {
		info1, _ := os.Stat(files[i])
		info2, _ := os.Stat(files[j])
		if info1 == nil || info2 == nil {
			return false
		}
		return info1.ModTime().Before(info2.ModTime())
	})

	// 删除超出数量的旧文件
	deletedCount := 0
	if len(files) > l.maxBackups {
		for i := 0; i < len(files)-l.maxBackups; i++ {
			if err := os.Remove(files[i]); err != nil {
				l.handleError(err, fmt.Sprintf("删除旧日志文件失败 %s", files[i]))
			} else {
				deletedCount++
			}
		}
	}

	if deletedCount > 0 {
		fmt.Printf("成功清理 %d 个旧日志文件\n", deletedCount)
	}
}

// rotateLogFile 轮转日志文件（带锁版本）
func (l *threadSafeLogEntrys) rotateLogFile() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.filePath == "" {
		return fmt.Errorf("日志文件路径为空")
	}

	// 检查文件是否存在
	if _, err := os.Stat(l.filePath); os.IsNotExist(err) {
		l.lastRotation = time.Now()
		return nil
		// return fmt.Errorf("日志文件不存在: %s", l.filePath)
	}

	// 关闭当前文件句柄（如果已打开）
	if l.file != nil {
		l.file.Close()
		l.file = nil
	}

	// 生成唯一的轮转文件名
	timestamp := time.Now().Format("20060102150405")
	dir := filepath.Dir(l.filePath)
	baseName := filepath.Base(l.filePath)

	// 创建备份文件名
	backupName := fmt.Sprintf("%s.%s.rotate", baseName, timestamp)
	backupPath := filepath.Join(dir, backupName)

	// 检查文件名是否已存在，如果存在则添加后缀
	counter := 1
	for {
		if _, err := os.Stat(backupPath); os.IsNotExist(err) {
			break
		}
		backupName = fmt.Sprintf("%s.%s.rotate.%d", baseName, timestamp, counter)
		backupPath = filepath.Join(dir, backupName)
		counter++
	}

	// 移动当前日志文件到备份位置
	if err := os.Rename(l.filePath, backupPath); err != nil {
		return fmt.Errorf("移动日志文件失败: %v", err)
	}

	// 清理旧日志文件（保留最新的5个）
	l.cleanupOldLogs()

	// 更新轮转时间和统计信息
	l.lastRotation = time.Now()
	l.fileRotateCount++

	return nil
}

// getOrOpenFile 获取或打开文件句柄（带重试机制）
func (l *threadSafeLogEntrys) getOrOpenFile() (*os.File, error) {
	l.muFile.Lock()
	defer l.muFile.Unlock()

	if l.file == nil {
		// 确保目录存在
		dir := filepath.Dir(l.filePath)
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("创建日志目录失败: %v", err)
		}

		// 打开文件（带重试机制）
		var file *os.File
		var err error
		maxRetries := 3
		retryDelay := 100 * time.Millisecond

		for i := 0; i < maxRetries; i++ {
			file, err = os.OpenFile(l.filePath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
			if err == nil {
				break
			}

			if i < maxRetries-1 {
				time.Sleep(retryDelay)
				retryDelay *= 2 // 指数退避
			}
		}

		if err != nil {
			return nil, fmt.Errorf("打开日志文件失败 (重试%d次): %v", maxRetries, err)
		}

		l.file = file
		l.fileOpenCount++
	}

	return l.file, nil
}

// writeToFile 写入日志条目到文件（带锁版本）
func (l *threadSafeLogEntrys) writeToFile(logEntry LogEntry) {
	// 检查日志是否需要轮转
	if l.shouldRotateWithLock() {
		// 轮转日志文件
		err := l.rotateLogFile()
		if err != nil {
			l.handleError(err, "轮转日志文件失败")
		}
	}

	// 获取文件句柄并写入（getOrOpenFile已加锁）
	file, err := l.getOrOpenFile()
	if err != nil {
		l.handleError(err, "获取日志文件句柄失败")
		return
	}

	// 写入日志条目
	logLine := fmt.Sprintf("%s %s %s:%d %s %s\n",
		logEntry.TimeStamp.Format("2006-01-02 15:04:05"),
		logEntry.Level,
		logEntry.FileName,
		logEntry.LineNum,
		logEntry.Function,
		logEntry.Message)

	// 文件句柄已经在getOrOpenFile中获取了锁，直接写入
	l.fileWriteCount++
	_, err = file.WriteString(logLine)
	if err != nil {
		l.writeFailure++
		// 关闭文件句柄
		file.Close()
		l.file = nil
		l.handleError(err, "写入日志文件失败")
	}
}

// Log 记录日志（带锁版本）
func (l *threadSafeLogEntrys) Log(level LogLevel, msg string) {
	l.mu.Lock()

	// 检查日志级别和是否启用日志记录
	if level < l.minLevel || !l.enable {
		l.mu.Unlock()
		return
	}

	file, line, function := l.getCallerInfo()
	logEntry := LogEntry{
		TimeStamp: time.Now(),
		Level:     level,
		Message:   msg,
		FileName:  file,
		LineNum:   line,
		Function:  function,
	}
	l.logEntrys = append(l.logEntrys, logEntry)
	l.writeCount++ // 增加写入次数统计

	// 显示日志条目，防止内存溢出
	if len(l.logEntrys) > l.maxLogLine {
		l.logEntrys = l.logEntrys[len(l.logEntrys)-l.maxLogLine:]
	}

	// 检查是否启用异步日志记录
	enableAsync := l.enableAsync

	l.mu.Unlock()

	// 输出日志
	if enableAsync {
		// 异步写入
		select {
		case l.logChan <- logEntry:
			// 成功写入通道，更新异步队列最大大小
			queueSize := len(l.logChan)
			l.mu.Lock()
			if queueSize > l.asyncQueueMax {
				l.asyncQueueMax = queueSize
			}
			l.mu.Unlock()
		default:
			// 通道已满，采用同步写入并记录降级事件
			downgradeMsg := fmt.Sprintf("异步日志通道已满，降级为同步写入 (当前队列大小: %d)", len(l.logChan))
			fmt.Printf("[%s] %s\n", time.Now().Format("2006-01-02 15:04:05"), downgradeMsg)

			// 同步写入
			if l.consoleOutPut {
				l.printToConsole(logEntry)
			}
			// 写入文件
			if l.fileOutPut && l.filePath != "" {
				l.writeToFile(logEntry)
			}
		}
	} else {
		// 同步写入
		if l.consoleOutPut {
			l.printToConsole(logEntry)
		}
		// 写入文件
		if l.fileOutPut && l.filePath != "" {
			l.writeToFile(logEntry)
		}
	}
}

func (l *threadSafeLogEntrys) Logf(level LogLevel, format string, args ...interface{}) {
	if level < l.minLevel || !l.enable {
		return
	}

	message := message.NewPrinter(message.MatchLanguage("zh-CN")) // 创建一个新的消息打印机，匹配中文语言
	msg := message.Sprintf(format, args...)
	l.Log(level, msg)
}

func (l *threadSafeLogEntrys) Info(msg string) {
	l.Log(Info, msg)
}

func (l *threadSafeLogEntrys) Error(msg string) {
	l.Log(Error, msg)
}

func (l *threadSafeLogEntrys) Warning(msg string) {
	l.Log(Warning, msg)
}

func (l *threadSafeLogEntrys) Fatal(msg string) {
	l.Log(Fatal, msg)
}

func (l *threadSafeLogEntrys) Infof(format string, args ...interface{}) {
	l.Logf(Info, format, args...)
}

func (l *threadSafeLogEntrys) Errorf(format string, args ...interface{}) {
	l.Logf(Error, format, args...)
}

func (l *threadSafeLogEntrys) Warningf(format string, args ...interface{}) {
	l.Logf(Warning, format, args...)
}

func (l *threadSafeLogEntrys) Fatalf(format string, args ...interface{}) {
	l.Logf(Fatal, format, args...)
}

func (l *threadSafeLogEntrys) SetConsoleOutput(enable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.consoleOutPut = enable
}

func (l *threadSafeLogEntrys) SetFileOutput(enable bool, filePath string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fileOutPut = enable
	l.filePath = filePath
}

func (l *threadSafeLogEntrys) SetMinLevel(level LogLevel) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.minLevel = level
}

func (l *threadSafeLogEntrys) SetEnable(enable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enable = enable
}

func (l *threadSafeLogEntrys) SetLogRotation(enable bool, maxFileSize int64, rotationInterval time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enableRotation = enable

	// 设置合理的默认值
	if maxFileSize <= 0 {
		maxFileSize = 10 * 1024 * 1024 // 默认10MB
	}
	if rotationInterval <= 0 && enable {
		rotationInterval = 24 * time.Hour // 默认24小时
	}

	l.maxFileSize = maxFileSize
	l.rotationInterval = rotationInterval
}

func (l *threadSafeLogEntrys) SetAsync(enable bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.enableAsync = enable
}

func (l *threadSafeLogEntrys) SetMaxBackups(maxBackups int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxBackups = maxBackups
}

func (l *threadSafeLogEntrys) SetMaxLogLine(maxLogLine int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.maxLogLine = maxLogLine
}

// stringToLogLevel 将字符串转换为 LogLevel 枚举值
func stringToLogLevel(levelStr string) LogLevel {
	switch levelStr {
	case "Info", "INFO":
		return Info
	case "Error", "ERROR":
		return Error
	case "Warning", "WARNING":
		return Warning
	case "Fatal", "FATAL":
		return Fatal
	default:
		return Info
	}
}

// LoadConfig 从文件加载日志配置
func (l *threadSafeLogEntrys) LoadConfig(configPath string) error {
	configFile, err := os.Open(configPath)
	if err != nil {
		return fmt.Errorf("打开日志配置文件失败: %v", err)
	}
	defer configFile.Close()

	// 从文件加载配置
	var config LogConfig
	err = json.NewDecoder(configFile).Decode(&config)
	if err != nil {
		return fmt.Errorf("加载日志配置文件失败: %v", err)
	}

	// 验证配置值的有效性
	if config.MaxLogLine <= 0 {
		return fmt.Errorf("MaxLogLine必须大于0，当前值: %d", config.MaxLogLine)
	}

	if config.MaxFileSize <= 0 {
		return fmt.Errorf("MaxFileSize必须大于0，当前值: %d", config.MaxFileSize)
	}

	if config.RotationInterval <= 0 && config.EnableRotation {
		return fmt.Errorf("启用日志轮转时，RotationInterval必须大于0，当前值: %v", config.RotationInterval)
	}

	if config.MaxBackups < 0 {
		return fmt.Errorf("MaxBackups不能为负数，当前值: %d", config.MaxBackups)
	}

	if config.FileOutPut && config.FilePath == "" {
		return fmt.Errorf("启用文件输出时，FilePath不能为空")
	}

	// 验证日志级别
	level := stringToLogLevel(config.MinLevel)
	if level < Info || level > Fatal {
		return fmt.Errorf("无效的日志级别: %s", config.MinLevel)
	}

	l.mu.Lock()
	defer l.mu.Unlock()

	// 更新日志配置
	l.consoleOutPut = config.ConsoleOutPut
	l.fileOutPut = config.FileOutPut
	l.filePath = config.FilePath
	l.maxLogLine = config.MaxLogLine
	l.minLevel = level
	l.enableAsync = config.EnableAsync
	l.enableRotation = config.EnableRotation
	l.maxFileSize = config.MaxFileSize
	l.rotationInterval = config.RotationInterval
	l.maxBackups = config.MaxBackups

	return nil
}

// 处理日志通道中的日志
func (l *threadSafeLogEntrys) processLogs() {
	for logEntry := range l.logChan {
		l.mu.RLock()
		consoleOutPut := l.consoleOutPut
		fileOutPut := l.fileOutPut
		filePath := l.filePath
		minLevel := l.minLevel
		l.mu.RUnlock()

		if consoleOutPut && logEntry.Level >= minLevel {
			l.printToConsole(logEntry)
		}
		// 写入文件
		if fileOutPut && filePath != "" && logEntry.Level >= minLevel {
			l.writeToFile(logEntry)
		}
	}
	// 通道关闭后的清理工作
	fmt.Printf("日志处理通道已关闭，停止处理异步日志\n")
}

// Sync 刷新文件内容到磁盘
func (l *threadSafeLogEntrys) Sync() error {
	l.muFile.Lock()
	defer l.muFile.Unlock()

	if l.file != nil {
		return l.file.Sync()
	}
	return nil
}

// GetStatistics 获取日志统计信息
func (l *threadSafeLogEntrys) GetStatistics() LogStatistics {
	l.mu.RLock()
	defer l.mu.RUnlock()

	return LogStatistics{
		WriteCount:       l.writeCount,
		WriteFailure:     l.writeFailure,
		AsyncQueueMax:    l.asyncQueueMax,
		FileOpenCount:    l.fileOpenCount,
		FileWriteCount:   l.fileWriteCount,
		FileRotateCount:  l.fileRotateCount,
		QueueCurrentSize: len(l.logChan),
	}
}

// handleError 统一的错误处理方法
func (l *threadSafeLogEntrys) handleError(err error, message string) {
	if err == nil {
		return
	}

	// 构建错误日志条目
	file, line, function := l.getCallerInfo()
	errorEntry := LogEntry{
		TimeStamp: time.Now(),
		Level:     Error,
		Message:   fmt.Sprintf("%s: %v", message, err),
		FileName:  file,
		LineNum:   line,
		Function:  function,
	}

	// 记录到内部日志列表
	l.mu.Lock()
	l.logEntrys = append(l.logEntrys, errorEntry)
	if len(l.logEntrys) > l.maxLogLine {
		l.logEntrys = l.logEntrys[len(l.logEntrys)-l.maxLogLine:]
	}
	l.writeCount++
	l.writeFailure++
	l.mu.Unlock()

	// 输出到控制台
	if l.consoleOutPut {
		l.printToConsole(errorEntry)
	}

	// 如果启用文件输出，尝试写入文件
	if l.fileOutPut && l.filePath != "" {
		l.writeToFile(errorEntry)
	}
}

// 关闭方法，确保文件句柄被关闭和通道关闭
func (l *threadSafeLogEntrys) Close() error {
	// 关闭异步日志通道
	l.mu.Lock()
	if l.enableAsync && l.logChan != nil {
		close(l.logChan)
		l.enableAsync = false
	}
	l.mu.Unlock()

	// 关闭文件句柄
	l.muFile.Lock()
	defer l.muFile.Unlock()

	if l.file != nil {
		// 先刷新文件内容到磁盘
		if err := l.file.Sync(); err != nil {
			l.handleError(err, "刷新日志文件失败")
		}
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

// GetAllLogEntries 返回所有日志条目的副本
func (l *threadSafeLogEntrys) GetAllLogEntries() []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	logsCopy := make([]LogEntry, len(l.logEntrys))
	copy(logsCopy, l.logEntrys)
	return logsCopy
}

// GetLogEntryByIndex 返回指定索引的日志条目
func (l *threadSafeLogEntrys) GetLogEntryByIndex(index int) (LogEntry, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if index < 0 || index >= len(l.logEntrys) {
		return LogEntry{}, fmt.Errorf("索引超出范围")
	}
	return l.logEntrys[index], nil
}

// GetLogEntryCount 返回日志条目数量
func (l *threadSafeLogEntrys) GetLogEntryCount() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.logEntrys)
}

// ClearLogEntries 清空所有日志条目
func (l *threadSafeLogEntrys) ClearLogEntries() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.logEntrys = []LogEntry{}
}

// GetLogEntryByLevel 返回指定日志级别的所有日志条目
func (l *threadSafeLogEntrys) GetLogEntryByLevel(level LogLevel) []LogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	var logsCopy []LogEntry
	for _, logEntry := range l.logEntrys {
		if logEntry.Level == level {
			logsCopy = append(logsCopy, logEntry)
		}
	}
	return logsCopy
}

// GetLogEntryByTimeRange 返回指定时间范围内的所有日志条目
func (l *threadSafeLogEntrys) GetLogEntryByTimeRange(startTime, endTime time.Time) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var logsCopy []LogEntry
	for _, logEntry := range l.logEntrys {
		// 使用 After 和 Before 方法比较时间
		if !logEntry.TimeStamp.Before(startTime) && !logEntry.TimeStamp.After(endTime) {
			logsCopy = append(logsCopy, logEntry)
		}
	}
	return logsCopy
}

// GetLogEntryByTimeRangeAndLevel 返回指定时间范围内和日志级别的所有日志条目
func (l *threadSafeLogEntrys) GetLogEntryByTimeRangeAndLevel(startTime, endTime time.Time, level LogLevel) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	var logsCopy []LogEntry
	for _, logEntry := range l.logEntrys {
		// 使用 After 和 Before 方法比较时间
		if !logEntry.TimeStamp.Before(startTime) && !logEntry.TimeStamp.After(endTime) && logEntry.Level == level {
			logsCopy = append(logsCopy, logEntry)
		}
	}
	return logsCopy
}

// GetLastNumLogEntry 返回最近的num条日志条目
func (l *threadSafeLogEntrys) GetLastNumLogEntry(num int) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if num <= 0 {
		return []LogEntry{}
	}
	if num > len(l.logEntrys) {
		num = len(l.logEntrys)
	}

	var logsCopy []LogEntry
	for i := len(l.logEntrys) - 1; i >= 0 && num > 0; i-- {
		logsCopy = append(logsCopy, l.logEntrys[i])
		num--
	}
	return logsCopy
}

// GetLastNumLogEntryByLevel 返回最近的num条指定日志级别的日志条目
func (l *threadSafeLogEntrys) GetLastNumLogEntryByLevel(num int, level LogLevel) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if num <= 0 {
		return []LogEntry{}
	}
	if num > len(l.logEntrys) {
		num = len(l.logEntrys)
	}

	var logsCopy []LogEntry
	for i := len(l.logEntrys) - 1; i >= 0 && num > 0; i-- {
		if l.logEntrys[i].Level == level {
			logsCopy = append(logsCopy, l.logEntrys[i])
			num--
		}
	}
	return logsCopy
}

func (l *threadSafeLogEntrys) GetLastNumLogEntryByLevelAndTimeRange(num int, level LogLevel, startTime, endTime time.Time) []LogEntry {
	l.mu.RLock()
	defer l.mu.RUnlock()

	if num <= 0 {
		return []LogEntry{}
	}
	if num > len(l.logEntrys) {
		num = len(l.logEntrys)
	}

	var logsCopy []LogEntry
	for i := len(l.logEntrys) - 1; i >= 0 && num > 0; i-- {
		if l.logEntrys[i].Level == level && !l.logEntrys[i].TimeStamp.Before(startTime) && !l.logEntrys[i].TimeStamp.After(endTime) {
			logsCopy = append(logsCopy, l.logEntrys[i])
			num--
		}
	}
	return logsCopy
}

func (l *threadSafeLogEntrys) GetLogsFromFile() ([]LogEntry, error) {
	l.muFile.Lock()
	defer l.muFile.Unlock()

	if !l.fileOutPut {
		return nil, fmt.Errorf("文件输出未启用")
	}

	if l.filePath == "" {
		return nil, fmt.Errorf("文件路径未初始化")
	}

	// 检查文件是否存在
	if _, err := os.Stat(l.filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("文件不存在: %w", err)
	}

	// 单独以读模式打开文件
	file, err := os.Open(l.filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 使用bufio.Scanner进行流式读取，避免一次性加载整个文件
	var logs []LogEntry
	scanner := bufio.NewScanner(file)

	// 设置更大的缓冲区，提高读取性能
	buffer := make([]byte, 1024*1024)    // 1MB缓冲区
	scanner.Buffer(buffer, 10*1024*1024) // 最大行长度10MB

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		logEntry, err := parseLogLine(line)
		if err != nil {
			// 忽略格式不正确的日志行
			continue
		}
		logs = append(logs, logEntry)
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("扫描文件失败: %w", err)
	}

	return logs, nil
}

func parseLogLine(line string) (LogEntry, error) {
	// 日志格式为 2006-01-02 15:04:05 ERROR main.go:16 main.main 测试错误级别的日志
	line = strings.TrimSpace(line)
	if line == "" {
		return LogEntry{}, fmt.Errorf("日志行为空")
	}

	// 先尝试标准格式解析
	parts := strings.SplitN(line, " ", 6)
	if len(parts) < 6 {
		// 尝试更宽松的解析
		parts = strings.Split(line, " ")
		if len(parts) < 6 {
			return LogEntry{}, fmt.Errorf("日志行格式错误: %s", line)
		}
	}

	// 解析时间
	timestamp, err := time.Parse("2006-01-02 15:04:05", fmt.Sprintf("%s %s", parts[0], parts[1]))
	if err != nil {
		// 尝试其他时间格式
		if len(parts) >= 2 {
			timestamp, err = time.Parse("2006/01/02 15:04:05", fmt.Sprintf("%s %s", parts[0], parts[1]))
			if err != nil {
				timestamp, err = time.Parse("02/01/2006 15:04:05", fmt.Sprintf("%s %s", parts[0], parts[1]))
				if err != nil {
					return LogEntry{}, fmt.Errorf("解析时间失败: %w", err)
				}
			}
		} else {
			return LogEntry{}, fmt.Errorf("解析时间失败: %w", err)
		}
	}

	// 解析日志级别
	levelStr := parts[2]
	level := stringToLogLevel(levelStr)
	if level < Info || level > Fatal {
		// 尝试忽略大小写
		level = stringToLogLevel(strings.ToUpper(levelStr))
		if level < Info || level > Fatal {
			return LogEntry{}, fmt.Errorf("未知日志级别: %s", levelStr)
		}
	}

	// 解析文件和行号
	fileLineStr := parts[3]
	fileLineParts := strings.Split(fileLineStr, ":")
	if len(fileLineParts) < 2 {
		return LogEntry{}, fmt.Errorf("解析文件和行号失败: %s", fileLineStr)
	}

	fileName := fileLineParts[0]
	lineNum := 0
	if len(fileLineParts) > 1 {
		lineNum, err = strconv.Atoi(fileLineParts[1])
		if err != nil {
			lineNum = 0 // 行号解析失败，使用默认值
		}
	}

	// 解析函数名
	funcName := ""
	if len(parts) >= 5 {
		funcName = parts[4]
	}

	// 解析消息
	message := ""
	if len(parts) >= 6 {
		message = strings.Join(parts[5:], " ")
	}

	return LogEntry{
		TimeStamp: timestamp,
		Level:     level,
		FileName:  fileName,
		LineNum:   lineNum,
		Function:  funcName,
		Message:   message,
	}, nil
}

func (l *threadSafeLogEntrys) GetLastNumLogFromFile(num int) ([]LogEntry, error) {
	if num <= 0 {
		return nil, fmt.Errorf("num必须大于0")
	}

	l.muFile.Lock()
	defer l.muFile.Unlock()

	if !l.fileOutPut {
		return nil, fmt.Errorf("文件输出未启用")
	}

	if l.filePath == "" {
		return nil, fmt.Errorf("文件路径未初始化")
	}

	// 检查文件是否存在
	if _, err := os.Stat(l.filePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("文件不存在: %w", err)
	}

	// 单独以读模式打开文件
	file, err := os.Open(l.filePath)
	if err != nil {
		return nil, fmt.Errorf("打开文件失败: %w", err)
	}
	defer file.Close()

	// 获取文件大小
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("获取文件信息失败: %w", err)
	}
	fileSize := fileInfo.Size()

	// 从文件末尾开始读取，避免读取整个文件
	// 假设每行平均长度为100字节，读取足够的字节数
	readSize := int64(num * 200) // 每行预留200字节
	if readSize > fileSize {
		readSize = fileSize
	}

	// 移动到文件末尾前readSize位置
	if _, err = file.Seek(-readSize, io.SeekEnd); err != nil {
		// 如果文件太小，从头开始读取
		if _, err = file.Seek(0, io.SeekStart); err != nil {
			return nil, fmt.Errorf("定位文件指针失败: %w", err)
		}
	}

	// 读取内容
	content, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("读取文件失败: %w", err)
	}

	// 解析日志行
	var logs []LogEntry
	lines := strings.Split(string(content), "\n")

	// 跳过可能不完整的第一行
	startIdx := 0
	if len(lines) > 0 && !strings.HasPrefix(lines[0], "2") { // 日志时间以数字开头
		startIdx = 1
	}

	for i := startIdx; i < len(lines); i++ {
		line := strings.TrimSpace(lines[i])
		if line == "" {
			continue
		}
		logEntry, err := parseLogLine(line)
		if err != nil {
			continue
		}
		logs = append(logs, logEntry)
	}

	// 返回最后num条日志
	if len(logs) > num {
		logs = logs[len(logs)-num:]
	}

	return logs, nil
}
