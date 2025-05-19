package log

import (
	"fmt"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	log  *zerolog.Logger
	once sync.Once
	file *os.File
)

// 日志级别常量
const (
	LevelDebug = "DEBUG"
	LevelInfo  = "INFO"
	LevelWarn  = "WARN"
	LevelError = "ERROR"
	LevelFatal = "FATAL"
)

// ParseLogLevel 解析日志级别
func ParseLogLevel(level string) zerolog.Level {
	switch level {
	case LevelDebug, "debug":
		return zerolog.DebugLevel
	case LevelInfo, "info":
		return zerolog.InfoLevel
	case LevelWarn, "warn":
		return zerolog.WarnLevel
	case LevelError, "error":
		return zerolog.ErrorLevel
	case LevelFatal, "fatal":
		return zerolog.FatalLevel
	default:
		return zerolog.InfoLevel
	}
}

// LogConfig 日志配置
type LogConfig struct {
	SourceType    string // 日志来源
	LogFile       string // 日志文件
	LogDir        string // 日志目录
	OutputFile    bool   // 是否同时输出到文件
	Encrypted     bool   // 是否加密
	PartnerCode   string // 合作伙伴代码
	BatchId       int    // 批次ID
	OutputConsole bool   // 是否同时输出到控制台
	MinLevel      string // 最小日志级别
}

// EdgeXLogHook 日志内容字段配置
// 建议通过NewEdgeXLog获取对象，可自动生成uuid
type EdgeXLogHook struct {
	lc      *zerolog.Logger
	seq     string //uuid,去掉"-"
	TraceId string //全链路traceId
	//SourceType string // 日志来源
	LogFile   string // 日志文件
	LogDir    string // 日志目录
	Encrypted bool   // 是否加密
	//LogLevel string	//日志级别
	FactoryId   int64  //工厂id
	PsId        int64  //烧录站id
	PartnerCode string // 合作伙伴代码
	BatchId     int64  // 批次ID
	//OutputConsole bool   // 是否同时输出到控制台
	Ext     EdgeXExtensionLog //拓展字段 要求为json定义为string
	Payload string            //指令数据
	//MinLevel      string // 最小日志级别
}

type EdgeXExtensionLog struct {
}

// NewLogger 创建新的日志实例
func InitLogger(config LogConfig) {
	// 设置时间格式
	zerolog.TimeFieldFormat = time.RFC3339Nano
	zerolog.TimestampFieldName = "timestamp"
	zerolog.LevelFieldName = "logLevel"
	zerolog.MessageFieldName = "payload"
	zerolog.CallerMarshalFunc = func(pc uintptr, file string, line int) string {
		return filepath.Base(file) + ":" + strconv.Itoa(line)
	}
	// 设置最小日志级别
	//zerolog.SetGlobalLevel(ParseLogLevel(config.MinLevel))

	var writers []io.Writer

	if config.OutputFile {
		// 如果指定了日志文件和目录
		if config.LogFile == "" {
			config.LogFile = "pcsc-device-hsm.log"
		}
		if config.LogDir == "" {
			config.LogDir = "./log/"
		}

		if err := os.MkdirAll(config.LogDir, 0755); err != nil {
			fmt.Printf("创建日志目录失败: %v\n", err)
		} else {
			logPath := filepath.Join(config.LogDir, config.LogFile)
			file, err = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
			if err != nil {
				fmt.Printf("打开日志文件失败: %v\n", err)
			} else {
				writers = append(writers, file)
			}
		}
	}

	// 如果需要输出到控制台
	if config.OutputConsole {
		writers = append(writers, os.Stdout)
	}

	// 如果没有任何输出，默认输出到控制台
	if len(writers) == 0 {
		writers = append(writers, os.Stdout)
	}

	// 创建多输出writer
	multiWriter := io.MultiWriter(writers...)

	// 创建logger
	once.Do(func() {
		lc := zerolog.New(multiWriter).
			Level(ParseLogLevel(config.MinLevel)).
			With().
			CallerWithSkipFrameCount(zerolog.CallerSkipFrameCount+1).
			//Caller().
			Timestamp().
			Str("sourceType", config.SourceType).
			Logger()
		log = &lc

	})
}

func GetLogger() *zerolog.Logger {
	return log
}

//func GetLoggerWithTrace(traceId string) zerolog.Logger {
//	return log.With().Str("traceId", traceId).Logger()
//}

func NewEdgeXLog(lc *zerolog.Logger) EdgeXLogHook {
	return EdgeXLogHook{
		lc:  lc,
		seq: strings.ReplaceAll(uuid.New().String(), "-", ""),
	}
}
func (h EdgeXLogHook) SetLogger(lc *zerolog.Logger) EdgeXLogHook {
	h.lc = lc
	return h
}

func (h EdgeXLogHook) Run(e *zerolog.Event, level zerolog.Level, msg string) {
	//if h.seq!="" {
	//	e.Str("seq",h.seq)
	//}
	if h.TraceId != "" {
		e.Str("traceId", h.TraceId)
	}
	//if h.SourceType!="" {
	//	e.Str("sourceType",h.SourceType)
	//}
	if h.LogFile != "" {
		e.Str("logFile", h.LogFile)
	}
	if h.LogDir != "" {
		e.Str("logDir", h.LogDir)
	}

	e.Bool("encrypted", h.Encrypted)
	//if h.LogLevel!="" {
	//	e.Str("logLevel",h.LogLevel)
	//}
	if h.FactoryId > -1 {
		e.Int64("factoryId", h.FactoryId)
	}
	if h.PsId > -1 {
		e.Int64("psId", h.PsId)
	}
	if h.PartnerCode != "" {
		e.Str("partnerCode", h.PartnerCode)
	}
	if h.BatchId > -1 {
		e.Int64("batchId", h.BatchId)
	}
	if h.Ext != (EdgeXExtensionLog{}) {
		e.Interface("ext", h.BatchId)
	}
	if h.Payload != "" {
		e.Str("payload", h.Payload)
	}
	//e.Str("sourceType", h.SourceType).
	//	Str("encrypted", "production"). // 固定环境字段
	//	Int64("timestamp_ms", time.Now().UnixMilli()) // 自定义时间戳格式
}

// Close 关闭日志文件
func Close() {
	if file != nil {
		if err := file.Close(); err != nil {
			fmt.Println("close file meet err:", err)
			return
		}
	}
}

// addCaller 添加调用者信息
//func addCaller(skip int) string {
//	_, file, line, ok := runtime.Caller(skip + 1)
//	if !ok {
//		return ""
//	}
//	//return fmt.Sprintf("%s:%d", filepath.Base(file), line)
//	return filepath.Base(file) + ":" + strconv.Itoa(line)
//}

// Fatalf 使用格式化字符串输出致命错误日志
/*func (l *Logger) Fatalf(traceId string, format string, args ...interface{}) {
	l.log(zerolog.FatalLevel, traceId, fmt.Sprintf(format, args...), nil)
	os.Exit(1)
}
*/

// Debug 输出调试级别日志
func (h EdgeXLogHook) Debug(msg string) {
	lc := h.lc.Hook(h).With().Logger()
	lc.Debug().
		//Str("caller", addCaller(2)).
		Msg(msg)
}

// Info 输出信息级别日志
func (h EdgeXLogHook) Info(msg string) {
	lc := h.lc.Hook(h).With().Logger()
	lc.Info().
		//Str("caller", addCaller(2)).
		Msg(msg)
}

// Warn 输出警告级别日志
func (h EdgeXLogHook) Warn(msg string) {
	lc := h.lc.Hook(h).With().Logger()
	lc.Warn().
		//Str("caller", addCaller(2)).
		Msg(msg)
}

// Error 输出错误级别日志
func (h EdgeXLogHook) Error(msg string) {
	lc := h.lc.Hook(h).With().Logger()
	lc.Error().
		//Str("caller", addCaller(2)).
		Msg(msg)
}

// Debugf 使用格式化字符串输出调试日志
func (h EdgeXLogHook) Debugf(format string, args ...interface{}) {
	lc := h.lc.With().Logger()
	lc.Debug().
		//Str("caller", addCaller(2)).
		Msgf(format, args)
}

// Infof 使用格式化字符串输出信息日志
func (h EdgeXLogHook) Infof(format string, args ...interface{}) {
	lc := h.lc.With().Logger()
	lc.Info().
		//Str("caller", addCaller(2)).
		Msgf(format, args)
}

// Warnf 使用格式化字符串输出警告日志
func (h EdgeXLogHook) Warnf(format string, args ...interface{}) {
	lc := h.lc.With().Logger()
	lc.Warn().
		//Str("caller", addCaller(2)).
		Msgf(format, args)
}

// Errorf 使用格式化字符串输出错误日志
func (h EdgeXLogHook) Errorf(format string, args ...interface{}) {
	lc := h.lc.With().Logger()
	lc.Error().
		//Str("caller", addCaller(2)).
		Msgf(format, args)
}

// Fatalf 使用格式化字符串输出致命错误日志
/*func (h *Logger) Fatalf(l zerolog.Logger, format string, args ...interface{}) {
	lc := l.Hook(h).With().Logger()
	lc.Fatal().Msgf(format,args)
	os.Exit(1)
}
*/
