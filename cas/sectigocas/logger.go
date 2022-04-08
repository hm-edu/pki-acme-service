package sectigocas

import (
	"fmt"
	"go.uber.org/zap"
	"strings"
)

type ZapLogger struct {
	logger *zap.Logger
}

func (z *ZapLogger) Fatal(args ...interface{}) {
	z.logger.Sugar().Fatal(args...)
}

func (z *ZapLogger) Fatalln(args ...interface{}) {
	z.logger.Sugar().Fatal(args...)
}

func (z *ZapLogger) Fatalf(format string, args ...interface{}) {
	z.logger.Sugar().Fatalf(format, args...)
}

func (z *ZapLogger) Print(args ...interface{}) {
	msg := fmt.Sprint(args...)
	if strings.HasPrefix(msg, "[WARN]") {
		z.logger.Sugar().Warn(msg)
	} else {
		z.logger.Sugar().Info(msg)
	}
}
func (z *ZapLogger) Println(args ...interface{}) {
	msg := fmt.Sprint(args...)
	if strings.HasPrefix(msg, "[WARN]") {
		z.logger.Sugar().Warn(msg)
	} else {
		z.logger.Sugar().Info(msg)
	}
}
func (z *ZapLogger) Printf(format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if strings.HasPrefix(msg, "[WARN]") {
		z.logger.Sugar().Warn(msg)
	} else {
		z.logger.Sugar().Info(msg)
	}

}
