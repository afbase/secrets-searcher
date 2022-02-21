package config

import (
	"time"

	"github.com/afbase/secrets-searcher/pkg/errors"
	va "github.com/go-ozzo/ozzo-validation/v4"
)

type ReportConfig struct {
	ReportDir         string        `param:"report-dir" env:"true"`
	ReportArchivesDir string        `param:"report-archives-dir" env:"true"`
	ShowDebugOutput   bool          `param:"show-debug-output" env:"true"`
	EnablePreReports  bool          `param:"enable-pre-reports" env:"true"`
	PreReportInterval time.Duration `param:"pre-report-interval" env:"true"`
}

func (reportCfg ReportConfig) Validate() (err error) {
	return va.ValidateStruct(&reportCfg,
		va.Field(&reportCfg.PreReportInterval, va.When(reportCfg.EnablePreReports, va.By(checkPreReportInterval))),
	)
}

func checkPreReportInterval(value interface{}) error {
	interval, _ := value.(time.Duration)
	if interval.Seconds() < 1 {
		return errors.New("must be at least 1 second")
	}
	return nil
}
