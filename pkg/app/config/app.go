package config

import (
	"context"

	"github.com/afbase/secrets-searcher/pkg/manip"

	"github.com/afbase/secrets-searcher/pkg/app/vars"
	"github.com/afbase/secrets-searcher/pkg/logg"
	va "github.com/go-ozzo/ozzo-validation/v4"
)

const (
	appCfgCtx = "appCfg"
)

type AppConfig struct {
	LogLevel          string       `param:"log-level" env:"true"`
	OutputDir         string       `param:"output-dir" env:"true"`
	NonZero           bool         `param:"non-zero" env:"true"`
	Interactive       bool         `param:"interactive" env:"true"`
	EnableSourcePhase bool         `param:"enable-source-phase" env:"true"`
	EnableSearchPhase bool         `param:"enable-search-phase" env:"true"`
	EnableReportPhase bool         `param:"enable-report-phase" env:"true"`
	EnableProfiling   bool         `param:"enable-profiling" env:"true"`
	RescanPrevious    bool         `param:"rescan-previous" env:"true"`
	DevConfig         DevConfig    `param:"dev"`
	SourceConfig      SourceConfig `param:"source"`
	SearchConfig      SearchConfig `param:"search"`
	ReporterConfig    ReportConfig `param:"report"`
}

func NewAppConfig() (appCfg *AppConfig) {
	appCfg = &AppConfig{
		Interactive:       true,
		EnableSourcePhase: true,
		EnableSearchPhase: true,
		EnableReportPhase: true,
		SourceConfig:      *NewSourceConfig(),
		SearchConfig:      *NewSearchConfig(),
	}
	appCfg.SetDefaults()
	return
}

func (appCfg *AppConfig) SetDefaults() {
	if appCfg.LogLevel == "" {
		appCfg.LogLevel = logg.Info.Value()
	}
	if appCfg.OutputDir == "" {
		appCfg.OutputDir = "./output"
	}
}

func (appCfg AppConfig) Validate() (err error) {
	// Create context object with app config in it,
	// so validation on nested structs can use it for context-aware validation
	ctx := context.Background()
	ctx = context.WithValue(ctx, appCfgCtx, &appCfg)

	// Validation error messages should use the "param" tag when referencing fields
	va.ErrorTag = vars.ConfigParamTag

	return va.ValidateStructWithContext(ctx, &appCfg,
		va.Field(&appCfg.LogLevel, va.Required, va.In(manip.DowncastSlice(logg.ValidLevelValues())...)),
		va.Field(&appCfg.OutputDir, va.Required),
		va.Field(&appCfg.SourceConfig),
		va.Field(&appCfg.SearchConfig),
		va.Field(&appCfg.ReporterConfig),
	)
}

func getAppCfgToContext(ctx context.Context) *AppConfig {
	return ctx.Value(appCfgCtx).(*AppConfig)
}
