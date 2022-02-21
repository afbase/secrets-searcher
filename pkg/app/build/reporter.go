package build

import (
	"path/filepath"

	"github.com/afbase/secrets-searcher/pkg/stats"

	"github.com/afbase/secrets-searcher/pkg/manip"

	"github.com/afbase/secrets-searcher/pkg/app/config"
	"github.com/afbase/secrets-searcher/pkg/database"
	"github.com/afbase/secrets-searcher/pkg/logg"
	reporterpkg "github.com/afbase/secrets-searcher/pkg/reporter"
	"github.com/afbase/secrets-searcher/pkg/source"
)

func Reporter(reporterCfg *config.ReportConfig, outputDir, url string, sourceProvider source.ProviderI, secretIDFilter *manip.SliceFilter, stats *stats.Stats, db *database.Database, log logg.Logg) *reporterpkg.Reporter {
	reportDir := reporterCfg.ReportDir
	if reportDir == "" {
		reportDir = filepath.Join(outputDir, "report")
	}
	reportArchivesDir := reporterCfg.ReportArchivesDir
	if reportArchivesDir == "" {
		reportArchivesDir = filepath.Join(outputDir, "report-archive")
	}

	return reporterpkg.New(
		reportDir,
		reportArchivesDir,
		url,
		reporterCfg.ShowDebugOutput,
		reporterCfg.EnablePreReports,
		reporterCfg.PreReportInterval,
		secretIDFilter,
		sourceProvider,
		stats,
		db,
		log,
	)
}
