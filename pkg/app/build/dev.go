package build

import (
	"github.com/afbase/secrets-searcher/pkg/app/config"
	"github.com/afbase/secrets-searcher/pkg/dev"
)

func Dev(devCfg *config.DevConfig) *dev.Parameters {
	return &dev.Parameters{
		Filter: dev.Filter{
			Processor: devCfg.Filter.Processor,
			Repo:      devCfg.Filter.Repo,
			Commit:    devCfg.Filter.Commit,
			Path:      devCfg.Filter.Path,
			Line:      devCfg.Filter.Line,
		},
	}
}
