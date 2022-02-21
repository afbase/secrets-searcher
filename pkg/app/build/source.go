package build

import (
	"context"

	"github.com/afbasse/secrets-searcher/pkg/app/config"
	"github.com/afbasse/secrets-searcher/pkg/database"
	gitpkg "github.com/afbasse/secrets-searcher/pkg/git"
	interactpkg "github.com/afbasse/secrets-searcher/pkg/interact"
	"github.com/afbasse/secrets-searcher/pkg/logg"
	"github.com/afbasse/secrets-searcher/pkg/manip"
	"github.com/afbasse/secrets-searcher/pkg/source"
	providerpkg "github.com/afbasse/secrets-searcher/pkg/source/providers"
	"github.com/google/go-github/v29/github"
	"golang.org/x/oauth2"
)

func Source(sourceCfg *config.SourceConfig, sourceDir string, repoFilter *manip.SliceFilter, git *gitpkg.Git, sourceProvider source.ProviderI, interact *interactpkg.Interact, db *database.Database, sourceLog logg.Logg) (result *source.Source) {
	return source.New(
		sourceDir,
		sourceCfg.SkipFetch,
		sourceCfg.WorkerCount,
		repoFilter,
		git,
		sourceProvider,
		interact,
		db,
		sourceLog,
	)
}

func buildSourceProvider(sourceCfg *config.SourceConfig, git *gitpkg.Git, sourceLog logg.Logg) (result source.ProviderI) {
	providerLog := sourceLog.AddPrefixPath("provider")
	switch sourceCfg.Provider {

	// Github source provider
	case source.Local.Value():
		result = buildLocalProvider(sourceCfg, git, providerLog)
	case source.Github.Value():
		githubClient := buildGithubClient(sourceCfg)
		result = buildGithubProvider(sourceCfg, githubClient, providerLog)
	}

	return
}

func buildLocalProvider(sourceCfg *config.SourceConfig, git *gitpkg.Git, log logg.Logg) *providerpkg.LocalProvider {

	// Metadata provider
	var metadataProvider source.ProviderI
	switch sourceCfg.MetadataProvider {
	case source.Github.Value():
		metadataProvider = buildGithubProvider(sourceCfg, nil, log)
	}

	providerLog := log.AddPrefixPath("local-provider")
	return providerpkg.NewLocalProvider(sourceCfg.Provider, sourceCfg.LocalDir, git, metadataProvider, providerLog)
}

func buildGithubProvider(sourceCfg *config.SourceConfig, gitHubClient *github.Client, log logg.Logg) *providerpkg.GithubProvider {
	providerLog := log.AddPrefixPath("github-provider")
	return providerpkg.NewGithubProvider(sourceCfg.Provider, sourceCfg.Organization, gitHubClient, sourceCfg.SkipForks, providerLog)
}

func buildGithubClient(sourceCfg *config.SourceConfig) *github.Client {
	ctx := context.Background()
	tc := oauth2.NewClient(ctx, oauth2.StaticTokenSource(&oauth2.Token{AccessToken: sourceCfg.APIToken}))
	return github.NewClient(tc)
}
