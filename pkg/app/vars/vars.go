package vars

// Build information (set via ldflags during build)
var (
	Version = "dev"
	Commit  = "none"
	Date    = "unknown"
)

const (

	// ID
	Name        = "secrets-searcher"
	Description = "Search for sensitive information stored in Pantheon git repositories."
	URL         = "https://github.com/afbase/secrets-searcher"

	// Config

	ConfigParamTag = "param"
	EnvParamTag    = "env"
	EnvVarPrefix   = "SECRETS_"
)
