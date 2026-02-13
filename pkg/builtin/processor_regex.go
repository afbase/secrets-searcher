package builtin

import (
	"github.com/afbase/secrets-searcher/pkg/app/config"
	"github.com/afbase/secrets-searcher/pkg/search"
)

// Regex processor definitions
func regexProcessorDefinitions() (result []*config.ProcessorConfig) {
	return []*config.ProcessorConfig{

		// Slack token regex
		{
			Name:      SlackTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(xox[p|b|o|a]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32})`,
			},
		},

		// Facebook OAuth regex
		{
			Name:      FacebookOAuthRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[f|F][a|A][c|C][e|E][b|B][o|O][o|O][k|K].*['|"][0-9a-f]{32}['|"]`,
			},
		},

		// Google OAuth regex
		{
			Name:      GoogleOAuthRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[t|T][w|W][i|I][t|T][t|T][e|E][r|R].*['|"][0-9a-zA-Z]{35,44}['|"]`,
			},
		},

		// Twitter regex
		{
			Name:      TwitterRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `("client_secret":"[a-zA-Z0-9-_]{24}")`,
			},
		},

		// Heroku API Key regex
		{
			Name:      HerokuAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[h|H][e|E][r|R][o|O][k|K][u|U].*[0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12}`,
			},
		},

		// Slack Webhook regex
		{
			Name:      SlackWebhookRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `https://hooks.slack.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8}/[a-zA-Z0-9_]{24}`,
			},
		},

		// GCP Service Account regex
		{
			Name:      GCPServiceAccountRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?s){\s*"type": ?"service_account",.*"private_key_id": ?"([^"]+)"`,
			},
		},

		// Twilio API Key regex
		{
			Name:      TwilioAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `SK[a-z0-9]{32}`,
			},
		},

		// URL Password regex
		{
			Name:      URLPasswordRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[a-z](?:[a-z]|\d|\+|-|\.)*://([a-zA-z0-9\-_]{4,20}:[a-zA-z0-9\-_]{4,20})@[a-zA-z0-9:.\-_/]*`,
			},
		},

		// Generic Secret regex
		{
			Name:      GenericSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[s|S][e|E][c|C][r|R][e|E][t|T].*['|"][0-9a-zA-Z]{32,45}['|"]`,
			},
		},

		// AWS Access Key ID regex
		{
			Name:      AWSAccessKeyIDRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `((?:ASIA|AKIA|AROA|AIDA)[A-Z0-9]{16})`,
			},
		},

		// AWS Secret Access Key regex
		{
			Name:      AWSSecretKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)aws(.{0,20})?(?-i)['\"][0-9a-zA-Z\/+]{40}['\"]`,
			},
		},

		// AWS MWS Auth Token regex
		{
			Name:      AWSMWSAuthTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			},
		},

		// GitHub Token regex
		{
			Name:      GitHubTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)github[_\s]*(?:token|key|secret|pat)[\s]*[=:>]*[\s]*['\"]?([a-zA-Z0-9_]{35,})['\"]?`,
			},
		},

		// GitHub OAuth Token regex
		{
			Name:      GitHubOAuthRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[g|G][i|I][t|T][h|H][u|U][b|B].*['\"][0-9a-zA-Z]{35,40}['\"]`,
			},
		},

		// LinkedIn Client ID regex
		{
			Name:      LinkedInClientIDRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)linkedin(.{0,20})?(?-i)['\"][0-9a-z]{12}['\"]`,
			},
		},

		// LinkedIn Secret Key regex
		{
			Name:      LinkedInSecretKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)linkedin(.{0,20})?['\"][0-9a-z]{16}['\"]`,
			},
		},

		// Stripe API Key regex
		{
			Name:      StripeAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:sk|pk)_(?:test|live)_[0-9a-zA-Z]{24,}`,
			},
		},

		// Square Access Token regex
		{
			Name:      SquareAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `sq0atp-[0-9A-Za-z\-_]{22}`,
			},
		},

		// Square OAuth Secret regex
		{
			Name:      SquareOAuthSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `sq0csp-[0-9A-Za-z\-_]{43}`,
			},
		},

		// PayPal Braintree Access Token regex
		{
			Name:      PayPalBraintreeAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
			},
		},

		// SendGrid API Key regex
		{
			Name:      SendGridAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}`,
			},
		},

		// MailGun API Key regex
		{
			Name:      MailGunAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `key-[0-9a-zA-Z]{32}`,
			},
		},

		// MailChimp API Key regex
		{
			Name:      MailChimpAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[0-9a-f]{32}-us[0-9]{1,2}`,
			},
		},

		// Digital Ocean Personal Access Token regex
		{
			Name:      DigitalOceanPATRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(dop_v1_[a-f0-9]{64})\b`,
			},
		},

		// Digital Ocean OAuth Token regex
		{
			Name:      DigitalOceanOAuthRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(doo_v1_[a-f0-9]{64})\b`,
			},
		},

		// Digital Ocean Refresh Token regex
		{
			Name:      DigitalOceanRefreshTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(dor_v1_[a-f0-9]{64})\b`,
			},
		},

		// NuGet API Key regex
		{
			Name:      NuGetAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `oy2[a-z0-9]{43}`,
			},
		},

		//
		// ===== NEW DETECTORS =====
		//

		// ========================================
		// AI/ML Providers
		// ========================================

		// OpenAI API Key
		{
			Name:      OpenAIAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk-[a-zA-Z0-9_-]+T3BlbkFJ[a-zA-Z0-9_-]+)\b`,
			},
		},

		// Anthropic API Key
		{
			Name:      AnthropicAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk-ant-(?:admin01|api03)-[\w\-]{93}AA)\b`,
			},
		},

		// Groq API Key
		{
			Name:      GroqAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(gsk_[a-zA-Z0-9]{52})\b`,
			},
		},

		// DeepSeek API Key
		{
			Name:      DeepSeekAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)deepseek.{0,40}?\b(sk-[a-z0-9]{32})\b`,
			},
		},

		// xAI API Key
		{
			Name:      XAIAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(xai-[0-9a-zA-Z_]{80})\b`,
			},
		},

		// HuggingFace Token
		{
			Name:      HuggingFaceTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:hf_|api_org_)[a-zA-Z0-9]{34})\b`,
			},
		},

		// Replicate API Token
		{
			Name:      ReplicateAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(r8_[0-9A-Za-z_-]{37})\b`,
			},
		},

		// ElevenLabs API Key
		{
			Name:      ElevenLabsAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk_[a-f0-9]{48})\b`,
			},
		},

		// ========================================
		// Cloud & Infrastructure
		// ========================================

		// Google Cloud API Key
		{
			Name:      GoogleCloudAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `AIza[0-9A-Za-z\-_]{35}`,
			},
		},

		// Google OAuth Access Token
		{
			Name:      GoogleOAuthAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `ya29\.[0-9A-Za-z\-_]+`,
			},
		},

		// Google OAuth Key
		{
			Name:      GoogleOAuthKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com`,
			},
		},

		// Cloudflare API Token
		{
			Name:      CloudflareAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)cloudflare.{0,40}?\b([A-Za-z0-9_-]{40})\b`,
			},
		},

		// Cloudflare Global API Key
		{
			Name:      CloudflareGlobalAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)cloudflare.{0,40}?\b([A-Za-z0-9_-]{37})\b`,
			},
		},

		// Azure Storage Key
		{
			Name:      AzureStorageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:Access|Account|Storage)[_.\-]?Key.{0,25}?([a-zA-Z0-9+/\-]{86,88}={0,2})`,
			},
		},

		// Azure Entra Secret
		{
			Name:      AzureEntraSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:azure|entra|aad).{0,40}?(['"][a-zA-Z0-9~._-]{34}['"])`,
			},
		},

		// Supabase Token
		{
			Name:      SupabaseTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sbp_[a-z0-9]{40})\b`,
			},
		},

		// MongoDB Connection String
		{
			Name:      MongoDBConnectionStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(mongodb(?:\+srv)?://\S{3,50}:\S{3,88}@[-.%\w]+(?::\d{1,5})?)`,
			},
		},

		// PostgreSQL Connection String
		{
			Name:      PostgreSQLConnectionStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(postgres(?:ql)?://\S+:\S+@\S+)`,
			},
		},

		// Redis Connection String
		{
			Name:      RedisConnectionStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bredi[s]{1,2}://[\S]{3,50}:([\S]{3,50})@[-.%\w/:]+\b`,
			},
		},

		// Azure DevOps PAT
		{
			Name:      AzureDevOpsPATRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)azure.{0,40}?\b([0-9a-z]{52})\b`,
			},
		},

		// ========================================
		// Developer Platforms & Version Control
		// ========================================

		// GitHub Fine-Grained PAT
		{
			Name:      GitHubFineGrainedPATRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b`,
			},
		},

		// GitLab Token
		{
			Name:      GitLabTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(glpat-[a-zA-Z0-9\-=_]{20,})\b`,
			},
		},

		// NPM Token
		{
			Name:      NPMTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(npm_[0-9a-zA-Z]{36})`,
			},
		},

		// PyPI Token
		{
			Name:      PyPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(pypi-AgEIcHlwaS5vcmcCJ[a-zA-Z0-9_-]{150,157})`,
			},
		},

		// RubyGems Token
		{
			Name:      RubyGemsTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(rubygems_[a-zA-Z0-9]{48})\b`,
			},
		},

		// Shopify Token
		{
			Name:      ShopifyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:shppa_|shpat_)[0-9A-Fa-f]{32})\b`,
			},
		},

		// Atlassian Token
		{
			Name:      AtlassianTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`,
			},
		},

		// Jira Token
		{
			Name:      JiraTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ATATT[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b`,
			},
		},

		// Postman API Key
		{
			Name:      PostmanAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(PMAK-[a-zA-Z0-9-]{59})\b`,
			},
		},

		// Figma PAT
		{
			Name:      FigmaPATRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(fig[dou][rh]?_[a-z0-9A-Z_-]{40})\b`,
			},
		},

		// ========================================
		// Communication & Social
		// ========================================

		// Discord Bot Token
		{
			Name:      DiscordBotTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)discord.{0,40}?\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b`,
			},
		},

		// Discord Webhook
		{
			Name:      DiscordWebhookRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(https://discord\.com/api/webhooks/[0-9]{18,19}/[0-9a-zA-Z-]{68})`,
			},
		},

		// Telegram Bot Token
		{
			Name:      TelegramBotTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:telegram|tgram).{0,40}?\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b`,
			},
		},

		// Facebook Access Token
		{
			Name:      FacebookAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `EAACEdEose0cBA[0-9A-Za-z]+`,
			},
		},

		// Facebook Secret Key
		{
			Name:      FacebookSecretKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)(?:facebook|fb).{0,20}?['\"][0-9a-f]{32}['\"]",
			},
		},

		// Facebook Client ID
		{
			Name:      FacebookClientIDRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)(?:facebook|fb).{0,20}?['\"][0-9]{13,17}['\"]",
			},
		},

		// Twitter Secret Key
		{
			Name:      TwitterSecretKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)twitter.{0,20}?['\"][0-9a-z]{35,44}['\"]",
			},
		},

		// Twitter Client ID
		{
			Name:      TwitterClientIDRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)twitter.{0,20}?['\"][0-9a-z]{18,25}['\"]",
			},
		},

		// ========================================
		// Monitoring, Observability & DevOps
		// ========================================

		// Datadog API Key
		{
			Name:      DatadogAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:datadog|dd).{0,40}?\b([a-zA-Z0-9-]{32})\b`,
			},
		},

		// Datadog App Key
		{
			Name:      DatadogAppKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:datadog|dd).{0,40}?\b([a-zA-Z0-9-]{40})\b`,
			},
		},

		// Sentry Token
		{
			Name:      SentryTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sntryu_[a-f0-9]{64})\b`,
			},
		},

		// Sentry Org Token
		{
			Name:      SentryOrgTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sntrys_eyJ[a-zA-Z0-9=_+/]{197})\b`,
			},
		},

		// New Relic API Key
		{
			Name:      NewRelicAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)newrelic.{0,40}?\b([A-Za-z0-9_.]{4}-[A-Za-z0-9_.]{42})\b`,
			},
		},

		// Splunk Token
		{
			Name:      SplunkTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)splunk.{0,40}?\b([a-z0-9A-Z]{22})\b`,
			},
		},

		// Grafana Cloud Token
		{
			Name:      GrafanaCloudTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(glc_eyJ[A-Za-z0-9+/=]{60,160})`,
			},
		},

		// Grafana Service Account
		{
			Name:      GrafanaServiceAccountRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(glsa_[0-9a-zA-Z_]{41})\b`,
			},
		},

		// CircleCI Token
		{
			Name:      CircleCITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(CCIPAT_[a-zA-Z0-9]{22}_[a-fA-F0-9]{40})`,
			},
		},

		// Buildkite Token
		{
			Name:      BuildkiteTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(bkua_[a-z0-9]{40})\b`,
			},
		},

		// TravisCI Token
		{
			Name:      TravisCITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)travis.{0,40}?\b([a-zA-Z0-9_]{22})\b`,
			},
		},

		// Snyk Key
		{
			Name:      SnykKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)snyk.{0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// ========================================
		// Hosting, Deployment & SaaS
		// ========================================

		// Vercel Token
		{
			Name:      VercelTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)vercel.{0,40}?\b([a-zA-Z0-9]{24})\b`,
			},
		},

		// Netlify Token
		{
			Name:      NetlifyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(nfp_[a-zA-Z0-9_]{36})\b`,
			},
		},

		// Doppler Token
		{
			Name:      DopplerTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(dp\.(?:ct|pt|st(?:\.[a-z0-9\-_]{2,35})?|sa|scim|audit)\.[a-zA-Z0-9]{40,44})\b`,
			},
		},

		// PlanetScale Token
		{
			Name:      PlanetScaleTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bpscale_tkn_[A-Za-z0-9_]{43}\b`,
			},
		},

		// PlanetScale Password
		{
			Name:      PlanetScalePasswordRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bpscale_pw_[A-Za-z0-9_]{43}\b`,
			},
		},

		// LaunchDarkly Token
		{
			Name:      LaunchDarklyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// Algolia Admin Key
		{
			Name:      AlgoliaAdminKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:algolia|docsearch|apiKey).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Okta Token
		{
			Name:      OktaTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b00[a-zA-Z0-9_-]{40}\b`,
			},
		},

		// Linear API Key
		{
			Name:      LinearAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(lin_api_[0-9A-Za-z]{40})\b`,
			},
		},

		// Weights & Biases Key
		{
			Name:      WeightsAndBiasesKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)wandb.{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// HashiCorp Vault Token
		{
			Name:      HashiCorpVaultTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(hvs\.[a-zA-Z0-9_-]{24,})\b`,
			},
		},

		// Mapbox Token
		{
			Name:      MapboxTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk\.[a-zA-Z0-9.\-]{80,240})\b`,
			},
		},

		// ========================================
		// Miscellaneous Content Patterns
		// ========================================

		// JWT
		{
			Name:      JWTRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b`,
			},
		},

		// Artifactory Token
		{
			Name:      ArtifactoryTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)artifactory.{0,50}['\"`]?([a-zA-Z0-9=]{112})",
			},
		},

		// CodeClimate Token
		{
			Name:      CodeClimateTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)codeclima.{0,50}['\"`]?([0-9a-f]{64})",
			},
		},

		// SonarQube Token
		{
			Name:      SonarQubeTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)sonar.{0,50}['\"`]?([0-9a-f]{40})",
			},
		},

		// HockeyApp Token
		{
			Name:      HockeyAppTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)hockey.{0,50}['\"`]?([0-9a-f]{32})",
			},
		},

		// StackHawk API Key
		{
			Name:      StackHawkAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20}`,
			},
		},

		// Outlook Webhook
		{
			Name:      OutlookWebhookRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(https://outlook\.office\.com/webhook/[0-9a-f-]{36}@)`,
			},
		},

		// WordPress Config Credentials
		{
			Name:      WPConfigCredentialsRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)define\s*\(\s*['\"](?:DB_PASSWORD|DB_USER|AUTH_KEY|SECURE_AUTH_KEY|LOGGED_IN_KEY|NONCE_KEY|AUTH_SALT|SECURE_AUTH_SALT|LOGGED_IN_SALT|NONCE_SALT)['\"]\s*,\s*['\"](.*?)['\"]`,
			},
		},

		// ========================================
		// Cloud & Infrastructure (Batch 1)
		// ========================================

		// Alibaba Cloud Access Key ID
		{
			Name:      AlibabaCloudKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(LTAI[a-zA-Z0-9]{17,21})\b`,
			},
		},

		// Databricks Token
		{
			Name:      DatabricksTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(dapi[0-9a-f]{32}(?:-\d)?)\b`,
			},
		},

		// NVIDIA NGC API Key
		{
			Name:      NVIDIANGCKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(nvapi-[a-zA-Z0-9_-]{64,})\b`,
			},
		},

		// AWS Session Token
		{
			Name:      AWSSessionTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)aws.{0,20}?session.{0,20}?token.{0,20}?\b(FwoGZXIvYXdz[a-zA-Z0-9/+=]{20,})\b`,
			},
		},

		// Azure SAS Token
		{
			Name:      AzureSASTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(sp=[racwdli]+&st=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z&se=\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z(?:&sip=\d{1,3}(?:\.\d{1,3}){3}(?:-\d{1,3}(?:\.\d{1,3}){3})?)?(?:&spr=https)?(?:,https)?&sv=\d{4}-\d{2}-\d{2}&sr=[bcfso]&sig=[a-zA-Z0-9%]{10,})`,
			},
		},

		// Azure Function Key
		{
			Name:      AzureFunctionKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)azure.{0,40}?function.{0,40}?\b([a-zA-Z0-9_-]{20,56}={0,2})\b`,
			},
		},

		// Azure Container Registry Password
		{
			Name:      AzureContainerRegistryRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b([a-zA-Z0-9+/]{42}\+ACR[a-zA-Z0-9]{6})\b`,
			},
		},

		// Azure Search Admin Key
		{
			Name:      AzureSearchAdminKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:azure|search).{0,40}?(?:admin|api).{0,20}?key.{0,20}?\b([0-9a-zA-Z]{52})\b`,
			},
		},

		// Azure App Configuration Connection String
		{
			Name:      AzureAppConfigConnStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(Endpoint=https://[a-zA-Z0-9-]+\.azconfig\.io;Id=[a-zA-Z0-9+/=]+;Secret=[a-zA-Z0-9+/=]+)`,
			},
		},

		// Azure OpenAI Key
		{
			Name:      AzureOpenAIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:api[_.-]?key|openai[_.-]?key).{0,40}?\b([a-f0-9]{32})\b`,
			},
		},

		// Azure Cosmos DB Key
		{
			Name:      AzureCosmosDBKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:cosmos|document).{0,40}?(?:Key|AccountKey).{0,10}?([A-Za-z0-9+/]{86}==)`,
			},
		},

		// Azure Batch Key
		{
			Name:      AzureBatchKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:batch).{0,40}?(?:key).{0,10}?([A-Za-z0-9+/]{88}==)`,
			},
		},

		// Azure API Management Subscription Key
		{
			Name:      AzureAPIManagementKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:azure|\.azure-api\.net|subscription|ocp-apim).{0,40}?key.{0,10}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Confluent Cloud API Key
		{
			Name:      ConfluentKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)confluent.{0,40}?\b([a-zA-Z0-9]{16})\b`,
			},
		},

		// Confluent Cloud API Secret
		{
			Name:      ConfluentSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)confluent.{0,40}?secret.{0,20}?\b([a-zA-Z0-9+/]{64})\b`,
			},
		},

		// Aiven Token
		{
			Name:      AivenTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)aiven.{0,40}?\b([a-zA-Z0-9/+=]{372})\b`,
			},
		},

		// Pulumi Access Token
		{
			Name:      PulumiTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pul-[a-z0-9]{40})\b`,
			},
		},

		// Terraform Cloud Personal Token
		{
			Name:      TerraformCloudTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b([A-Za-z0-9]{14}\.atlasv1\.[A-Za-z0-9]{67})\b`,
			},
		},

		// Infura API Key
		{
			Name:      InfuraAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)infura.{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// Alchemy API Key
		{
			Name:      AlchemyAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(alcht_[0-9a-zA-Z]{30})\b`,
			},
		},

		// DigitalOcean Spaces Access Key
		{
			Name:      DigitalOceanSpacesKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:do|digitalocean|spaces).{0,40}?\b([A-Z0-9]{20})\b`,
			},
		},

		// Scaleway Secret Key
		{
			Name:      ScalewayKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)scaleway.{0,40}?\b([0-9a-z]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// Vultr API Key
		{
			Name:      VultrAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)vultr.{0,40}?\b([A-Z0-9]{36})\b`,
			},
		},

		// Hetzner API Token
		{
			Name:      HetznerAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)hetzner.{0,40}?\b([A-Za-z0-9]{64})\b`,
			},
		},

		// Linode API Token
		{
			Name:      LinodeAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)linode.{0,40}?\b([a-f0-9]{64})\b`,
			},
		},

		// Dropbox Access Token
		{
			Name:      DropboxTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sl\.(?:u\.)?[A-Za-z0-9_-]{130,})\b`,
			},
		},

		// Fly.io Access Token
		{
			Name:      FlyIOTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(FlyV1 fm\d+_[A-Za-z0-9+/=,_-]{500,700})\b`,
			},
		},

		// Railway API Token
		{
			Name:      RailwayTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)railway.{0,40}?\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			},
		},

		// Render API Key
		{
			Name:      RenderAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(rnd_[a-zA-Z0-9]{32})\b`,
			},
		},

		// Couchbase Connection String
		{
			Name:      CouchbaseConnStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(cb\.[a-z0-9]+\.cloud\.couchbase\.com)\b`,
			},
		},

		// RabbitMQ Connection String
		{
			Name:      RabbitMQConnStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bamqps?://[\S]{3,50}:([\S]{3,50})@[-.%\w/:]+\b`,
			},
		},

		// FTP Credential
		{
			Name:      FTPCredentialRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bftp://[\S]{3,50}:([\S]{3,50})@[-.%\w/:]+\b`,
			},
		},

		// JDBC Connection String
		{
			Name:      JDBCConnStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)(jdbc:[\\w]{3,10}:[^\\s\"'<>,{}[\\]]{10,511}[A-Za-z0-9])",
			},
		},

		// MySQL Connection String
		{
			Name:      MySQLConnStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bmysql://[\S]{3,50}:([\S]{3,50})@[-.%\w/:]+\b`,
			},
		},

		// Elasticsearch URL with credentials
		{
			Name:      ElasticsearchURLRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bhttps?://[\S]{3,50}:([\S]{3,50})@[-.%\w]+(?::\d{1,5})\b`,
			},
		},

		// Ngrok Auth Token
		{
			Name:      NGrokTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)ngrok.{0,40}?\b(2[a-zA-Z0-9]{26}_\d[a-zA-Z0-9]{20})\b`,
			},
		},

		// Portainer Token
		{
			Name:      PortainerTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ptr_[A-Za-z0-9/_\-+=]{20,60})\b`,
			},
		},

		// Snowflake Account Identifier
		{
			Name:      SnowflakeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)snowflake.{0,40}?account.{0,20}?\b([a-zA-Z]{7}-[0-9a-zA-Z_-]{1,255})\b`,
			},
		},

		// Cloudsmith API Key
		{
			Name:      CloudsmithAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)cloudsmith.{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// PackageCloud Token
		{
			Name:      PackageCloudTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)packagecloud.{0,40}?\b([0-9a-f]{48})\b`,
			},
		},

		// ========================================
		// Marketing, Analytics & CRM (Batch 5)
		// ========================================

		// MailerLite Token
		{
			Name:      MailerLiteTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)mailerlite.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ConvertKit Token
		{
			Name:      ConvertKitTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)convertkit.{0,40}?\b([a-z0-9A-Z_]{22})\b`,
			},
		},

		// Omnisend Key
		{
			Name:      OmnisendKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)omnisend.{0,40}?\b([a-z0-9A-Z-]{75})\b`,
			},
		},

		// Customer.io Key
		{
			Name:      CustomerIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)customer.{0,40}?\b([a-z0-9A-Z]{20})\b`,
			},
		},

		// Klaviyo Private Key
		{
			Name:      KlaviyoPrivateKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pk_[a-zA-Z0-9]{34})\b`,
			},
		},

		// Iterable API Key
		{
			Name:      IterableAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)iterable.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Brevo (Sendinblue v2) API Key
		{
			Name:      BrevoAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(xkeysib-[A-Za-z0-9_-]{81})\b`,
			},
		},

		// ActiveCampaign Key
		{
			Name:      ActiveCampaignKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)activecampaign.{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// Drip API Key
		{
			Name:      DripAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)drip.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// GetResponse Key
		{
			Name:      GetResponseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)getresponse.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Moosend Key
		{
			Name:      MoosendKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)moosend.{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// SendinBlue Key (legacy)
		{
			Name:      SendinBlueKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(xkeysib-[A-Za-z0-9_-]{81})\b`,
			},
		},

		// Eventbrite Key
		{
			Name:      EventbriteKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)eventbrite.{0,40}?\b([0-9A-Z]{20})\b`,
			},
		},

		// Typeform Token
		{
			Name:      TypeformTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(tfp_[a-zA-Z0-9_]{40,59})\b`,
			},
		},

		// SurveyMonkey Token
		{
			Name:      SurveyMonkeyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)surveymonkey.{0,40}?\b([a-zA-Z0-9]{50})\b`,
			},
		},

		// FullStory Token
		{
			Name:      FullStoryTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(na1\.[A-Za-z0-9+/]{100})\b`,
			},
		},

		// Hotjar Token
		{
			Name:      HotjarTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)hotjar.{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// Optimizely Token
		{
			Name:      OptimizelyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)optimizely.{0,40}?\b([0-9A-Za-z:_-]{54})\b`,
			},
		},

		// Appsflyer Key
		{
			Name:      AppsflyerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)appsflyer.{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// Branch.io Key
		{
			Name:      BranchIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(key_(?:live|test)_[a-zA-Z0-9]{32})\b`,
			},
		},

		// Chargebee Key
		{
			Name:      ChargebeeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(live_[a-zA-Z0-9]{32})\b`,
			},
		},

		// Recurly API Key
		{
			Name:      RecurlyAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)recurly.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Paddle Key
		{
			Name:      PaddleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)paddle.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Chargify Key
		{
			Name:      ChargifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)chargify.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Zuora Key
		{
			Name:      ZuoraKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)zuora.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// BigCommerce Token
		{
			Name:      BigCommerceTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)bigcommerce.{0,40}?\b([a-z0-9]{48})\b`,
			},
		},

		// WooCommerce Key
		{
			Name:      WooCommerceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ck_[a-zA-Z0-9]{40})\b`,
			},
		},

		// Contentstack Token
		{
			Name:      ContentstackTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(cs_[a-zA-Z0-9]{28})\b`,
			},
		},

		// Storyblok Token
		{
			Name:      StoryblokTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)storyblok.{0,40}?\b([0-9A-Za-z]{22}tt)\b`,
			},
		},

		// GraphCMS Token
		{
			Name:      GraphCMSTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:graphcms|hygraph).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Prismic Token
		{
			Name:      PrismicTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)prismic.{0,40}?\b([a-zA-Z0-9]{50}\.[a-zA-Z0-9]{10})\b`,
			},
		},

		// Strapi API Key
		{
			Name:      StrapiAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)strapi.{0,40}?\b([a-z0-9]{48})\b`,
			},
		},

		// Ghost Admin Key
		{
			Name:      GhostAdminKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b([a-f0-9]{24}:[a-f0-9]{32})\b`,
			},
		},

		// ButterCMS Key
		{
			Name:      ButterCMSKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)buttercms.{0,40}?\b([a-z0-9]{40})\b`,
			},
		},

		// DatoCMS Token
		{
			Name:      DatoCMSTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:datocms|dato).{0,40}?\b([a-z0-9]{20})\b`,
			},
		},

		// HarperDB Key
		{
			Name:      HarperDBKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)harperdb.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// FaunaDB Key
		{
			Name:      FaunaDBKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(fnA[A-Za-z0-9_-]{37,})\b`,
			},
		},

		// PlanetScale OAuth Token
		{
			Name:      PlanetScaleOAuthRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pscale_otkn_[A-Za-z0-9_]{43})\b`,
			},
		},

		// Turso Token
		{
			Name:      TursoTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)turso.{0,40}?\b([a-z0-9]{44})\b`,
			},
		},

		// Neon Token
		{
			Name:      NeonTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)neon.{0,40}?\b([a-z0-9]{44})\b`,
			},
		},

		// ========================================
		// Data Platforms & Misc (Batch 6)
		// ========================================

		// Splunk Observability Token
		{
			Name:      SplunkObservabilityTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)splunk.{0,40}?\b([a-zA-Z0-9]{22})\b`,
			},
		},

		// SumoLogic Key
		{
			Name:      SumoLogicKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:sumo|accessKey).{0,40}?\b([A-Za-z0-9]{64})\b`,
			},
		},

		// Elastic Cloud Key
		{
			Name:      ElasticCloudKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)elastic.{0,40}?\b([a-zA-Z0-9+/]{44}={0,2})`,
			},
		},

		// TimescaleDB Token
		{
			Name:      TimescaleDBTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(tsdbk_[a-zA-Z0-9]{36,})\b`,
			},
		},

		// ClickHouse Token
		{
			Name:      ClickHouseTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(chc_[a-zA-Z0-9]{30,})\b`,
			},
		},

		// InfluxDB Token
		{
			Name:      InfluxDBTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)influx.{0,40}?\b([a-zA-Z0-9+/]{80,88}={0,2})`,
			},
		},

		// CockroachDB Token
		{
			Name:      CockroachDBTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(crl-v1-[a-z0-9]{36,})\b`,
			},
		},

		// Redis Cloud Key
		{
			Name:      RedisCloudTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)redis.{0,10}?cloud.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Upstash Token
		{
			Name:      UpstashTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(AXXX[A-Za-z0-9]{40,})\b`,
			},
		},

		// OpenSearch Key
		{
			Name:      OpenSearchKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)opensearch.{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// PagerDuty Service Key
		{
			Name:      PagerDutyServiceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:pagerduty|pager_duty|pd_|pd-).{0,40}?\b(u\+[a-zA-Z0-9_+-]{18})\b`,
			},
		},

		// StatusPage Key
		{
			Name:      StatusPageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)statuspage.{0,40}?\b([0-9a-z-]{36})\b`,
			},
		},

		// UptimeRobot Key
		{
			Name:      UptimeRobotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)uptimerobot.{0,40}?\b([a-zA-Z0-9]{9}-[a-zA-Z0-9]{24})\b`,
			},
		},

		// Datadog RUM Token
		{
			Name:      DatadogRUMTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pub[a-f0-9]{29})\b`,
			},
		},

		// Google Maps API Key
		{
			Name:      GoogleMapsAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(AIzaSy[A-Za-z0-9_-]{33})\b`,
			},
		},

		// MapTiler Key
		{
			Name:      MapTilerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)maptiler.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// TomTom API Key
		{
			Name:      TomTomAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)tomtom.{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// HERE API Key
		{
			Name:      HereAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)hereapi.{0,40}?\b([a-zA-Z0-9]{43})\b`,
			},
		},

		// TwelveData API Key
		{
			Name:      TwelveDatAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)twelvedata.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// AlphaVantage Key
		{
			Name:      AlphaVantageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)alphavantage.{0,40}?\b([A-Z0-9]{16})\b`,
			},
		},

		// Polygon.io Key
		{
			Name:      PolygonIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)polygon.{0,40}?\b([a-z0-9A-Z]{32})\b`,
			},
		},

		// Finnhub Token
		{
			Name:      FinnhubTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)finnhub.{0,40}?\b([0-9a-z]{20})\b`,
			},
		},

		// CoinGecko Key
		{
			Name:      CoinGeckoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(CG-[a-z0-9]{34})\b`,
			},
		},

		// Blockchain.info Key
		{
			Name:      BlockchainInfoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)blockchain.{0,40}?\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			},
		},

		// AWS Cognito Token
		{
			Name:      AWSCognitoTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(us-(?:east|west)-[12]_[a-zA-Z0-9]{9})\b`,
			},
		},

		// Firebase API Key
		{
			Name:      FirebaseAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)firebase.{0,40}?\b(AIzaSy[A-Za-z0-9_-]{33})\b`,
			},
		},

		// Firebase Cloud Messaging
		{
			Name:      FirebaseCloudMsgRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(AAAA[A-Za-z0-9_-]{7,}:APA91b[A-Za-z0-9_-]{130,})\b`,
			},
		},

		// AppCenter Token
		{
			Name:      AppCenterTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)appcenter.{0,40}?\b([a-f0-9]{40})\b`,
			},
		},

		// Expo Token
		{
			Name:      ExpoTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ExponentPushToken\[[a-zA-Z0-9_-]+\])`,
			},
		},

		// TestFlight Token (Apple App Store Connect API Key)
		{
			Name:      TestFlightTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:appstoreconnect|testflight|app.store).{0,40}?\b(eyJ[A-Za-z0-9+/=_-]{60,})\b`,
			},
		},

		// SonarCloud Token
		{
			Name:      SonarCloudTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)sonarcloud.{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// Coverity Token
		{
			Name:      CoverityTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)coverity.{0,40}?\b(cov-[a-z0-9]{32})\b`,
			},
		},

		// FOSSA Key
		{
			Name:      FossaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(fossa-[a-z0-9]{32,})\b`,
			},
		},

		// WhiteSource Key
		{
			Name:      WhitesourceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)whitesource.{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// Black Duck Token
		{
			Name:      BlackDuckTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)blackduck.{0,40}?\b([a-zA-Z0-9]{100,})\b`,
			},
		},

		// Netlify Deploy Key
		{
			Name:      NetlifyDeployKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(nfp_[a-zA-Z0-9_]{36})\b`,
			},
		},

		// Cloudinary URL
		{
			Name:      CloudinaryURLRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(cloudinary://[0-9]{10,}:[A-Za-z0-9_-]{20,}@[a-z0-9]+)`,
			},
		},

		// Imgix Token
		{
			Name:      ImgixTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ix-[a-zA-Z0-9]{32,})\b`,
			},
		},

		// Fastly API Token
		{
			Name:      FastlyAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)fastly.{0,40}?\b([A-Za-z0-9_-]{32})\b`,
			},
		},

		// Akamai Token
		{
			Name:      AkamaiTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(akab-[a-z0-9]{16}-[a-z0-9]{16})\b`,
			},
		},

		// ========================================
		// SaaS & Communication (Batch 3)
		// ========================================

		// Twilio Account SID
		{
			Name:      TwilioAccountSIDRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(AC[0-9a-f]{32})\b`,
			},
		},

		// Telnyx API Key
		{
			Name:      TelnyxAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(KEY[0-9A-Za-z_-]{55})\b`,
			},
		},

		// Vonage API Key
		{
			Name:      VonageAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)vonage.{0,40}?\b([a-z0-9]{8})\b`,
			},
		},

		// Plivo Auth Token
		{
			Name:      PlivoAuthTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)plivo.{0,40}?\b([A-Za-z0-9_-]{40})\b`,
			},
		},

		// MessageBird Key
		{
			Name:      MessageBirdKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)messagebird.{0,40}?\b([A-Za-z0-9_-]{25})\b`,
			},
		},

		// SendBird Key
		{
			Name:      SendBirdKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)sendbird.{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// Mandrill API Key
		{
			Name:      MandrillAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)mandrill.{0,40}?\b([A-Za-z0-9_-]{22})\b`,
			},
		},

		// SparkPost Token
		{
			Name:      SparkPostTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)sparkpost.{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// Courier API Key
		{
			Name:      CourierAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pk_[a-zA-Z0-9]+_[a-zA-Z0-9]{28})\b`,
			},
		},

		// Postmark Token
		{
			Name:      PostmarkTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)postmark.{0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// Intercom Token
		{
			Name:      IntercomTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)intercom.{0,40}?\b([a-zA-Z0-9\W\S]{59}=)`,
			},
		},

		// Freshdesk Token
		{
			Name:      FreshdeskTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)freshdesk.{0,40}?\b([0-9A-Za-z]{20})\b`,
			},
		},

		// Freshbooks Token
		{
			Name:      FreshbooksTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)freshbooks.{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// HubSpot API Key
		{
			Name:      HubSpotAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)hubspot.{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// Salesforce Token
		{
			Name:      SalesforceTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(00[a-zA-Z0-9]{13}![a-zA-Z0-9_.]{96})\b`,
			},
		},

		// DocuSign Key
		{
			Name:      DocuSignKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:docusign|integration).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// Fastly Token
		{
			Name:      FastlyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)fastly.{0,40}?\b([A-Za-z0-9_-]{32})\b`,
			},
		},

		// Mattermost Token
		{
			Name:      MattermostTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)mattermost.{0,40}?\b([a-z0-9]{26})\b`,
			},
		},

		// Webflow Token
		{
			Name:      WebflowTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)webflow.{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// Deepgram API Key
		{
			Name:      DeepgramAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)deepgram.{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// AssemblyAI Key
		{
			Name:      AssemblyAIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)assemblyai.{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// Cohere API Key
		{
			Name:      CohereAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)cohere.{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// Mistral API Key
		{
			Name:      MistralAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)mistral.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Fireworks API Key
		{
			Name:      FireworksAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(fw_[a-zA-Z0-9]{32,64})\b`,
			},
		},

		// Together API Key
		{
			Name:      TogetherAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)together.{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// Perplexity API Key
		{
			Name:      PerplexityAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pplx-[a-f0-9]{48})\b`,
			},
		},

		// Slack App Token
		{
			Name:      SlackAppTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(xapp-[0-9]+-[A-Za-z0-9]+-[0-9]+-[a-z0-9]+)\b`,
			},
		},

		// Trello API Key
		{
			Name:      TrelloAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)trello.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Monday Token
		{
			Name:      MondayTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)monday.{0,40}?\b(eyJ[A-Za-z0-9_-]{15,100}\.eyJ[A-Za-z0-9_-]{100,300}\.[A-Za-z0-9_-]{25,100})\b`,
			},
		},

		// Todoist Token
		{
			Name:      TodoistTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)todoist.{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// LarkSuite Token
		{
			Name:      LarkSuiteTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:lark|larksuite).{0,40}?\b(cli_[a-z0-9A-Z]{16})\b`,
			},
		},

		// Smartsheet Token
		{
			Name:      SmartsheetTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:smartsheet|sheet).{0,40}?\b([a-zA-Z0-9]{26})\b`,
			},
		},

		// Auth0 Client Secret
		{
			Name:      Auth0ClientSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)auth0.{0,40}?\b([a-zA-Z0-9_-]{64,})\b`,
			},
		},

		// OneLogin Secret
		{
			Name:      OneLoginSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)onelogin.{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// JumpCloud API Key
		{
			Name:      JumpCloudAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)jumpcloud.{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// Pipedream API Key
		{
			Name:      PipedreamAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)pipedream.{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// Webex Bot Token
		{
			Name:      WebexBotTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `([a-zA-Z0-9]{64}_[a-zA-Z0-9]{4}_[a-zA-Z0-9]{8}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{4}-[a-zA-Z0-9]{12})`,
			},
		},

		// Twitch Access Token
		{
			Name:      TwitchAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)twitch.{0,40}?\b([0-9a-z]{30})\b`,
			},
		},

		// SignalWire Token
		{
			Name:      SignalWireTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)signalwire.{0,40}?\b([0-9A-Za-z]{50})\b`,
			},
		},

		// TextMagic Key
		{
			Name:      TextMagicKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)textmagic.{0,40}?\b([0-9A-Za-z]{30})\b`,
			},
		},

		// ========================================
		// Payments, Blockchain & Security (Batch 4)
		// ========================================

		// Flutterwave Secret Key
		{
			Name:      FlutterwaveKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(FLWSECK-[0-9a-z]{32}-X)\b`,
			},
		},

		// Paystack Secret Key
		{
			Name:      PaystackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk_[a-z]+_[A-Za-z0-9]{40})\b`,
			},
		},

		// Razorpay Key
		{
			Name:      RazorpayKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(rzp_live_[A-Za-z0-9]{14})\b`,
			},
		},

		// Etherscan API Key
		{
			Name:      EtherscanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)etherscan.{0,40}?\b([0-9A-Z]{34})\b`,
			},
		},

		// BSCScan API Key
		{
			Name:      BSCScanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)bscscan.{0,40}?\b([0-9A-Z]{34})\b`,
			},
		},

		// Pinata API Key
		{
			Name:      PinataAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)pinata.{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// Moralis API Key
		{
			Name:      MoralisAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)moralis.{0,40}?\b([0-9a-zA-Z]{64})\b`,
			},
		},

		// Coinbase API Key Name
		{
			Name:      CoinbaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(organizations/\w{8}-\w{4}-\w{4}-\w{4}-\w{12}/apiKeys/\w{8}-\w{4}-\w{4}-\w{4}-\w{12})\b`,
			},
		},

		// Plaid Access Token
		{
			Name:      PlaidAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(access-(?:sandbox|production)-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			},
		},

		// Plaid Secret Key
		{
			Name:      PlaidSecretKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)plaid.{0,40}?\b([a-f0-9]{30})\b`,
			},
		},

		// Wise (TransferWise) API Key
		{
			Name:      WiseAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)transferwise.{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// Dwolla API Key
		{
			Name:      DwollaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)dwolla.{0,40}?\b([a-zA-Z0-9-]{50})\b`,
			},
		},

		// LemonSqueezy API Key (JWT format)
		{
			Name:      LemonSqueezyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.[0-9A-Za-z]{314}\.[0-9A-Za-z_-]{512})\b`,
			},
		},

		// SauceLabs Access Key
		{
			Name:      SauceLabsTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)saucelabs.{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// BrowserStack Access Key
		{
			Name:      BrowserStackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:browserstack|BS_AUTHKEY|ACCESS_KEY).{0,40}?\b([0-9a-zA-Z]{20})\b`,
			},
		},

		// Bitly Access Token
		{
			Name:      BitlyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)bitly.{0,40}?\b([a-zA-Z0-9-]{40})\b`,
			},
		},

		// Snipcart API Key
		{
			Name:      SnipcartAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)snipcart.{0,40}?\b([0-9A-Za-z_]{75})\b`,
			},
		},

		// Gumroad Access Token
		{
			Name:      GumroadAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)gumroad.{0,40}?\b([a-z0-9A-Z-]{43})\b`,
			},
		},

		// RapidAPI Key
		{
			Name:      RapidAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)rapidapi.{0,40}?\b([A-Za-z0-9_-]{50})\b`,
			},
		},

		// IPInfo Token
		{
			Name:      IPInfoTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)ipinfo.{0,40}?\b([a-f0-9]{14})\b`,
			},
		},

		// Shodan API Key
		{
			Name:      ShodanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)shodan.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// VirusTotal API Key
		{
			Name:      VirusTotalAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)virustotal.{0,40}?\b([a-f0-9]{64})\b`,
			},
		},

		// SecurityTrails API Key
		{
			Name:      SecurityTrailsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)securitytrails.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// URLScan API Key
		{
			Name:      URLScanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)urlscan.{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// Censys API Key
		{
			Name:      CensysKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)censys.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Sanity Auth Token
		{
			Name:      SanityTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk[A-Za-z0-9]{79})\b`,
			},
		},

		// Wistia API Key
		{
			Name:      WistiaTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)wistia.{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// Stripe Payment Intent Secret
		{
			Name:      StripePaymentIntentRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pi_[a-zA-Z0-9]{24}_secret_[a-zA-Z0-9]{24})\b`,
			},
		},

		// Square Application Token
		{
			Name:      SquareAppTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `((?:sandbox-)?sq0i[a-z]{2}-[0-9A-Za-z_-]{22,43})`,
			},
		},

		// OneSignal API Key
		{
			Name:      OneSignalKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)onesignal.{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// SSHPass Command
		{
			Name:      SSHPassRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `sshpass\s+-p\s*['"](.+?)['"]`,
			},
		},

		// Grafana API Key (glsa_)
		{
			Name:      GrafanaAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(glsa_[0-9a-zA-Z_]{41})\b`,
			},
		},

		// Frame.io Token
		{
			Name:      FrameIOTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(fio-u-[0-9a-zA-Z_-]{64})\b`,
			},
		},

		// Stytch Secret
		{
			Name:      StytchSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)stytch.{0,40}?\b([a-zA-Z0-9_-]{47}=)`,
			},
		},

		// Klaviyo API Key
		{
			Name:      KlaviyoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pk_[a-zA-Z0-9]{34})\b`,
			},
		},

		// Laravel App Key
		{
			Name:      LaravelAppKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)APP_KEY\s*=\s*(base64:[A-Za-z0-9+/]{43}=)`,
			},
		},

		// Generic API Key pattern
		{
			Name:      GenericAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: "(?i)api[_-]?key[\\s]*[=:>]+[\\s]*['\"`]?([a-zA-Z0-9_\\-]{32,64})['\"`]?",
			},
		},

		// Robinhood Crypto API Key
		{
			Name:      RobinhoodCryptoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(rh-api-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`,
			},
		},

		// Zoho CRM Token
		{
			Name:      ZohoTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(1000\.[a-f0-9]{32}\.[a-f0-9]{32})\b`,
			},
		},

		// GoDaddy API Key
		{
			Name:      GoDaddyAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)godaddy.{0,40}?\b([a-zA-Z0-9_]{37})\b`,
			},
		},

		// ===== DevOps & Developer Tools (Batch 2) =====

		// Bitbucket App Password
		{
			Name:      BitbucketAppPasswordRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ATBB[A-Za-z0-9_=.-]{30,})\b`,
			},
		},

		// Drone CI Token
		{
			Name:      DroneTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)drone.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Sourcegraph Access Token
		{
			Name:      SourcegraphTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40})\b`,
			},
		},

		// Sourcegraph Cody Token
		{
			Name:      SourcegraphCodyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(slk_[a-fA-F0-9]{64})\b`,
			},
		},

		// LangSmith API Token
		{
			Name:      LangSmithTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(lsv2_(?:pt|sk)_[a-f0-9]{32}_[a-f0-9]{10})\b`,
			},
		},

		// Langfuse Secret Key
		{
			Name:      LangfuseSecretKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// Langfuse Public Key
		{
			Name:      LangfusePublicKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pk-lf-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// Prefect Cloud API Token
		{
			Name:      PrefectTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pnu_[a-z0-9]{36})\b`,
			},
		},

		// Harness Personal/Service Account Token
		{
			Name:      HarnessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pat\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20})\b`,
			},
		},

		// Contentful Personal Access Token
		{
			Name:      ContentfulPATRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(CFPAT-[a-zA-Z0-9_-]{43})\b`,
			},
		},

		// Airtable API Key / PAT
		{
			Name:      AirtableTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pat[a-zA-Z0-9]{14}\.[a-fA-F0-9]{64})\b`,
			},
		},

		// Notion Integration Secret
		{
			Name:      NotionTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(secret_[A-Za-z0-9]{43})\b`,
			},
		},

		// ClickUp API Token
		{
			Name:      ClickUpTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pk_[0-9]{7,8}_[A-Za-z0-9]{32})\b`,
			},
		},

		// Asana Personal Access Token
		{
			Name:      AsanaPATRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b([0-9]{1}/[0-9]{16}:[a-f0-9]{32})\b`,
			},
		},

		// Coveralls Repo Token
		{
			Name:      CoverallsTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)coveralls.{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// Codemagic API Token
		{
			Name:      CodemagicTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)codemagic.{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// Codacy Project Token
		{
			Name:      CodacyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)codacy.{0,40}?\b([a-f0-9]{32})\b`,
			},
		},

		// Scrutinizer API Token
		{
			Name:      ScrutinizerTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)scrutinizer.{0,40}?\b([a-f0-9]{48})\b`,
			},
		},

		// Percy Token
		{
			Name:      PercyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)percy.{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// PagerDuty API Key
		{
			Name:      PagerDutyAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)pagerduty.{0,40}?\b(u\+[a-zA-Z0-9]{18})\b`,
			},
		},

		// Opsgenie API Key
		{
			Name:      OpsgenieAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)opsgenie.{0,40}?\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			},
		},

		// Honeycomb API Key
		{
			Name:      HoneycombTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)honeycomb.{0,40}?\b([a-zA-Z0-9]{22,24})\b`,
			},
		},

		// BetterStack / Logtail Token
		{
			Name:      BetterStackTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:betterstack|logtail).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Loggly Customer Token
		{
			Name:      LogglyTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)loggly.{0,40}?\b([a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12})\b`,
			},
		},

		// Logz.io API Token
		{
			Name:      LogzIOTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)logz.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// PostHog Project API Key
		{
			Name:      PostHogTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(phx_[a-zA-Z0-9_]{43})\b`,
			},
		},

		// Segment Write Key
		{
			Name:      SegmentAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)segment.{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// Mixpanel Project Token
		{
			Name:      MixpanelTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)mixpanel.{0,40}?\b([a-f0-9]{32})\b`,
			},
		},

		// Amplitude API Key
		{
			Name:      AmplitudeAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)amplitude.{0,40}?\b([a-f0-9]{32})\b`,
			},
		},

		// Endor Labs API Token
		{
			Name:      EndorLabsTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(endr_[a-zA-Z0-9]{40,})\b`,
			},
		},

		// Nightfall API Key
		{
			Name:      NightfallAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(NF-[a-zA-Z0-9]{32,})\b`,
			},
		},

		// Sentry DSN (Client Key)
		{
			Name:      SentryDSNRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(https://[a-f0-9]{32}@o[0-9]+\.ingest\.sentry\.io/[0-9]+)`,
			},
		},

		// JupiterOne API Token
		{
			Name:      JupiterOneTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)jupiterone.{0,40}?\b([a-zA-Z0-9]{56})\b`,
			},
		},

		// Wiz Auth Token
		{
			Name:      WizTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)wiz.{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// Detectify API Key
		{
			Name:      DetectifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)detectify.{0,40}?\b([a-f0-9]{32})\b`,
			},
		},

		// Microsoft Teams Webhook
		{
			Name:      MicrosoftTeamsWebhookRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(https://[a-zA-Z0-9-]+\.webhook\.office\.com/webhookb2/[a-f0-9-]+@[a-f0-9-]+/IncomingWebhook/[a-z0-9]+/[a-f0-9-]+)`,
			},
		},

		// Zapier Webhook URL
		{
			Name:      ZapierWebhookRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(https://hooks\.zapier\.com/hooks/catch/[0-9]+/[a-z0-9]+/)`,
			},
		},

		// Tines Webhook URL
		{
			Name:      TinesWebhookRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(https://[a-zA-Z0-9-]+\.tines\.com/webhook/[a-f0-9]{32})`,
			},
		},

		// GitLab Runner Registration Token
		{
			Name:      GitLabRunnerTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(glrt-[a-zA-Z0-9\-=_]{20,})\b`,
			},
		},

		// Docker Hub Personal Access Token
		{
			Name:      DockerHubTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(dckr_pat_[a-zA-Z0-9_-]{27})\b`,
			},
		},

	}
}