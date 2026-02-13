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
	}
}
