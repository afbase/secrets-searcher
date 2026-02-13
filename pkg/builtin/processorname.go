package builtin

//go:generate stringer -type ProcessorName

type ProcessorName int

const (
	URLPathParamValSetter ProcessorName = iota
	URLQueryStringParamValSetter
	PyVarAssignSetter
	PyDictFieldAssignSetter
	PyDictLiteralFieldSetter
	PyTupleSetter
	PHPVarAssignSetter
	PHPAssocArrayFieldAssignSetter
	PHPAssocArrayLiteralFieldSetter
	PHPConstDefineSetter
	JSVarAssignSetter
	JSObjFieldAssignSetter
	JSObjLiteralFieldSetter
	GoVarAssignSetter
	GoHashFieldAssignSetter
	GoHashLiteralFieldSetter
	GoFlagDefaultValSetter
	RubyVarAssignSetter
	RubyHashFieldAssignSetter
	RubyArrowParamSetter
	RubyColonParamSetter
	ConfParamSystemdServiceEnvVarSetter
	ConfParamLogstashStyleSetter
	ConfParamLogstashStyleEnvVarDefaultSetter
	ShellScriptVarAssignSetter
	ShellCmdParamValSetter
	YAMLDictFieldValSetter
	JSONObjFieldValSetter
	XMLTagValSetter
	XMLTagValKeyAsAttrSetter
	XMLAttrValSetter
	HTMLTableRowValSetter
	GenericSetter

	RSAPrivateKeyPEM
	OpenSSHPrivateKeyPEM
	ECPrivateKeyPEM
	PGPPrivateKeyBlockPEM
	DSAPrivateKeyPEM

	SlackTokenRegex
	FacebookOAuthRegex
	GoogleOAuthRegex
	TwitterRegex
	HerokuAPIKeyRegex
	SlackWebhookRegex
	GCPServiceAccountRegex
	TwilioAPIKeyRegex
	URLPasswordRegex
	GenericSecretRegex
	AWSAccessKeyIDRegex
	AWSSecretKeyRegex
	AWSMWSAuthTokenRegex
	GitHubTokenRegex
	GitHubOAuthRegex
	LinkedInClientIDRegex
	LinkedInSecretKeyRegex
	StripeAPIKeyRegex
	SquareAccessTokenRegex
	SquareOAuthSecretRegex
	PayPalBraintreeAccessTokenRegex
	SendGridAPIKeyRegex
	MailGunAPIKeyRegex
	MailChimpAPIKeyRegex
	DigitalOceanPATRegex
	DigitalOceanOAuthRegex
	DigitalOceanRefreshTokenRegex
	NuGetAPIKeyRegex

	// AI/ML Providers
	OpenAIAPIKeyRegex
	AnthropicAPIKeyRegex
	GroqAPIKeyRegex
	DeepSeekAPIKeyRegex
	XAIAPIKeyRegex
	HuggingFaceTokenRegex
	ReplicateAPITokenRegex
	ElevenLabsAPIKeyRegex

	// Cloud & Infrastructure
	GoogleCloudAPIKeyRegex
	GoogleOAuthAccessTokenRegex
	GoogleOAuthKeyRegex
	CloudflareAPITokenRegex
	CloudflareGlobalAPIKeyRegex
	AzureStorageKeyRegex
	AzureEntraSecretRegex
	SupabaseTokenRegex
	MongoDBConnectionStringRegex
	PostgreSQLConnectionStringRegex
	RedisConnectionStringRegex
	AzureDevOpsPATRegex

	// Developer Platforms & Version Control
	GitHubFineGrainedPATRegex
	GitLabTokenRegex
	NPMTokenRegex
	PyPITokenRegex
	RubyGemsTokenRegex
	ShopifyTokenRegex
	AtlassianTokenRegex
	JiraTokenRegex
	PostmanAPIKeyRegex
	FigmaPATRegex

	// Communication & Social
	DiscordBotTokenRegex
	DiscordWebhookRegex
	TelegramBotTokenRegex
	FacebookAccessTokenRegex
	FacebookSecretKeyRegex
	FacebookClientIDRegex
	TwitterSecretKeyRegex
	TwitterClientIDRegex

	// Monitoring, Observability & DevOps
	DatadogAPIKeyRegex
	DatadogAppKeyRegex
	SentryTokenRegex
	SentryOrgTokenRegex
	NewRelicAPIKeyRegex
	SplunkTokenRegex
	GrafanaCloudTokenRegex
	GrafanaServiceAccountRegex
	CircleCITokenRegex
	BuildkiteTokenRegex
	TravisCITokenRegex
	SnykKeyRegex

	// Hosting, Deployment & SaaS
	VercelTokenRegex
	NetlifyTokenRegex
	DopplerTokenRegex
	PlanetScaleTokenRegex
	PlanetScalePasswordRegex
	LaunchDarklyTokenRegex
	AlgoliaAdminKeyRegex
	OktaTokenRegex
	LinearAPIKeyRegex
	WeightsAndBiasesKeyRegex
	HashiCorpVaultTokenRegex
	MapboxTokenRegex

	// Miscellaneous content patterns
	JWTRegex
	ArtifactoryTokenRegex
	CodeClimateTokenRegex
	SonarQubeTokenRegex
	HockeyAppTokenRegex
	StackHawkAPIKeyRegex
	OutlookWebhookRegex
	WPConfigCredentialsRegex

	// File Signature processors
	PEMFileExtensionFileSig
	PKCS12FileExtensionFileSig
	P12FileExtensionFileSig
	PFXFileExtensionFileSig
	ASCFileExtensionFileSig
	OVPNFileExtensionFileSig
	CSCFGFileExtensionFileSig
	RDPFileExtensionFileSig
	MDFFileExtensionFileSig
	SDFFileExtensionFileSig
	SQLiteFileExtensionFileSig
	SQLite3FileExtensionFileSig
	BEKFileExtensionFileSig
	TPMFileExtensionFileSig
	FVEFileExtensionFileSig
	JKSFileExtensionFileSig
	PSafe3FileExtensionFileSig
	AgileKeychainFileExtensionFileSig
	KeychainFileExtensionFileSig
	PCAPFileExtensionFileSig
	GnuCashFileExtensionFileSig
	KWalletFileExtensionFileSig
	TBLKFileExtensionFileSig
	DayOneFileExtensionFileSig
	PPKFileExtensionFileSig
	SQLDumpFileExtensionFileSig
	NetrcFileExtensionFileSig
	LogFileExtensionFileSig

	OTRPrivateKeyFileSig
	SecretTokenRBFileSig
	CarrierWaveRBFileSig
	DatabaseYMLFileSig
	OmniauthRBFileSig
	SettingsPYFileSig
	CredentialsXMLFileSig
	LocalSettingsPHPFileSig
	FavoritesPlistFileSig
	KnifeRBFileSig
	ProftpdPasswdFileSig
	RobomongoJSONFileSig
	FileZillaXMLFileSig
	RecentServersXMLFileSig
	TerraformTFVarsFileSig
	DotExportsFileSig
	DotFunctionsFileSig
	DotExtraFileSig
	HerokuJSONFileSig
	DumpSQLFileSig
	MongoidYMLFileSig
	SalesforceJSFileSig
	ShellRCFileSig
	ShellProfileFileSig
	ShellAliasesFileSig
	GemrcFileSig
	DockerCfgFileSig
	NpmrcFileSig
	EnvFileSig
	HtpasswdFileSig
	KeystoreFileSig

	SSHRSAKeyFileSig
	SSHDSAKeyFileSig
	SSHEd25519KeyFileSig
	SSHECDSAKeyFileSig
	SSHConfigFileSig
	AWSCredentialsFileSig
	DockerConfigJSONFileSig
	BashHistoryFileSig
	ZshHistoryFileSig
	MySQLHistoryFileSig
	PsqlHistoryFileSig
	IRBHistoryFileSig
	ConsoleHistoryFileSig
	SSHKnownHostsFileSig
	IdeaWebServersXMLFileSig
	VSCodeSFTPJSONFileSig
	EtcShadowFileSig
	EtcPasswdFileSig
	FirefoxLoginsJSONFileSig
	SShellHistoryFileSig
	LessHistoryFileSig
	GitCredentialsFileSig
	GnuPGFileSig
	S3CFGFileSig
	WgetHSTSFileSig
	PerlHistoryFileSig
	FTPHistoryFileSig
	TerraformTFStateFileSig
	AWSConfigFileSig
	GCloudConfigFileSig
	KubeConfigFileSig
	PGPassFileSig
	IntellIJDatasourcesFileSig
	AppSettingsJSONFileSig
	WebConfigFileSig
	DBConfigPHPFileSig
	WpConfigPHPFileSig
	ConfigIncPHPFileSig
	KeystorePropertiesFileSig
	KeyPairFileSig

	Base64Entropy
	HexEntropy
)
