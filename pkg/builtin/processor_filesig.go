package builtin

import (
	"github.com/afbase/secrets-searcher/pkg/app/config"
	"github.com/afbase/secrets-searcher/pkg/search"
)

// File signature processor definitions
func fileSignatureProcessorDefinitions() (result []*config.ProcessorConfig) {
	return []*config.ProcessorConfig{

		// ========================================
		// Extension-based file signatures
		// ========================================

		{
			Name:      PEMFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "pem",
				Description: "Potential cryptographic key or certificate",
			},
		},
		{
			Name:      PKCS12FileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "pkcs12",
				Description: "PKCS#12 key bundle",
			},
		},
		{
			Name:      P12FileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "p12",
				Description: "PKCS#12 key bundle",
			},
		},
		{
			Name:      PFXFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "pfx",
				Description: "PKCS#12 key bundle (PFX)",
			},
		},
		{
			Name:      ASCFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "asc",
				Description: "PGP/GPG armored key or signature",
			},
		},
		{
			Name:      OVPNFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "ovpn",
				Description: "OpenVPN configuration file",
			},
		},
		{
			Name:      CSCFGFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "cscfg",
				Description: "Azure Cloud Service configuration",
			},
		},
		{
			Name:      RDPFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "rdp",
				Description: "Remote Desktop Protocol connection file",
			},
		},
		{
			Name:      MDFFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "mdf",
				Description: "SQL Server database file",
			},
		},
		{
			Name:      SDFFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "sdf",
				Description: "SQL Server Compact database file",
			},
		},
		{
			Name:      SQLiteFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "sqlite",
				Description: "SQLite database file",
			},
		},
		{
			Name:      SQLite3FileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "sqlite3",
				Description: "SQLite3 database file",
			},
		},
		{
			Name:      BEKFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "bek",
				Description: "BitLocker encryption key",
			},
		},
		{
			Name:      TPMFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "tpm",
				Description: "Trusted Platform Module key",
			},
		},
		{
			Name:      FVEFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "fve",
				Description: "BitLocker Full Volume Encryption key",
			},
		},
		{
			Name:      JKSFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "jks",
				Description: "Java KeyStore file",
			},
		},
		{
			Name:      PSafe3FileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "psafe3",
				Description: "Password Safe database",
			},
		},
		{
			Name:      AgileKeychainFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "agilekeychain",
				Description: "1Password Agile Keychain",
			},
		},
		{
			Name:      KeychainFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "keychain",
				Description: "macOS Keychain file",
			},
		},
		{
			Name:      PCAPFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "pcap",
				Description: "Network packet capture file",
			},
		},
		{
			Name:      GnuCashFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "gnucash",
				Description: "GnuCash financial data",
			},
		},
		{
			Name:      KWalletFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "kwallet",
				Description: "KDE Wallet Manager data",
			},
		},
		{
			Name:      TBLKFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "tblk",
				Description: "Tunnelblick VPN configuration",
			},
		},
		{
			Name:      DayOneFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "dayone",
				Description: "Day One journal data",
			},
		},
		{
			Name:      PPKFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "ppk",
				Description: "PuTTY private key",
			},
		},
		{
			Name:      SQLDumpFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "sqldump",
				Description: "SQL database dump",
			},
		},
		{
			Name:      NetrcFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "netrc",
				Description: "Netrc credentials file",
			},
		},
		{
			Name:      LogFileExtensionFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "extension",
				Match:       "log",
				Description: "Log file (may contain secrets)",
			},
		},

		// ========================================
		// Filename-based file signatures
		// ========================================

		{
			Name:      OTRPrivateKeyFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "otr.private_key",
				Description: "OTR private key",
			},
		},
		{
			Name:      SecretTokenRBFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "secret_token.rb",
				Description: "Rails secret token configuration",
			},
		},
		{
			Name:      CarrierWaveRBFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "carrierwave.rb",
				Description: "CarrierWave configuration (may contain cloud storage credentials)",
			},
		},
		{
			Name:      DatabaseYMLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "database.yml",
				Description: "Database configuration file",
			},
		},
		{
			Name:      OmniauthRBFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "omniauth.rb",
				Description: "OmniAuth configuration (may contain OAuth secrets)",
			},
		},
		{
			Name:      SettingsPYFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "settings.py",
				Description: "Django settings file (may contain SECRET_KEY)",
			},
		},
		{
			Name:      CredentialsXMLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "credentials.xml",
				Description: "Jenkins credentials file",
			},
		},
		{
			Name:      LocalSettingsPHPFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "LocalSettings.php",
				Description: "MediaWiki local settings (contains DB credentials)",
			},
		},
		{
			Name:      FavoritesPlistFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "Favorites.plist",
				Description: "Sequel Pro favorites (contains DB credentials)",
			},
		},
		{
			Name:      KnifeRBFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "knife.rb",
				Description: "Chef Knife configuration",
			},
		},
		{
			Name:      ProftpdPasswdFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "proftpdpasswd",
				Description: "ProFTPd password file",
			},
		},
		{
			Name:      RobomongoJSONFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "robomongo.json",
				Description: "Robo 3T / Robomongo config (may contain MongoDB credentials)",
			},
		},
		{
			Name:      FileZillaXMLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "filezilla.xml",
				Description: "FileZilla configuration (may contain FTP credentials)",
			},
		},
		{
			Name:      RecentServersXMLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "recentservers.xml",
				Description: "FileZilla recent servers (may contain FTP credentials)",
			},
		},
		{
			Name:      TerraformTFVarsFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "terraform.tfvars",
				Description: "Terraform variables file (may contain cloud credentials)",
			},
		},
		{
			Name:      DotExportsFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".exports",
				Description: "Shell exports file (may contain API keys)",
			},
		},
		{
			Name:      DotFunctionsFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".functions",
				Description: "Shell functions file",
			},
		},
		{
			Name:      DotExtraFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".extra",
				Description: "Shell extra configuration (often contains secrets)",
			},
		},
		{
			Name:      HerokuJSONFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "heroku.json",
				Description: "Heroku configuration",
			},
		},
		{
			Name:      DumpSQLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "dump.sql",
				Description: "SQL database dump",
			},
		},
		{
			Name:      MongoidYMLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "mongoid.yml",
				Description: "Mongoid configuration (contains MongoDB credentials)",
			},
		},
		{
			Name:      SalesforceJSFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "salesforce.js",
				Description: "Salesforce configuration",
			},
		},
		{
			Name:      ShellRCFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.(?:bash|zsh|csh|tcsh|fish)rc$`,
				Description: "Shell RC file (may contain exported secrets)",
			},
		},
		{
			Name:      ShellProfileFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.(?:bash_profile|zprofile|profile|zshenv|zlogin)$`,
				Description: "Shell profile file (may contain exported secrets)",
			},
		},
		{
			Name:      ShellAliasesFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.(?:bash_aliases|zsh_aliases|aliases)$`,
				Description: "Shell aliases file",
			},
		},
		{
			Name:      GemrcFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".gemrc",
				Description: "RubyGems configuration (may contain API key)",
			},
		},
		{
			Name:      DockerCfgFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".dockercfg",
				Description: "Docker legacy configuration (contains registry credentials)",
			},
		},
		{
			Name:      NpmrcFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".npmrc",
				Description: "NPM configuration (may contain auth tokens)",
			},
		},
		{
			Name:      EnvFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.env(?:\.(?:local|development|staging|production|test|backup))?$`,
				Description: "Environment file (typically contains secrets)",
			},
		},
		{
			Name:      HtpasswdFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".htpasswd",
				Description: "Apache htpasswd file",
			},
		},
		{
			Name:      KeystoreFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "keystore",
				Description: "Java/Android keystore file",
			},
		},

		// ========================================
		// Path/regex-based file signatures
		// ========================================

		// SSH keys
		{
			Name:      SSHRSAKeyFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)(?:id_rsa|.*_rsa)$`,
				Description: "SSH RSA private key",
			},
		},
		{
			Name:      SSHDSAKeyFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)(?:id_dsa|.*_dsa)$`,
				Description: "SSH DSA private key",
			},
		},
		{
			Name:      SSHEd25519KeyFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)(?:id_ed25519|.*_ed25519)$`,
				Description: "SSH Ed25519 private key",
			},
		},
		{
			Name:      SSHECDSAKeyFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)(?:id_ecdsa|.*_ecdsa)$`,
				Description: "SSH ECDSA private key",
			},
		},
		{
			Name:      SSHConfigFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.ssh/config$`,
				Description: "SSH client configuration",
			},
		},
		{
			Name:      AWSCredentialsFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.aws/credentials$`,
				Description: "AWS credentials file",
			},
		},
		{
			Name:      DockerConfigJSONFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.docker/config\.json$`,
				Description: "Docker config (contains registry credentials)",
			},
		},

		// Shell histories
		{
			Name:      BashHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".bash_history",
				Description: "Bash history (may contain secrets in commands)",
			},
		},
		{
			Name:      ZshHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".zsh_history",
				Description: "Zsh history (may contain secrets in commands)",
			},
		},
		{
			Name:      MySQLHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".mysql_history",
				Description: "MySQL client history",
			},
		},
		{
			Name:      PsqlHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".psql_history",
				Description: "PostgreSQL client history",
			},
		},
		{
			Name:      IRBHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".irb_history",
				Description: "Ruby IRB history",
			},
		},
		{
			Name:      ConsoleHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".console_history",
				Description: "Rails console history",
			},
		},

		// SSH known hosts
		{
			Name:      SSHKnownHostsFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.ssh/known_hosts$`,
				Description: "SSH known hosts file",
			},
		},

		// IDE configs
		{
			Name:      IdeaWebServersXMLFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.idea/WebServers\.xml$`,
				Description: "IntelliJ IDEA web server config (may contain credentials)",
			},
		},
		{
			Name:      VSCodeSFTPJSONFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.vscode/sftp\.json$`,
				Description: "VS Code SFTP config (may contain credentials)",
			},
		},

		// System files
		{
			Name:      EtcShadowFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)etc/shadow$`,
				Description: "Unix shadow password file",
			},
		},
		{
			Name:      EtcPasswdFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)etc/passwd$`,
				Description: "Unix password file",
			},
		},

		// Browser data
		{
			Name:      FirefoxLoginsJSONFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.mozilla/firefox/[^/]+/logins\.json$`,
				Description: "Firefox saved logins",
			},
		},

		// More histories
		{
			Name:      SShellHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".sh_history",
				Description: "Shell history file",
			},
		},
		{
			Name:      LessHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".lesshst",
				Description: "Less history file",
			},
		},

		// Git credentials
		{
			Name:      GitCredentialsFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".git-credentials",
				Description: "Git credentials store",
			},
		},

		// GnuPG
		{
			Name:      GnuPGFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.gnupg/(?:secring\.gpg|trustdb\.gpg|private-keys-v1\.d/)`,
				Description: "GnuPG private key or trust database",
			},
		},

		// S3 configuration
		{
			Name:      S3CFGFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".s3cfg",
				Description: "s3cmd configuration (contains AWS credentials)",
			},
		},

		// wget
		{
			Name:      WgetHSTSFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".wget-hsts",
				Description: "wget HSTS cache",
			},
		},

		// More histories
		{
			Name:      PerlHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".cpan_history",
				Description: "Perl CPAN history",
			},
		},
		{
			Name:      FTPHistoryFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".lftp_history",
				Description: "LFTP history",
			},
		},

		// Terraform state
		{
			Name:      TerraformTFStateFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)terraform\.tfstate(?:\.backup)?$`,
				Description: "Terraform state file (contains cloud resource details and secrets)",
			},
		},

		// Cloud configs
		{
			Name:      AWSConfigFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.aws/config$`,
				Description: "AWS CLI configuration",
			},
		},
		{
			Name:      GCloudConfigFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.config/gcloud/`,
				Description: "Google Cloud CLI configuration",
			},
		},
		{
			Name:      KubeConfigFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.kube/config$`,
				Description: "Kubernetes configuration (may contain cluster credentials)",
			},
		},

		// Database configs
		{
			Name:      PGPassFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       ".pgpass",
				Description: "PostgreSQL password file",
			},
		},

		// IDE database configs
		{
			Name:      IntellIJDatasourcesFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.idea/dataSources(?:\.local)?\.xml$`,
				Description: "IntelliJ IDEA database config (may contain credentials)",
			},
		},

		// .NET / ASP.NET configs
		{
			Name:      AppSettingsJSONFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "appsettings.json",
				Description: ".NET application settings (may contain connection strings)",
			},
		},
		{
			Name:      WebConfigFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "web.config",
				Description: "ASP.NET web config (may contain connection strings)",
			},
		},

		// PHP configs
		{
			Name:      DBConfigPHPFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "db-config.php",
				Description: "PHP database config",
			},
		},
		{
			Name:      WpConfigPHPFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "wp-config.php",
				Description: "WordPress configuration (contains DB credentials and auth keys)",
			},
		},
		{
			Name:      ConfigIncPHPFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "config.inc.php",
				Description: "PHP config include (may contain credentials)",
			},
		},

		// Android / Java
		{
			Name:      KeystorePropertiesFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "filename",
				Match:       "keystore.properties",
				Description: "Android keystore properties (contains signing credentials)",
			},
		},
		{
			Name:      KeyPairFileSig.String(),
			Processor: search.FileSignature.String(),
			FileSignatureProcessorConfig: config.FileSignatureProcessorConfig{
				Part:        "path",
				RegexString: `(?:^|/)\.?key(?:pair)?(?:\.pem|\.key)?$`,
				Description: "Generic key/keypair file",
			},
		},
	}
}
