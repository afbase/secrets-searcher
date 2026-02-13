package builtin_test

import (
	"testing"

	"github.com/afbase/secrets-searcher/pkg/app/build"
	"github.com/afbase/secrets-searcher/pkg/builtin"
	gitpkg "github.com/afbase/secrets-searcher/pkg/git"
	"github.com/afbase/secrets-searcher/pkg/logg"
	"github.com/afbase/secrets-searcher/pkg/manip"
	"github.com/afbase/secrets-searcher/pkg/search/contract"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// FileSigJobMock implements contract.ProcessorJobI for testing the file signature processor.
type FileSigJobMock struct {
	path    string
	results []*contract.Result
	logger  logg.Logg
}

func (m *FileSigJobMock) FileChange() *gitpkg.FileChange {
	return &gitpkg.FileChange{Commit: &gitpkg.Commit{}, Path: m.path}
}
func (m *FileSigJobMock) SubmitResult(result *contract.Result) {
	m.results = append(m.results, result)
}
func (m *FileSigJobMock) SubmitIgnore(fileRange *manip.FileRange)                  {}
func (m *FileSigJobMock) Log(yourLog logg.Logg) logg.Logg                          { return m.logger }
func (m *FileSigJobMock) SearchingCommit(commit *gitpkg.Commit)                    {}
func (m *FileSigJobMock) SearchingWithProcessor(proc contract.NamedProcessorI)     {}
func (m *FileSigJobMock) SearchingFileChange(fileChange *gitpkg.FileChange)        {}
func (m *FileSigJobMock) SearchingLine(line int)                                   {}
func (m *FileSigJobMock) Commit() *gitpkg.Commit                                  { return &gitpkg.Commit{} }
func (m *FileSigJobMock) Processor() contract.NamedProcessorI                      { return nil }
func (m *FileSigJobMock) Diff() *gitpkg.Diff                                      { return nil }
func (m *FileSigJobMock) Line() int                                                { return 1 }

func runFileSigTest(t *testing.T, name builtin.ProcessorName, filePath string, expectMatch bool) {
	t.Helper()
	procConfig := builtin.ProcessorConfig(name)
	proc := build.ProcFileSignature(procConfig.Name, &procConfig.FileSignatureProcessorConfig, log)

	job := &FileSigJobMock{path: filePath, logger: log}
	err := proc.FindResultsInFileChange(job)
	require.NoError(t, err)

	if expectMatch {
		assert.Len(t, job.results, 1, "Expected match for path: %s", filePath)
	} else {
		assert.Len(t, job.results, 0, "Expected no match for path: %s", filePath)
	}
}

// ========================================
// Extension-based file signatures (1-28)
// ========================================

func TestFileSig_PEMFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.PEMFileExtensionFileSig, "certs/server.pem", true)
}
func TestFileSig_PEMFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PEMFileExtensionFileSig, "certs/server.crt", false)
}

func TestFileSig_PKCS12FileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.PKCS12FileExtensionFileSig, "keys/bundle.pkcs12", true)
}
func TestFileSig_PKCS12FileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PKCS12FileExtensionFileSig, "keys/bundle.pem", false)
}

func TestFileSig_P12FileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.P12FileExtensionFileSig, "keys/cert.p12", true)
}
func TestFileSig_P12FileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.P12FileExtensionFileSig, "keys/cert.pem", false)
}

func TestFileSig_PFXFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.PFXFileExtensionFileSig, "keys/cert.pfx", true)
}
func TestFileSig_PFXFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PFXFileExtensionFileSig, "keys/cert.pem", false)
}

func TestFileSig_ASCFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.ASCFileExtensionFileSig, "keys/key.asc", true)
}
func TestFileSig_ASCFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ASCFileExtensionFileSig, "keys/key.txt", false)
}

func TestFileSig_OVPNFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.OVPNFileExtensionFileSig, "vpn/config.ovpn", true)
}
func TestFileSig_OVPNFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.OVPNFileExtensionFileSig, "vpn/config.txt", false)
}

func TestFileSig_CSCFGFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.CSCFGFileExtensionFileSig, "azure/service.cscfg", true)
}
func TestFileSig_CSCFGFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.CSCFGFileExtensionFileSig, "azure/service.json", false)
}

func TestFileSig_RDPFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.RDPFileExtensionFileSig, "remote/server.rdp", true)
}
func TestFileSig_RDPFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.RDPFileExtensionFileSig, "remote/server.txt", false)
}

func TestFileSig_MDFFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.MDFFileExtensionFileSig, "db/data.mdf", true)
}
func TestFileSig_MDFFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.MDFFileExtensionFileSig, "db/data.bak", false)
}

func TestFileSig_SDFFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.SDFFileExtensionFileSig, "db/compact.sdf", true)
}
func TestFileSig_SDFFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SDFFileExtensionFileSig, "db/compact.mdf", false)
}

func TestFileSig_SQLiteFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.SQLiteFileExtensionFileSig, "db/app.sqlite", true)
}
func TestFileSig_SQLiteFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SQLiteFileExtensionFileSig, "db/app.db", false)
}

func TestFileSig_SQLite3FileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.SQLite3FileExtensionFileSig, "db/app.sqlite3", true)
}
func TestFileSig_SQLite3FileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SQLite3FileExtensionFileSig, "db/app.db", false)
}

func TestFileSig_BEKFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.BEKFileExtensionFileSig, "keys/bitlocker.bek", true)
}
func TestFileSig_BEKFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.BEKFileExtensionFileSig, "keys/bitlocker.key", false)
}

func TestFileSig_TPMFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.TPMFileExtensionFileSig, "keys/module.tpm", true)
}
func TestFileSig_TPMFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.TPMFileExtensionFileSig, "keys/module.key", false)
}

func TestFileSig_FVEFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.FVEFileExtensionFileSig, "keys/volume.fve", true)
}
func TestFileSig_FVEFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.FVEFileExtensionFileSig, "keys/volume.key", false)
}

func TestFileSig_JKSFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.JKSFileExtensionFileSig, "java/keystore.jks", true)
}
func TestFileSig_JKSFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.JKSFileExtensionFileSig, "java/keystore.ks", false)
}

func TestFileSig_PSafe3FileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.PSafe3FileExtensionFileSig, "vault/passwords.psafe3", true)
}
func TestFileSig_PSafe3FileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PSafe3FileExtensionFileSig, "vault/passwords.kdbx", false)
}

func TestFileSig_AgileKeychainFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.AgileKeychainFileExtensionFileSig, "1pass/data.agilekeychain", true)
}
func TestFileSig_AgileKeychainFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.AgileKeychainFileExtensionFileSig, "1pass/data.opvault", false)
}

func TestFileSig_KeychainFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.KeychainFileExtensionFileSig, "mac/login.keychain", true)
}
func TestFileSig_KeychainFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KeychainFileExtensionFileSig, "mac/login.plist", false)
}

func TestFileSig_PCAPFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.PCAPFileExtensionFileSig, "capture/traffic.pcap", true)
}
func TestFileSig_PCAPFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PCAPFileExtensionFileSig, "capture/traffic.log", false)
}

func TestFileSig_GnuCashFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.GnuCashFileExtensionFileSig, "finance/books.gnucash", true)
}
func TestFileSig_GnuCashFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.GnuCashFileExtensionFileSig, "finance/books.qif", false)
}

func TestFileSig_KWalletFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.KWalletFileExtensionFileSig, "kde/wallet.kwallet", true)
}
func TestFileSig_KWalletFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KWalletFileExtensionFileSig, "kde/wallet.dat", false)
}

func TestFileSig_TBLKFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.TBLKFileExtensionFileSig, "vpn/tunnel.tblk", true)
}
func TestFileSig_TBLKFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.TBLKFileExtensionFileSig, "vpn/tunnel.ovpn", false)
}

func TestFileSig_DayOneFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.DayOneFileExtensionFileSig, "journal/entry.dayone", true)
}
func TestFileSig_DayOneFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DayOneFileExtensionFileSig, "journal/entry.md", false)
}

func TestFileSig_PPKFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.PPKFileExtensionFileSig, "ssh/key.ppk", true)
}
func TestFileSig_PPKFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PPKFileExtensionFileSig, "ssh/key.pem", false)
}

func TestFileSig_SQLDumpFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.SQLDumpFileExtensionFileSig, "backup/db.sqldump", true)
}
func TestFileSig_SQLDumpFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SQLDumpFileExtensionFileSig, "backup/db.sql", false)
}

func TestFileSig_NetrcFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.NetrcFileExtensionFileSig, "auth/creds.netrc", true)
}
func TestFileSig_NetrcFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.NetrcFileExtensionFileSig, "auth/creds.txt", false)
}

func TestFileSig_LogFileExtension_Match(t *testing.T) {
	runFileSigTest(t, builtin.LogFileExtensionFileSig, "logs/app.log", true)
}
func TestFileSig_LogFileExtension_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.LogFileExtensionFileSig, "logs/app.txt", false)
}

// ========================================
// Filename-based file signatures (29-75)
// ========================================

func TestFileSig_OTRPrivateKey_Match(t *testing.T) {
	runFileSigTest(t, builtin.OTRPrivateKeyFileSig, "home/otr.private_key", true)
}
func TestFileSig_OTRPrivateKey_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.OTRPrivateKeyFileSig, "home/otr.public_key", false)
}

func TestFileSig_SecretTokenRB_Match(t *testing.T) {
	runFileSigTest(t, builtin.SecretTokenRBFileSig, "config/initializers/secret_token.rb", true)
}
func TestFileSig_SecretTokenRB_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SecretTokenRBFileSig, "config/initializers/session.rb", false)
}

func TestFileSig_CarrierWaveRB_Match(t *testing.T) {
	runFileSigTest(t, builtin.CarrierWaveRBFileSig, "config/initializers/carrierwave.rb", true)
}
func TestFileSig_CarrierWaveRB_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.CarrierWaveRBFileSig, "config/initializers/devise.rb", false)
}

func TestFileSig_DatabaseYML_Match(t *testing.T) {
	runFileSigTest(t, builtin.DatabaseYMLFileSig, "config/database.yml", true)
}
func TestFileSig_DatabaseYML_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DatabaseYMLFileSig, "config/application.yml", false)
}

func TestFileSig_OmniauthRB_Match(t *testing.T) {
	runFileSigTest(t, builtin.OmniauthRBFileSig, "config/initializers/omniauth.rb", true)
}
func TestFileSig_OmniauthRB_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.OmniauthRBFileSig, "config/initializers/cors.rb", false)
}

func TestFileSig_SettingsPY_Match(t *testing.T) {
	runFileSigTest(t, builtin.SettingsPYFileSig, "myapp/settings.py", true)
}
func TestFileSig_SettingsPY_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SettingsPYFileSig, "myapp/views.py", false)
}

func TestFileSig_CredentialsXML_Match(t *testing.T) {
	runFileSigTest(t, builtin.CredentialsXMLFileSig, "jenkins/credentials.xml", true)
}
func TestFileSig_CredentialsXML_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.CredentialsXMLFileSig, "jenkins/config.xml", false)
}

func TestFileSig_LocalSettingsPHP_Match(t *testing.T) {
	runFileSigTest(t, builtin.LocalSettingsPHPFileSig, "wiki/LocalSettings.php", true)
}
func TestFileSig_LocalSettingsPHP_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.LocalSettingsPHPFileSig, "wiki/Settings.php", false)
}

func TestFileSig_FavoritesPlist_Match(t *testing.T) {
	runFileSigTest(t, builtin.FavoritesPlistFileSig, "sequelpro/Favorites.plist", true)
}
func TestFileSig_FavoritesPlist_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.FavoritesPlistFileSig, "sequelpro/Config.plist", false)
}

func TestFileSig_KnifeRB_Match(t *testing.T) {
	runFileSigTest(t, builtin.KnifeRBFileSig, ".chef/knife.rb", true)
}
func TestFileSig_KnifeRB_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KnifeRBFileSig, ".chef/solo.rb", false)
}

func TestFileSig_ProftpdPasswd_Match(t *testing.T) {
	runFileSigTest(t, builtin.ProftpdPasswdFileSig, "etc/proftpdpasswd", true)
}
func TestFileSig_ProftpdPasswd_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ProftpdPasswdFileSig, "etc/passwd", false)
}

func TestFileSig_RobomongoJSON_Match(t *testing.T) {
	runFileSigTest(t, builtin.RobomongoJSONFileSig, ".3T/robomongo.json", true)
}
func TestFileSig_RobomongoJSON_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.RobomongoJSONFileSig, ".3T/settings.json", false)
}

func TestFileSig_FileZillaXML_Match(t *testing.T) {
	runFileSigTest(t, builtin.FileZillaXMLFileSig, ".config/filezilla.xml", true)
}
func TestFileSig_FileZillaXML_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.FileZillaXMLFileSig, ".config/other.xml", false)
}

func TestFileSig_RecentServersXML_Match(t *testing.T) {
	runFileSigTest(t, builtin.RecentServersXMLFileSig, ".config/recentservers.xml", true)
}
func TestFileSig_RecentServersXML_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.RecentServersXMLFileSig, ".config/servers.xml", false)
}

func TestFileSig_TerraformTFVars_Match(t *testing.T) {
	runFileSigTest(t, builtin.TerraformTFVarsFileSig, "infra/terraform.tfvars", true)
}
func TestFileSig_TerraformTFVars_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.TerraformTFVarsFileSig, "infra/main.tf", false)
}

func TestFileSig_DotExports_Match(t *testing.T) {
	runFileSigTest(t, builtin.DotExportsFileSig, "home/.exports", true)
}
func TestFileSig_DotExports_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DotExportsFileSig, "home/.bashrc", false)
}

func TestFileSig_DotFunctions_Match(t *testing.T) {
	runFileSigTest(t, builtin.DotFunctionsFileSig, "home/.functions", true)
}
func TestFileSig_DotFunctions_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DotFunctionsFileSig, "home/.bashrc", false)
}

func TestFileSig_DotExtra_Match(t *testing.T) {
	runFileSigTest(t, builtin.DotExtraFileSig, "home/.extra", true)
}
func TestFileSig_DotExtra_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DotExtraFileSig, "home/.bashrc", false)
}

func TestFileSig_HerokuJSON_Match(t *testing.T) {
	runFileSigTest(t, builtin.HerokuJSONFileSig, "app/heroku.json", true)
}
func TestFileSig_HerokuJSON_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.HerokuJSONFileSig, "app/package.json", false)
}

func TestFileSig_DumpSQL_Match(t *testing.T) {
	runFileSigTest(t, builtin.DumpSQLFileSig, "backup/dump.sql", true)
}
func TestFileSig_DumpSQL_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DumpSQLFileSig, "backup/schema.sql", false)
}

func TestFileSig_MongoidYML_Match(t *testing.T) {
	runFileSigTest(t, builtin.MongoidYMLFileSig, "config/mongoid.yml", true)
}
func TestFileSig_MongoidYML_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.MongoidYMLFileSig, "config/database.yml", false)
}

func TestFileSig_SalesforceJS_Match(t *testing.T) {
	runFileSigTest(t, builtin.SalesforceJSFileSig, "config/salesforce.js", true)
}
func TestFileSig_SalesforceJS_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SalesforceJSFileSig, "config/app.js", false)
}

func TestFileSig_Gemrc_Match(t *testing.T) {
	runFileSigTest(t, builtin.GemrcFileSig, "home/.gemrc", true)
}
func TestFileSig_Gemrc_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.GemrcFileSig, "home/.bashrc", false)
}

func TestFileSig_DockerCfg_Match(t *testing.T) {
	runFileSigTest(t, builtin.DockerCfgFileSig, "home/.dockercfg", true)
}
func TestFileSig_DockerCfg_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DockerCfgFileSig, "home/.docker/config.json", false)
}

func TestFileSig_Npmrc_Match(t *testing.T) {
	runFileSigTest(t, builtin.NpmrcFileSig, "project/.npmrc", true)
}
func TestFileSig_Npmrc_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.NpmrcFileSig, "project/package.json", false)
}

func TestFileSig_Htpasswd_Match(t *testing.T) {
	runFileSigTest(t, builtin.HtpasswdFileSig, "apache/.htpasswd", true)
}
func TestFileSig_Htpasswd_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.HtpasswdFileSig, "apache/.htaccess", false)
}

func TestFileSig_Keystore_Match(t *testing.T) {
	runFileSigTest(t, builtin.KeystoreFileSig, "android/keystore", true)
}
func TestFileSig_Keystore_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KeystoreFileSig, "android/build.gradle", false)
}

func TestFileSig_BashHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.BashHistoryFileSig, "home/.bash_history", true)
}
func TestFileSig_BashHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.BashHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_ZshHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.ZshHistoryFileSig, "home/.zsh_history", true)
}
func TestFileSig_ZshHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ZshHistoryFileSig, "home/.zshrc", false)
}

func TestFileSig_MySQLHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.MySQLHistoryFileSig, "home/.mysql_history", true)
}
func TestFileSig_MySQLHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.MySQLHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_PsqlHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.PsqlHistoryFileSig, "home/.psql_history", true)
}
func TestFileSig_PsqlHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PsqlHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_IRBHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.IRBHistoryFileSig, "home/.irb_history", true)
}
func TestFileSig_IRBHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.IRBHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_ConsoleHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.ConsoleHistoryFileSig, "home/.console_history", true)
}
func TestFileSig_ConsoleHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ConsoleHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_SShellHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.SShellHistoryFileSig, "home/.sh_history", true)
}
func TestFileSig_SShellHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SShellHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_LessHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.LessHistoryFileSig, "home/.lesshst", true)
}
func TestFileSig_LessHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.LessHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_GitCredentials_Match(t *testing.T) {
	runFileSigTest(t, builtin.GitCredentialsFileSig, "home/.git-credentials", true)
}
func TestFileSig_GitCredentials_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.GitCredentialsFileSig, "home/.gitconfig", false)
}

func TestFileSig_S3CFG_Match(t *testing.T) {
	runFileSigTest(t, builtin.S3CFGFileSig, "home/.s3cfg", true)
}
func TestFileSig_S3CFG_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.S3CFGFileSig, "home/.aws/config", false)
}

func TestFileSig_WgetHSTS_Match(t *testing.T) {
	runFileSigTest(t, builtin.WgetHSTSFileSig, "home/.wget-hsts", true)
}
func TestFileSig_WgetHSTS_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.WgetHSTSFileSig, "home/.bashrc", false)
}

func TestFileSig_PerlHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.PerlHistoryFileSig, "home/.cpan_history", true)
}
func TestFileSig_PerlHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PerlHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_FTPHistory_Match(t *testing.T) {
	runFileSigTest(t, builtin.FTPHistoryFileSig, "home/.lftp_history", true)
}
func TestFileSig_FTPHistory_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.FTPHistoryFileSig, "home/.bashrc", false)
}

func TestFileSig_PGPass_Match(t *testing.T) {
	runFileSigTest(t, builtin.PGPassFileSig, "home/.pgpass", true)
}
func TestFileSig_PGPass_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.PGPassFileSig, "home/.bashrc", false)
}

func TestFileSig_AppSettingsJSON_Match(t *testing.T) {
	runFileSigTest(t, builtin.AppSettingsJSONFileSig, "dotnet/appsettings.json", true)
}
func TestFileSig_AppSettingsJSON_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.AppSettingsJSONFileSig, "dotnet/package.json", false)
}

func TestFileSig_WebConfig_Match(t *testing.T) {
	runFileSigTest(t, builtin.WebConfigFileSig, "aspnet/web.config", true)
}
func TestFileSig_WebConfig_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.WebConfigFileSig, "aspnet/app.config", false)
}

func TestFileSig_DBConfigPHP_Match(t *testing.T) {
	runFileSigTest(t, builtin.DBConfigPHPFileSig, "wordpress/db-config.php", true)
}
func TestFileSig_DBConfigPHP_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DBConfigPHPFileSig, "wordpress/config.php", false)
}

func TestFileSig_WpConfigPHP_Match(t *testing.T) {
	runFileSigTest(t, builtin.WpConfigPHPFileSig, "wordpress/wp-config.php", true)
}
func TestFileSig_WpConfigPHP_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.WpConfigPHPFileSig, "wordpress/config.php", false)
}

func TestFileSig_ConfigIncPHP_Match(t *testing.T) {
	runFileSigTest(t, builtin.ConfigIncPHPFileSig, "phpmyadmin/config.inc.php", true)
}
func TestFileSig_ConfigIncPHP_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ConfigIncPHPFileSig, "phpmyadmin/config.php", false)
}

func TestFileSig_KeystoreProperties_Match(t *testing.T) {
	runFileSigTest(t, builtin.KeystorePropertiesFileSig, "android/keystore.properties", true)
}
func TestFileSig_KeystoreProperties_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KeystorePropertiesFileSig, "android/gradle.properties", false)
}

// ========================================
// Path/regex-based file signatures (76-99)
// ========================================

func TestFileSig_ShellRC_Match(t *testing.T) {
	runFileSigTest(t, builtin.ShellRCFileSig, "home/.bashrc", true)
}
func TestFileSig_ShellRC_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ShellRCFileSig, "home/.bash_profile", false)
}

func TestFileSig_ShellProfile_Match(t *testing.T) {
	runFileSigTest(t, builtin.ShellProfileFileSig, "home/.bash_profile", true)
}
func TestFileSig_ShellProfile_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ShellProfileFileSig, "home/.bashrc", false)
}

func TestFileSig_ShellAliases_Match(t *testing.T) {
	runFileSigTest(t, builtin.ShellAliasesFileSig, "home/.bash_aliases", true)
}
func TestFileSig_ShellAliases_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.ShellAliasesFileSig, "home/.bashrc", false)
}

func TestFileSig_Env_Match(t *testing.T) {
	runFileSigTest(t, builtin.EnvFileSig, "project/.env", true)
}
func TestFileSig_Env_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.EnvFileSig, "project/env.txt", false)
}

func TestFileSig_SSHRSAKey_Match(t *testing.T) {
	runFileSigTest(t, builtin.SSHRSAKeyFileSig, ".ssh/id_rsa", true)
}
func TestFileSig_SSHRSAKey_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SSHRSAKeyFileSig, ".ssh/id_rsa.pub", false)
}

func TestFileSig_SSHDSAKey_Match(t *testing.T) {
	runFileSigTest(t, builtin.SSHDSAKeyFileSig, ".ssh/id_dsa", true)
}
func TestFileSig_SSHDSAKey_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SSHDSAKeyFileSig, ".ssh/id_dsa.pub", false)
}

func TestFileSig_SSHEd25519Key_Match(t *testing.T) {
	runFileSigTest(t, builtin.SSHEd25519KeyFileSig, ".ssh/id_ed25519", true)
}
func TestFileSig_SSHEd25519Key_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SSHEd25519KeyFileSig, ".ssh/id_ed25519.pub", false)
}

func TestFileSig_SSHECDSAKey_Match(t *testing.T) {
	runFileSigTest(t, builtin.SSHECDSAKeyFileSig, ".ssh/id_ecdsa", true)
}
func TestFileSig_SSHECDSAKey_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SSHECDSAKeyFileSig, ".ssh/id_ecdsa.pub", false)
}

func TestFileSig_SSHConfig_Match(t *testing.T) {
	runFileSigTest(t, builtin.SSHConfigFileSig, "home/.ssh/config", true)
}
func TestFileSig_SSHConfig_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SSHConfigFileSig, "home/.ssh/known_hosts", false)
}

func TestFileSig_AWSCredentials_Match(t *testing.T) {
	runFileSigTest(t, builtin.AWSCredentialsFileSig, "home/.aws/credentials", true)
}
func TestFileSig_AWSCredentials_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.AWSCredentialsFileSig, "home/.aws/config", false)
}

func TestFileSig_DockerConfigJSON_Match(t *testing.T) {
	runFileSigTest(t, builtin.DockerConfigJSONFileSig, "home/.docker/config.json", true)
}
func TestFileSig_DockerConfigJSON_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.DockerConfigJSONFileSig, "home/.docker/daemon.json", false)
}

func TestFileSig_SSHKnownHosts_Match(t *testing.T) {
	runFileSigTest(t, builtin.SSHKnownHostsFileSig, "home/.ssh/known_hosts", true)
}
func TestFileSig_SSHKnownHosts_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.SSHKnownHostsFileSig, "home/.ssh/config", false)
}

func TestFileSig_IdeaWebServersXML_Match(t *testing.T) {
	runFileSigTest(t, builtin.IdeaWebServersXMLFileSig, "project/.idea/WebServers.xml", true)
}
func TestFileSig_IdeaWebServersXML_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.IdeaWebServersXMLFileSig, "project/.idea/workspace.xml", false)
}

func TestFileSig_VSCodeSFTPJSON_Match(t *testing.T) {
	runFileSigTest(t, builtin.VSCodeSFTPJSONFileSig, "project/.vscode/sftp.json", true)
}
func TestFileSig_VSCodeSFTPJSON_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.VSCodeSFTPJSONFileSig, "project/.vscode/settings.json", false)
}

func TestFileSig_EtcShadow_Match(t *testing.T) {
	runFileSigTest(t, builtin.EtcShadowFileSig, "etc/shadow", true)
}
func TestFileSig_EtcShadow_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.EtcShadowFileSig, "etc/passwd", false)
}

func TestFileSig_EtcPasswd_Match(t *testing.T) {
	runFileSigTest(t, builtin.EtcPasswdFileSig, "etc/passwd", true)
}
func TestFileSig_EtcPasswd_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.EtcPasswdFileSig, "etc/shadow", false)
}

func TestFileSig_FirefoxLoginsJSON_Match(t *testing.T) {
	runFileSigTest(t, builtin.FirefoxLoginsJSONFileSig, "home/.mozilla/firefox/abc123.default/logins.json", true)
}
func TestFileSig_FirefoxLoginsJSON_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.FirefoxLoginsJSONFileSig, "home/.mozilla/firefox/abc123.default/cookies.json", false)
}

func TestFileSig_GnuPG_Match(t *testing.T) {
	runFileSigTest(t, builtin.GnuPGFileSig, "home/.gnupg/secring.gpg", true)
}
func TestFileSig_GnuPG_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.GnuPGFileSig, "home/.gnupg/pubring.gpg", false)
}

func TestFileSig_TerraformTFState_Match(t *testing.T) {
	runFileSigTest(t, builtin.TerraformTFStateFileSig, "infra/terraform.tfstate", true)
}
func TestFileSig_TerraformTFState_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.TerraformTFStateFileSig, "infra/terraform.tf", false)
}

func TestFileSig_AWSConfig_Match(t *testing.T) {
	runFileSigTest(t, builtin.AWSConfigFileSig, "home/.aws/config", true)
}
func TestFileSig_AWSConfig_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.AWSConfigFileSig, "home/.aws/credentials", false)
}

func TestFileSig_GCloudConfig_Match(t *testing.T) {
	runFileSigTest(t, builtin.GCloudConfigFileSig, "home/.config/gcloud/credentials.json", true)
}
func TestFileSig_GCloudConfig_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.GCloudConfigFileSig, "home/.config/other/config", false)
}

func TestFileSig_KubeConfig_Match(t *testing.T) {
	runFileSigTest(t, builtin.KubeConfigFileSig, "home/.kube/config", true)
}
func TestFileSig_KubeConfig_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KubeConfigFileSig, "home/.kube/cache", false)
}

func TestFileSig_IntellIJDatasources_Match(t *testing.T) {
	runFileSigTest(t, builtin.IntellIJDatasourcesFileSig, "project/.idea/dataSources.xml", true)
}
func TestFileSig_IntellIJDatasources_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.IntellIJDatasourcesFileSig, "project/.idea/workspace.xml", false)
}

func TestFileSig_KeyPair_Match(t *testing.T) {
	runFileSigTest(t, builtin.KeyPairFileSig, "certs/.keypair.pem", true)
}
func TestFileSig_KeyPair_NoMatch(t *testing.T) {
	runFileSigTest(t, builtin.KeyPairFileSig, "certs/public.pem", false)
}
