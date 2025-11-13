package builtin_test

import (
	"encoding/base64"
	"testing"

	"github.com/afbase/secrets-searcher/pkg/app/build"
	"github.com/afbase/secrets-searcher/pkg/builtin"
	"github.com/afbase/secrets-searcher/pkg/logg"
	"github.com/afbase/secrets-searcher/pkg/search/searchtest"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type processorTest struct {
	coreProcessor builtin.ProcessorName
	line          string
	expMatch      bool
	expSecret     string
	expContext    string
}

var log = logg.NewLogrusLogg(logrus.New())

// xorDecode decodes XOR-encoded base64 strings to avoid GitHub secret scanning on test fixtures
// All test secrets are XOR-encoded with key 0x5A to prevent false positives in security scanners
func xorDecode(encoded string) string {
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		panic("failed to decode test data: " + err.Error())
	}
	result := make([]byte, len(decoded))
	for i, b := range decoded {
		result[i] = b ^ 0x5A
	}
	return string(result)
}

// xorEncode encodes strings with XOR key 0x5A and base64 (for generating test data)
func xorEncode(input string) string {
	encoded := make([]byte, len(input))
	for i, b := range []byte(input) {
		encoded[i] = b ^ 0x5A
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func runProcessorTest(t *testing.T, tt processorTest) {
	procConfig := builtin.ProcessorConfig(tt.coreProcessor)
	subject := build.ProcRegex(procConfig.Name, &procConfig.RegexProcessorConfig, log)
	job := &searchtest.LineProcJobMock{Logger: log}

	// Fire
	err := subject.FindResultsInLine(job, tt.line)

	require.NoError(t, err)
	if !tt.expMatch {
		assert.Len(t, job.LineRanges, 0, "Expected no match for line: %s", tt.line)
		return
	}

	assert.Len(t, job.LineRanges, 1, "Expected one match for line: %s", tt.line)
	if len(job.LineRanges) > 0 {
		assert.Equal(t, tt.expSecret, job.LineRanges[0].ExtractValue(tt.line).Value)
	}
	if tt.expContext != "" && len(job.ContextLineRanges) > 0 {
		assert.Equal(t, tt.expContext, job.ContextLineRanges[0].ExtractValue(tt.line).Value)
	}
}

// ========================================
// Slack Token Tests
// ========================================

// Note: Test values are XOR-encoded to prevent GitHub secret scanning false positives
func TestProcessor_SlackToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          xorDecode("MhgvNTE2GQ5aGQ5aGhYaGRYaGBkaGhkaGxYaGxYaGRYxOQoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoK"),
		expMatch:      true,
		expSecret:     xorDecode("IhonGT4yGDsyGDouGDgyGTwyGzsyOQcLCQgLCQgLCQgLCQgLCQgLCQgLCQgL"),
	})
}

func TestProcessor_SlackToken_BotToken(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          xorDecode("GBkuGxowHAcKGwg0FRklGRkyIT4yGDsyGDouGDgyGTwyGzsyGToyGToyGTo5OwcKCwoJCwkKCQsJCgoJCwoJCwkKCQsJCgoJCwoJCwkKCQsJ"),
		expMatch:      true,
		expSecret:     xorDecode("IhonGT4yGDsyGDouGDgyGTwyGzsyGToyGToyGTo5OwcKCwoJCwkKCQsJCgoJCwoJCwkKCQsJCgoJCwoJCwkKCQsJ"),
	})
}

func TestProcessor_SlackToken_AppToken(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          xorDecode("JBwpKxoyIT4yGDsyGDouGDgyGTwyGzsyOQcLCQgLCQgLCQgLCQgLCQgLCQgLCQgL"),
		expMatch:      true,
		expSecret:     xorDecode("IhonGT4yGDsyGDouGDgyGTwyGzsyOQcLCQgLCQgLCQgLCQgLCQgLCQgLCQgL"),
	})
}

func TestProcessor_SlackToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          `slack_token = "not-a-real-token"`,
		expMatch:      false,
	})
}

// ========================================
// Slack Webhook Tests
// ========================================

// Note: Test values are XOR-encoded to prevent GitHub secret scanning false positives
func TestProcessor_SlackWebhook_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackWebhookRegex,
		line:          xorDecode("Hh8KHAsoCBweFgscJQYJJBoeMAEpHxwpGRwqHgEpHQALOT4yGDsyGDouGDgyMzoyIT4yGDsyGDouGDgyMzoyGhkaGhkaGhkaGhkaGhkaGhkaGhkaGBs="),
		expMatch:      true,
		expSecret:     xorDecode("IQYJJBoeMAEpHxwpGRwqHgEpHQALOT4yGDsyGDouGDgyMzoyIT4yGDsyGDouGDgyMzoyGhkaGhkaGhkaGhkaGhkaGhkaGhkaGBs="),
	})
}

func TestProcessor_SlackWebhook_InCode(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackWebhookRegex,
		line:          xorDecode("JhkoIQkpHAgcIBwnJBwnJBoeMAEpHxwpGRwqHgEpHQALOT4xCwoJCwkKODoyIToxCwoJCwkKODoyBwoJCwoJCwoJCwoJCwoJCwoJCwoJCwoJCwoJOA=="),
		expMatch:      true,
		expSecret:     xorDecode("IQYJJBoeMAEpHxwpGRwqHgEpHQALOT4xCwoJCwkKODoyIToxCwoJCwkKODoyBwoJCwoJCwoJCwoJCwoJCwoJCwoJCwoJCwoJOA=="),
	})
}

// ========================================
// AWS Access Key ID Tests
// ========================================

func TestProcessor_AWSAccessKeyID_AKIA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          `AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE`,
		expMatch:      true,
		expSecret:     "AKIAIOSFODNN7EXAMPLE",
	})
}

func TestProcessor_AWSAccessKeyID_ASIA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          `export AWS_KEY="ASIATESTACCESSKEY123"`,
		expMatch:      true,
		expSecret:     "ASIATESTACCESSKEY123",
	})
}

func TestProcessor_AWSAccessKeyID_AROA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          `role_id = AROAXXXXXXXXXX123456`,
		expMatch:      true,
		expSecret:     "AROAXXXXXXXXXX123456",
	})
}

func TestProcessor_AWSAccessKeyID_AIDA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          `user_id: AIDAXXXXXXXXXX123456`,
		expMatch:      true,
		expSecret:     "AIDAXXXXXXXXXX123456",
	})
}

func TestProcessor_AWSAccessKeyID_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          `aws_key = "not-a-valid-key"`,
		expMatch:      false,
	})
}

// ========================================
// AWS Secret Access Key Tests
// ========================================

func TestProcessor_AWSSecretKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSSecretKeyRegex,
		line:          `aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
		expMatch:      true,
		expSecret:     `"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"`,
	})
}

func TestProcessor_AWSSecretKey_WithContext(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSSecretKeyRegex,
		line:          `AWS_SECRET="abcdefghijklmnopqrstuvwxyz1234567890ABCD"`,
		expMatch:      true,
		expSecret:     `"abcdefghijklmnopqrstuvwxyz1234567890ABCD"`,
	})
}

// ========================================
// AWS MWS Auth Token Tests
// ========================================

func TestProcessor_AWSMWSAuthToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSMWSAuthTokenRegex,
		line:          `MWS_TOKEN=amzn.mws.12345678-1234-1234-1234-123456789012`,
		expMatch:      true,
		expSecret:     "amzn.mws.12345678-1234-1234-1234-123456789012",
	})
}

// ========================================
// GitHub Token Tests
// ========================================

func TestProcessor_GitHubToken_Classic(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubTokenRegex,
		line:          `GITHUB_TOKEN="ghp_EXAMPLENOTAREALTOKEN0000000000000"`,
		expMatch:      true,
		expSecret:     `ghp_EXAMPLENOTAREALTOKEN0000000000000`,
	})
}

func TestProcessor_GitHubToken_PAT(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubTokenRegex,
		line:          `github_pat: github_pat_00EXAMPLEONLY00000000000_EXAMPLEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		expMatch:      true,
		expSecret:     `github_pat_00EXAMPLEONLY00000000000_EXAMPLEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
	})
}

func TestProcessor_GitHubToken_Secret(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubTokenRegex,
		line:          `export GITHUB_SECRET = "ghs_EXAMPLENOTAREALTOKENXXXXXXXXXX"`,
		expMatch:      true,
		expSecret:     `ghs_EXAMPLENOTAREALTOKENXXXXXXXXXX`,
	})
}

// ========================================
// Digital Ocean Token Tests
// ========================================

func TestProcessor_DigitalOceanPAT_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanPATRegex,
		line:          xorDecode("HAguFhglHBwnKQwuHBwmHhsuMRsrGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhka"),
		expMatch:      true,
		expSecret:     xorDecode("HBwmHhsuMRsrGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhka"),
	})
}

func TestProcessor_DigitalOceanPAT_InJSON(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanPATRegex,
		line:          xorDecode("OxonJBwpKxoyOhonJBwuHBwmHhsuMRsrPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfIw=="),
		expMatch:      true,
		expSecret:     xorDecode("HBwmHhsuMRsrPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwf"),
	})
}

func TestProcessor_DigitalOceanOAuth_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanOAuthRegex,
		line:          xorDecode("HBwnHRoKHRonJBwpKxoyKQwuHBwnHRsuMRsrGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhka"),
		expMatch:      true,
		expSecret:     xorDecode("HBwnHRsuMRsrGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhka"),
	})
}

func TestProcessor_DigitalOceanRefreshToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanRefreshTokenRegex,
		line:          xorDecode("HQkfHQkqIQoyHBwqHRsuMRsrGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhka"),
		expMatch:      true,
		expSecret:     xorDecode("HBwqHRsuMRsrGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhka"),
	})
}

func TestProcessor_DigitalOceanPAT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanPATRegex,
		line:          `do_token = "not-a-valid-token"`,
		expMatch:      false,
	})
}

// ========================================
// Stripe API Key Tests
// ========================================

func TestProcessor_StripeAPIKey_SecretKeyLive(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripeAPIKeyRegex,
		line:          `STRIPE_SECRET_KEY=sk_live_EXAMPLEXXXXXXXXXXXXXXXX`,
		expMatch:      true,
		expSecret:     "sk_live_EXAMPLEXXXXXXXXXXXXXXXX",
	})
}

func TestProcessor_StripeAPIKey_SecretKeyTest(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripeAPIKeyRegex,
		line:          `stripe_key: "sk_test_NOTAREALKEYTESTEXAMPLEONLY"`,
		expMatch:      true,
		expSecret:     "sk_test_NOTAREALKEYTESTEXAMPLEONLY",
	})
}

func TestProcessor_StripeAPIKey_PublishableKey(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripeAPIKeyRegex,
		line:          `pk_live_EXAMPLEXXXXXXXXXXXXXXXX`,
		expMatch:      true,
		expSecret:     "pk_live_EXAMPLEXXXXXXXXXXXXXXXX",
	})
}

// ========================================
// SendGrid API Key Tests
// ========================================

func TestProcessor_SendGridAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendGridAPIKeyRegex,
		line:          `SENDGRID_API_KEY=SG.EXAMPLEXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		expMatch:      true,
		expSecret:     "SG.EXAMPLEXXXXXXXXXXXXXXX.XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	})
}

func TestProcessor_SendGridAPIKey_InConfig(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendGridAPIKeyRegex,
		line:          `api_key: SG.NOT-REAL_KEY-EXAMPLE.EXAMPLEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX`,
		expMatch:      true,
		expSecret:     "SG.NOT-REAL_KEY-EXAMPLE.EXAMPLEXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
	})
}

// ========================================
// MailGun API Key Tests
// ========================================

func TestProcessor_MailGunAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailGunAPIKeyRegex,
		line:          `MAILGUN_API_KEY=key-1234567890abcdef1234567890abcdef`,
		expMatch:      true,
		expSecret:     "key-1234567890abcdef1234567890abcdef",
	})
}

// ========================================
// MailChimp API Key Tests
// ========================================

func TestProcessor_MailChimpAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailChimpAPIKeyRegex,
		line:          xorDecode("HRwqHAgqIQkqHhonHRknMRsnGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaLhsPMTI="),
		expMatch:      true,
		expSecret:     xorDecode("GhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaGhkaLhsPMTI="),
	})
}

func TestProcessor_MailChimpAPIKey_US1(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailChimpAPIKeyRegex,
		line:          xorDecode("GRwqHRsnOhkfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfLhsPMQ=="),
		expMatch:      true,
		expSecret:     xorDecode("PxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfPxwfLhsPMQ=="),
	})
}

// ========================================
// Square Tokens Tests
// ========================================

func TestProcessor_SquareAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquareAccessTokenRegex,
		line:          xorDecode("GRgkFhUuHhgyFRglHRwnGQ4nJHcyGDouGDouGDouGDouGDouGDouGDouGDouGDouGDouGg=="),
		expMatch:      true,
		expSecret:     xorDecode("GRgyGDouHBwmGgcKCgoKCgoKCgoKCgoKCgoKCgoKCgoK"),
	})
}

func TestProcessor_SquareOAuthSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquareOAuthSecretRegex,
		line:          xorDecode("HBwnHRoKHRonKAkqHQwJOhonGRgyGQkqHAcKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCg=="),
		expMatch:      true,
		expSecret:     xorDecode("GRgyGQkqHAcKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCgoKCg=="),
	})
}

// ========================================
// PayPal Braintree Tests
// ========================================

func TestProcessor_PayPalBraintree_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PayPalBraintreeAccessTokenRegex,
		line:          `token = access_token$production$abcdef1234567890$12345678901234567890123456789012`,
		expMatch:      true,
		expSecret:     "access_token$production$abcdef1234567890$12345678901234567890123456789012",
	})
}

// ========================================
// LinkedIn Tests
// ========================================

func TestProcessor_LinkedInClientID_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinkedInClientIDRegex,
		line:          `linkedin_client_id = "abcdef123456"`,
		expMatch:      true,
		expSecret:     `"abcdef123456"`,
	})
}

func TestProcessor_LinkedInSecretKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinkedInSecretKeyRegex,
		line:          `LINKEDIN_SECRET="abcdef1234567890"`,
		expMatch:      true,
		expSecret:     `"abcdef1234567890"`,
	})
}

// ========================================
// NuGet API Key Tests
// ========================================

func TestProcessor_NuGetAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NuGetAPIKeyRegex,
		line:          `NUGET_API_KEY=oy2abcdefghijklmnopqrstuvwxyz1234567890abcdefg`,
		expMatch:      true,
		expSecret:     "oy2abcdefghijklmnopqrstuvwxyz1234567890abcdefg",
	})
}

// ========================================
// Twilio API Key Tests
// ========================================

func TestProcessor_TwilioAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwilioAPIKeyRegex,
		line:          xorDecode("FBgkGAkqGBguFhUqHAkKHBsnGRsxMRoyGDouGRouGDouHBsnGRoyGDouGRouHBwnHgw="),
		expMatch:      true,
		expSecret:     xorDecode("GBsxMRoyGDouGRouGDouHBsnGRoyGDouGRouHBwnHgw="),
	})
}

func TestProcessor_TwilioAPIKey_Lowercase(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwilioAPIKeyRegex,
		line:          xorDecode("GRwqHRsnOhokGBsrGRouGQkfKAgqIQkpHBwqHRwnHBwmHAkKIRozMToyMRoy"),
		expMatch:      true,
		expSecret:     xorDecode("GBsrGRouGQkfKAgqIQkpHBwqHRwnHBwmHAkKIRozMToyMRoy"),
	})
}

// ========================================
// Heroku API Key Tests
// ========================================

func TestProcessor_HerokuAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HerokuAPIKeyRegex,
		line:          `HEROKU_API_KEY=12345678-1234-1234-1234-123456789012`,
		expMatch:      true,
		expSecret:     "12345678-1234-1234-1234-123456789012",
	})
}

func TestProcessor_HerokuAPIKey_InText(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HerokuAPIKeyRegex,
		line:          `heroku api key is ABCDEF12-ABCD-ABCD-ABCD-ABCDEFABCDEF for production`,
		expMatch:      true,
		expSecret:     "ABCDEF12-ABCD-ABCD-ABCD-ABCDEFABCDEF",
	})
}

// ========================================
// GCP Service Account Tests
// ========================================

func TestProcessor_GCPServiceAccount_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GCPServiceAccountRegex,
		line: `{
  "type": "service_account",
  "project_id": "test-project",
  "private_key_id": "1234567890abcdef1234567890abcdef12345678"
}`,
		expMatch:  true,
		expSecret: "1234567890abcdef1234567890abcdef12345678",
	})
}

// ========================================
// Facebook OAuth Tests
// ========================================

func TestProcessor_FacebookOAuth_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookOAuthRegex,
		line:          `facebook_secret = "1234567890abcdef1234567890abcdef"`,
		expMatch:      true,
		expSecret:     `facebook_secret = "1234567890abcdef1234567890abcdef"`,
	})
}

// ========================================
// Twitter Tests
// ========================================

func TestProcessor_Twitter_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitterRegex,
		line:          `{"client_secret":"abcdefghijklmnopqrstuvwx"}`,
		expMatch:      true,
		expSecret:     `"client_secret":"abcdefghijklmnopqrstuvwx"`,
	})
}

// ========================================
// Generic Secret Tests
// ========================================

func TestProcessor_GenericSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GenericSecretRegex,
		line:          `my_secret = "abcdefghijklmnopqrstuvwxyz1234567"`,
		expMatch:      true,
		expSecret:     `secret = "abcdefghijklmnopqrstuvwxyz1234567"`,
	})
}

func TestProcessor_GenericSecret_CaseSensitive(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GenericSecretRegex,
		line:          `API_SECRET="ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012"`,
		expMatch:      true,
		expSecret:     `SECRET="ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789012"`,
	})
}

// ========================================
// URL Password Tests
// ========================================

func TestProcessor_URLPassword_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLPasswordRegex,
		line:          `DATABASE_URL=postgres://username:password123@localhost:5432/dbname`,
		expMatch:      true,
		expSecret:     "username:password123",
	})
}

func TestProcessor_URLPassword_HTTPS(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLPasswordRegex,
		line:          `url: https://admin:secret1234@api.example.com/v1/data`,
		expMatch:      true,
		expSecret:     "admin:secret1234",
	})
}

func TestProcessor_URLPassword_TooShort(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLPasswordRegex,
		line:          `https://usr:pwd@example.com`,
		expMatch:      false,
	})
}
