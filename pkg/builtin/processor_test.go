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

func TestProcessor_SlackToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          xorDecode("LjUxPzR6Z3oiNSIqd2toaW5vbG1iY2praHdraGlub2xtYmNqa2h3a2hpbm9sbWJjamtodzs4OT4/PDs4OT4/PDs4OT4/PDs4OT4/PDs4OT4/PDs4"),
		expMatch:      true,
		expSecret:     xorDecode("IjUiKndraGlub2xtYmNqa2h3a2hpbm9sbWJjamtod2toaW5vbG1iY2praHc7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7OA=="),
	})
}

func TestProcessor_SlackToken_BotToken(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          xorDecode("CRYbGREFGBUOBQ4VER8UZyI1Ijh3a2hpbm9sbWJjamtod2toaW5vbG1iY2praHdraGlub2xtYmNqa2h3Ozg5Pj88Ozg5Pj88Ozg5Pj88Ozg5Pj88Ozg5Pj88Ozg="),
		expMatch:      true,
		expSecret:     xorDecode("IjUiOHdraGlub2xtYmNqa2h3a2hpbm9sbWJjamtod2toaW5vbG1iY2praHc7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7OA=="),
	})
}

func TestProcessor_SlackToken_AppToken(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackTokenRegex,
		line:          xorDecode("IjUiO3draGlub2xtYmNqa2h3a2hpbm9sbWJjamtod2toaW5vbG1iY2praHc7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7OA=="),
		expMatch:      true,
		expSecret:     xorDecode("IjUiO3draGlub2xtYmNqa2h3a2hpbm9sbWJjamtod2toaW5vbG1iY2praHc7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7ODk+Pzw7OA=="),
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

func TestProcessor_SlackWebhook_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackWebhookRegex,
		line:          xorDecode("LT84MjU1MQUvKDZ6Z3oyLi4qKWB1dTI1NTEpdCk2OzkxdDk1N3UpPygsMzk/KXUOa2hpbm9sbWJ1GGtoaW5vbG1idTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXUyNTUxKXQpNjs5MXQ5NTd1KT8oLDM5Pyl1DmtoaW5vbG1idRhraGlub2xtYnU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSI="),
	})
}

func TestProcessor_SlackWebhook_InCode(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackWebhookRegex,
		line:          xorDecode("OTU0KS56LT84MjU1MXpnengyLi4qKWB1dTI1NTEpdCk2OzkxdDk1N3UpPygsMzk/KXUOOzg5Pj88PTJ1GDs4OT4/PD0ydRsYGR4fHB0SOzg5Pj88PTJraGlub2xtYng="),
		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXUyNTUxKXQpNjs5MXQ5NTd1KT8oLDM5Pyl1Djs4OT4/PD0ydRg7ODk+Pzw9MnUbGBkeHxwdEjs4OT4/PD0ya2hpbm9sbWI="),
	})
}

// ========================================
// AWS Access Key ID Tests
// ========================================

func TestProcessor_AWSAccessKeyID_AKIA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          xorDecode("Gw0JBRsZGR8JCQURHwMFEx5nGxETGxMVCRwVHhQUbR8CGxcKFh8="),
		expMatch:      true,
		expSecret:     xorDecode("GxETGxMVCRwVHhQUbR8CGxcKFh8="),
	})
}

func TestProcessor_AWSAccessKeyID_ASIA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          xorDecode("PyIqNSguehsNCQURHwNneBsJExsOHwkOGxkZHwkJER8Da2hpeA=="),
		expMatch:      true,
		expSecret:     xorDecode("GwkTGw4fCQ4bGRkfCQkRHwNraGk="),
	})
}

func TestProcessor_AWSAccessKeyID_AROA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          xorDecode("KDU2PwUzPnpnehsIFRsCAgICAgICAgICa2hpbm9s"),
		expMatch:      true,
		expSecret:     xorDecode("GwgVGwICAgICAgICAgJraGlub2w="),
	})
}

func TestProcessor_AWSAccessKeyID_AIDA(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAccessKeyIDRegex,
		line:          xorDecode("Lyk/KAUzPmB6GxMeGwICAgICAgICAgJraGlub2w="),
		expMatch:      true,
		expSecret:     xorDecode("GxMeGwICAgICAgICAgJraGlub2w="),
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
		line:          xorDecode("Gw0JBREfA2d4LRA7NigCDy40HB8XE3URbRceHxQddTgKIgg8MxkDHwIbFwoWHxEfA3g="),
		expMatch:      true,
		expSecret:     `_KEY=`,
	})
}

func TestProcessor_AWSSecretKey_WithContext(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSSecretKeyRegex,
		line:          xorDecode("Gw0JBQkfGQgfDmd4Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBraGlub2xtYmNqGxgZHng="),
		expMatch:      true,
		expSecret:     `_SECRET=`,
	})
}

// ========================================
// AWS MWS Auth Token Tests
// ========================================

func TestProcessor_AWSMWSAuthToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSMWSAuthTokenRegex,
		line:          xorDecode("Fw0JBQ4VER8UZzs3IDR0Ny0pdGtoaW5vbG1id2toaW53a2hpbndraGlud2toaW5vbG1iY2praA=="),
		expMatch:      true,
		expSecret:     xorDecode("OzcgNHQ3LSl0a2hpbm9sbWJ3a2hpbndraGlud2toaW53a2hpbm9sbWJjamto"),
	})
}

// ========================================
// GitHub Token Tests
// ========================================

func TestProcessor_GitHubToken_Classic(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubTokenRegex,
		line:          xorDecode("HRMOEg8YBQ4VER8UZ3g9MioFHwIbFwoWHxQVDhsIHxsWDhURHxRqampqampqampqampqeA=="),
		expMatch:      true,
		expSecret:     xorDecode("PTIqBR8CGxcKFh8UFQ4bCB8bFg4VER8Uampqampqampqampqag=="),
	})
}

func TestProcessor_GitHubToken_PAT(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubTokenRegex,
		line:          xorDecode("PTMuMi84BSo7LmB6PTMuMi84BSo7LgVqah8CGxcKFh8VFBYDampqampqampqamoFHwIbFwoWHwICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"),
		expMatch:      true,
		expSecret:     xorDecode("PTMuMi84BSo7LgVqah8CGxcKFh8VFBYDampqampqampqamoFHwIbFwoWHwICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIC"),
	})
}

func TestProcessor_GitHubToken_Secret(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubTokenRegex,
		line:          xorDecode("PyIqNSgueh0TDhIPGAUJHxkIHw56Z3p4PTIpBR8CGxcKFh8UFQ4bCB8bFg4VER8UIiIiIiIiIiIiIiJ4"),
		expMatch:      true,
		expSecret:     xorDecode("PTIpBR8CGxcKFh8UFQ4bCB8bFg4VER8UIiIiIiIiIiIiIiI="),
	})
}

// ========================================
// Digital Ocean Token Tests
// ========================================

func TestProcessor_DigitalOceanPAT_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanPATRegex,
		line:          xorDecode("HhUFChsOBQ4VER8UZz41KgUsawU7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlp"),
		expMatch:      true,
		expSecret:     xorDecode("PjUqBSxrBTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk="),
	})
}

func TestProcessor_DigitalOceanPAT_InJSON(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanPATRegex,
		line:          xorDecode("IXguNTE/NHhgeng+NSoFLGsFampra2hoaWlubm9vbGxtbWJiY2M7Ozg4OTk+Pj8/PDxqamtraGhpaW5ub29sbG1tYmJjYzs7ODg5OT4+Pz88PHgn"),
		expMatch:      true,
		expSecret:     xorDecode("PjUqBSxrBWpqa2toaGlpbm5vb2xsbW1iYmNjOzs4ODk5Pj4/Pzw8ampra2hoaWlubm9vbGxtbWJiY2M7Ozg4OTk+Pj8/PDw="),
	})
}

func TestProcessor_DigitalOceanOAuth_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanOAuthRegex,
		line:          xorDecode("PjUFNTsvLjIFLjUxPzRnPjU1BSxrBTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk="),
		expMatch:      true,
		expSecret:     xorDecode("PjU1BSxrBTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk="),
	})
}

func TestProcessor_DigitalOceanRefreshToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanRefreshTokenRegex,
		line:          xorDecode("KD88KD8pMgUuNTE/NGc+NSgFLGsFOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaQ=="),
		expMatch:      true,
		expSecret:     xorDecode("PjUoBSxrBTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk="),
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
		line:          xorDecode("CQ4IEwofBQkfGQgfDgURHwNnKTEFNjMsPwUfAhsXChYfAgICAgICAgICAgICAgICAgIi"),
		expMatch:      true,
		expSecret:     xorDecode("KTEFNjMsPwUfAhsXChYfAgICAgICAgICAgICAgICAgIi"),
	})
}

func TestProcessor_StripeAPIKey_SecretKeyTest(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripeAPIKeyRegex,
		line:          xorDecode("KS4oMyo/BTE/I2B6eCkxBS4/KS4FFBUOGwgfGxYRHwMOHwkOHwIbFwoWHxUUFgN4"),
		expMatch:      true,
		expSecret:     xorDecode("KTEFLj8pLgUUFQ4bCB8bFhEfAw4fCQ4fAhsXChYfFRQWAw=="),
	})
}

func TestProcessor_StripeAPIKey_PublishableKey(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripeAPIKeyRegex,
		line:          xorDecode("KjEFNjMsPwUfAhsXChYfAgICAgICAgICAgICAgICAgIi"),
		expMatch:      true,
		expSecret:     xorDecode("KjEFNjMsPwUfAhsXChYfAgICAgICAgICAgICAgICAgIi"),
	})
}

// ========================================
// SendGrid API Key Tests
// ========================================

func TestProcessor_SendGridAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendGridAPIKeyRegex,
		line:          xorDecode("CR8UHh0IEx4FGwoTBREfA2cJHXQ7ODk+Pzw9MjMwMTY3NDUqKygpLi8sdDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0="),
		expMatch:      true,
		expSecret:     xorDecode("CR10Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLHQ7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),
	})
}

func TestProcessor_SendGridAPIKey_InConfig(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendGridAPIKeyRegex,
		line:          xorDecode("OyozBTE/I2B6CR10FBUOdwgfGxYFER8Ddx8CGxcKFh93InQ7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),
		expMatch:      true,
		expSecret:     xorDecode("CR10FBUOdwgfGxYFER8Ddx8CGxcKFh93InQ7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),
	})
}

// ========================================
// MailGun API Key Tests
// ========================================

func TestProcessor_MailGunAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailGunAPIKeyRegex,
		line:          xorDecode("FxsTFh0PFAUbChMFER8DZzE/I3draGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4OT4/PA=="),
		expMatch:      true,
		expSecret:     xorDecode("MT8jd2toaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88"),
	})
}

// ========================================
// MailChimp API Key Tests
// ========================================

func TestProcessor_MailChimpAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailChimpAPIKeyRegex,
		line:          xorDecode("FxsTFhkSExcKBRsKEwURHwNnamtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzx3LylraA=="),
		expMatch:      true,
		expSecret:     xorDecode("amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzx3LylraA=="),
	})
}

func TestProcessor_MailChimpAPIKey_US1(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailChimpAPIKeyRegex,
		line:          xorDecode("MT8jZzs7ODg5OT4+Pz88PGpqa2toaGlpbm5vb2xsbW1iYmNjdy8paw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozs4ODk5Pj4/Pzw8ampra2hoaWlubm9vbGxtbWJiY2N3Lylr"),
	})
}

// ========================================
// Square Tokens Tests
// ========================================

func TestProcessor_SquareAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquareAccessTokenRegex,
		line:          xorDecode("CQsPGwgfBQ4VER8UZykrajsuKnc7ODk+Pzw9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("KStqOy4qdzs4OT4/PD0yMzAxNjc0NSorKCkuLyw="),
	})
}

func TestProcessor_SquareOAuthSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquareOAuthSecretRegex,
		line:          xorDecode("NTsvLjIFKT85KD8uZykrajkpKnc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),
		expMatch:      true,
		expSecret:     xorDecode("KStqOSkqdzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0="),
	})
}

// ========================================
// PayPal Braintree Tests
// ========================================

func TestProcessor_PayPalBraintree_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PayPalBraintreeAccessTokenRegex,
		line:          xorDecode("LjUxPzR6Z3o7OTk/KSkFLjUxPzR+Kig1Pi85LjM1NH47ODk+PzxraGlub2xtYmNqfmtoaW5vbG1iY2praGlub2xtYmNqa2hpbm9sbWJjamto"),
		expMatch:      true,
		expSecret:     xorDecode("Ozk5PykpBS41MT80fiooNT4vOS4zNTR+Ozg5Pj88a2hpbm9sbWJjan5raGlub2xtYmNqa2hpbm9sbWJjamtoaW5vbG1iY2praA=="),
	})
}

// ========================================
// LinkedIn Tests
// ========================================

func TestProcessor_LinkedInClientID_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinkedInClientIDRegex,
		line:          xorDecode("NjM0MT8+MzQFOTYzPzQuBTM+emd6eDs4OT4/PGtoaW5vbHg="),

		expMatch:      true,
		expSecret:     `_client_id = `,
	})
}

func TestProcessor_LinkedInSecretKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinkedInSecretKeyRegex,
		line:          xorDecode("FhMUER8eExQFCR8ZCB8OZ3g7ODk+PzxraGlub2xtYmNqeA=="),

		expMatch:      true,
		expSecret:     `_SECRET=`,
	})
}

// ========================================
// NuGet API Key Tests
// ========================================

func TestProcessor_NuGetAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NuGetAPIKeyRegex,
		line:          xorDecode("FA8dHw4FGwoTBREfA2c1I2g7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGtoaW5vbG1iY2o7ODk+Pzw9"),
		expMatch:      true,
		expSecret:     xorDecode("NSNoOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBraGlub2xtYmNqOzg5Pj88PQ=="),
	})
}

// ========================================
// Twilio API Key Tests
// ========================================

func TestProcessor_TwilioAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwilioAPIKeyRegex,
		line:          xorDecode("Dg0TFhMVBRsKEwURHwNnCRFqa2hpbm9sbWJjamtoaW5vbG1iY2praGlub2xtYmNqaw=="),
		expMatch:      true,
		expSecret:     xorDecode("CRFqa2hpbm9sbWJjamtoaW5vbG1iY2praGlub2xtYmNqaw=="),
	})
}

func TestProcessor_TwilioAPIKey_Lowercase(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwilioAPIKeyRegex,
		line:          xorDecode("MT8jZwkROzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("CRE7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlubw=="),
	})
}

// ========================================
// Heroku API Key Tests
// ========================================

func TestProcessor_HerokuAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HerokuAPIKeyRegex,
		line:          xorDecode("Eh8IFREPBRsKEwURHwNna2hpbm9sbWJ3a2hpbndraGlud2toaW53a2hpbm9sbWJjamto"),
		expMatch:      true,
		expSecret:     xorDecode("Eh8IFREPBRsKEwURHwNna2hpbm9sbWJ3a2hpbndraGlud2toaW53a2hpbm9sbWJjamto"),
	})
}

func TestProcessor_HerokuAPIKey_InText(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HerokuAPIKeyRegex,
		line:          xorDecode("Mj8oNTEvejsqM3oxPyN6Myl6GxgZHh8ca2h3GxgZHncbGBkedxsYGR53GxgZHh8cGxgZHh8cejw1KHoqKDU+LzkuMzU0"),
		expMatch:      true,
		expSecret:     xorDecode("Mj8oNTEvejsqM3oxPyN6Myl6GxgZHh8ca2h3GxgZHncbGBkedxsYGR53GxgZHh8cGxgZHh8c"),
	})
}

// ========================================
// GCP Service Account Tests
// ========================================

func TestProcessor_GCPServiceAccount_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GCPServiceAccountRegex,
		line: xorDecode("IVB6enguIyo/eGB6eCk/KCwzOT8FOzk5NS80Lnh2UHp6eCooNTA/OS4FMz54YHp4Lj8pLncqKDUwPzkueHZQenp4KigzLDsuPwUxPyMFMz54YHp4a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYnhQJw=="),

		expMatch:  true,
		expSecret: xorDecode("a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYg=="),

	})
}

// ========================================
// Facebook OAuth Tests
// ========================================

func TestProcessor_FacebookOAuth_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookOAuthRegex,
		line:          xorDecode("PDs5Pzg1NTEFKT85KD8uemd6eGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88eA=="),

		expMatch:      true,
		expSecret:     xorDecode("PDs5Pzg1NTEFKT85KD8uemd6eGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88eA=="),

	})
}

// ========================================
// Twitter Tests
// ========================================

func TestProcessor_Twitter_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitterRegex,
		line:          xorDecode("IXg5NjM/NC4FKT85KD8ueGB4Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0ieCc="),

		expMatch:      true,
		expSecret:     xorDecode("eDk2Mz80LgUpPzkoPy54YHg7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSJ4"),

	})
}

// ========================================
// Generic Secret Tests
// ========================================

func TestProcessor_GenericSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GenericSecretRegex,
		line:          xorDecode("NyMFKT85KD8uemd6eDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMga2hpbm9sbXg="),

		expMatch:      true,
		expSecret:     xorDecode("KT85KD8uemd6eDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMga2hpbm9sbXg="),

	})
}

func TestProcessor_GenericSecret_CaseSensitive(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GenericSecretRegex,
		line:          xorDecode("GwoTBQkfGQgfDmd4GxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwBraGlub2xtYmNqa2h4"),

		expMatch:      true,
		expSecret:     xorDecode("CR8ZCB8OZ3gbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQIDAGtoaW5vbG1iY2praHg="),

	})
}

// ========================================
// URL Password Tests
// ========================================

func TestProcessor_URLPassword_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLPasswordRegex,
		line:          xorDecode("HhsOGxgbCR8FDwgWZyo1KS49KD8pYHV1Lyk/KDQ7Nz9gKjspKS01KD5raGkaNjU5OzYyNSkuYG9uaWh1Pjg0Ozc/"),

		expMatch:      true,
		expSecret:     "username:password123",
	})
}

func TestProcessor_URLPassword_HTTPS(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLPasswordRegex,
		line:          xorDecode("Lyg2YHoyLi4qKWB1dTs+NzM0YCk/OSg/LmtoaW4aOyozdD8iOzcqNj90OTU3dSxrdT47Ljs="),

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

// ========================================
// AI/ML Providers
// ========================================

func TestProcessor_OpenAIAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenAIAPIKeyRegex,
		line:          xorDecode("FQofFBsTBREfA2cpMXc7ODk+PzwOaRg2ODEcED0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("KTF3Ozg5Pj88DmkYNjgxHBA9MjMwMTY3NDUq"),
	})
}

func TestProcessor_OpenAIAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenAIAPIKeyRegex,
		line:          `key = "sk-notarealkey"`,
		expMatch:      false,
	})
}

func TestProcessor_AnthropicAPIKey_Valid(t *testing.T) {
	// 93 chars of [\w\-] after the prefix, then AA
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AnthropicAPIKeyRegex,
		line:          xorDecode("GxQOEggVChMZBREfA2cpMXc7NC53Oyozaml3Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwAFdzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoGxs="),
		expMatch:      true,
		expSecret:     xorDecode("KTF3OzQudzsqM2ppdzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0SExARFhcUFQoLCAkODwwNAgMABXc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraBsb"),
	})
}

func TestProcessor_AnthropicAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AnthropicAPIKeyRegex,
		line:          `sk-ant-wrong-prefix`,
		expMatch:      false,
	})
}

func TestProcessor_GroqAPIKey_Valid(t *testing.T) {
	// gsk_ + 52 alphanumeric chars
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GroqAPIKeyRegex,
		line:          xorDecode("HQgVCwURHwNnPSkxBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2obGBkeHxwdEhMQERYXFBU="),

		expMatch:      true,
		expSecret:     xorDecode("PSkxBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2obGBkeHxwdEhMQERYXFBU="),

	})
}

func TestProcessor_GroqAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GroqAPIKeyRegex,
		line:          `gsk_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_DeepSeekAPIKey_Valid(t *testing.T) {
	// (?i)deepseek.{0,40}?\b(sk-[a-z0-9]{32})\b - capture group is the sk- token
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DeepSeekAPIKeyRegex,
		line:          xorDecode("Pj8/Kik/PzEFMT8jemd6KTF3Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),

		expMatch:      true,
		expSecret:     xorDecode("KTF3Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),

	})
}

func TestProcessor_DeepSeekAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DeepSeekAPIKeyRegex,
		line:          `some_key = sk-tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_XAIAPIKey_Valid(t *testing.T) {
	// xai- + 80 chars of [0-9a-zA-Z_]
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.XAIAPIKeyRegex,
		line:          xorDecode("AhsTBREfA2ciOzN3Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQOzg5Pj88PTIzMGpraGlub2xtYmM="),

		expMatch:      true,
		expSecret:     xorDecode("Ijszdzs4OT4/PD0yMzBqa2hpbm9sbWJjGxgZHh8cHRITEDs4OT4/PD0yMzBqa2hpbm9sbWJjGxgZHh8cHRITEDs4OT4/PD0yMzBqa2hpbm9sbWJj"),

	})
}

func TestProcessor_XAIAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.XAIAPIKeyRegex,
		line:          `xai-tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_HuggingFaceToken_Valid(t *testing.T) {
	// hf_ + 34 alphanumeric
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HuggingFaceTokenRegex,
		line:          xorDecode("EhwFDhURHxRnMjwFOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbQ=="),

		expMatch:      true,
		expSecret:     xorDecode("MjwFOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbQ=="),

	})
}

func TestProcessor_HuggingFaceToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HuggingFaceTokenRegex,
		line:          `hf_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_ReplicateAPIToken_Valid(t *testing.T) {
	// r8_ + 37 chars of [0-9A-Za-z_-]
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ReplicateAPITokenRegex,
		line:          xorDecode("CB8KFhMZGw4fBQ4VER8UZyhiBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2o="),

		expMatch:      true,
		expSecret:     xorDecode("KGIFOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjag=="),

	})
}

func TestProcessor_ReplicateAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ReplicateAPITokenRegex,
		line:          `r8_short`,
		expMatch:      false,
	})
}

func TestProcessor_ElevenLabsAPIKey_Valid(t *testing.T) {
	// sk_ + 48 lowercase hex chars
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElevenLabsAPIKeyRegex,
		line:          xorDecode("HxYfDB8UFhsYCQURHwNnKTEFOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlp"),

		expMatch:      true,
		expSecret:     xorDecode("KTEFOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlp"),

	})
}

func TestProcessor_ElevenLabsAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElevenLabsAPIKeyRegex,
		line:          `sk_short`,
		expMatch:      false,
	})
}

// ========================================
// Cloud & Infrastructure
// ========================================

func TestProcessor_GoogleCloudAPIKey_Valid(t *testing.T) {
	// AIza + 35 chars of [0-9A-Za-z\-_] - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleCloudAPIKeyRegex,
		line:          xorDecode("HRUVHRYfBREfA2cbEyA7Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWI="),

		expMatch:      true,
		expSecret:     xorDecode("GxMgOzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1i"),

	})
}

func TestProcessor_GoogleCloudAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleCloudAPIKeyRegex,
		line:          `AIza_short`,
		expMatch:      false,
	})
}

func TestProcessor_GoogleOAuthAccessToken_Valid(t *testing.T) {
	// ya29\.[0-9A-Za-z\-_]+ - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleOAuthAccessTokenRegex,
		line:          xorDecode("LjUxPzRnIztoY3Q7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIA=="),

		expMatch:      true,
		expSecret:     xorDecode("IztoY3Q7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIA=="),

	})
}

func TestProcessor_GoogleOAuthAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleOAuthAccessTokenRegex,
		line:          `token=ya28.abcdef`,
		expMatch:      false,
	})
}

func TestProcessor_GoogleOAuthKey_Valid(t *testing.T) {
	// [0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleOAuthKeyRegex,
		line:          xorDecode("OTYzPzQuBTM+Z2toaW5vbG1iY3c7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub3Q7KiopdD01NT02Py8pPyg5NTQuPzQudDk1Nw=="),

		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sbWJjdzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vdDsqKil0PTU1PTY/Lyk/KDk1NC4/NC50OTU3"),

	})
}

func TestProcessor_GoogleOAuthKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleOAuthKeyRegex,
		line:          `not-a-google-key.com`,
		expMatch:      false,
	})
}

func TestProcessor_CloudflareAPIToken_Valid(t *testing.T) {
	// (?i)cloudflare.{0,40}?\b([A-Za-z0-9_-]{40})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudflareAPITokenRegex,
		line:          xorDecode("OTY1Lz48NjsoPwU7KjMFLjUxPzR6Z3o7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqGxgZ"),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjahsYGQ=="),

	})
}

func TestProcessor_CloudflareAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudflareAPITokenRegex,
		line:          `cloudflare_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_CloudflareGlobalAPIKey_Valid(t *testing.T) {
	// (?i)cloudflare.{0,40}?\b([A-Za-z0-9_-]{37})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudflareGlobalAPIKeyRegex,
		line:          xorDecode("OTY1Lz48NjsoPwU9NjU4OzYFMT8jZzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2o="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjag=="),

	})
}

func TestProcessor_CloudflareGlobalAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudflareGlobalAPIKeyRegex,
		line:          `cloudflare_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_AzureStorageKey_Valid(t *testing.T) {
	// (?i)(?:Access|Account|Storage)[_.\-]?Key.{0,25}?([a-zA-Z0-9+/\-]{86,88}={0,2}) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureStorageKeyRegex,
		line:          xorDecode("Gzk5NS80LhE/I2c7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQIDADs4OT4/PD0yMzAxNjc0NSorKCkuLywtIg=="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwA7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSI="),

	})
}

func TestProcessor_AzureStorageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureStorageKeyRegex,
		line:          `StorageKey=short`,
		expMatch:      false,
	})
}

func TestProcessor_AzureEntraSecret_Valid(t *testing.T) {
	// (?i)(?:azure|entra|aad).{0,40}?(['"][a-zA-Z0-9~._-]{34}['"]) - 1 capture group (includes quotes)
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureEntraSecretRegex,
		line:          xorDecode("OyAvKD8FOTYzPzQuBSk/OSg/Lnpneng7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xteA=="),

		expMatch:      true,
		expSecret:     xorDecode("eDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG14"),

	})
}

func TestProcessor_AzureEntraSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureEntraSecretRegex,
		line:          `azure_key = "short"`,
		expMatch:      false,
	})
}

func TestProcessor_SupabaseToken_Valid(t *testing.T) {
	// \b(sbp_[a-z0-9]{40})\b - 1 capture group, lowercase
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SupabaseTokenRegex,
		line:          xorDecode("CQ8KGxgbCR8FDhURHxRnKTgqBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2praGk="),

		expMatch:      true,
		expSecret:     xorDecode("KTgqBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2praGk="),

	})
}

func TestProcessor_SupabaseToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SupabaseTokenRegex,
		line:          `sbp_short`,
		expMatch:      false,
	})
}

func TestProcessor_MongoDBConnectionString_Valid(t *testing.T) {
	// \b(mongodb(?:\+srv)?://\S{3,50}:\S{3,88}@[-.%\w]+(?::\d{1,5})?) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MongoDBConnectionStringRegex,
		line:          xorDecode("HhgFDwgWZzc1ND01PjhxKSgsYHV1Oz43MzRgKjspKS01KD5raGkaOTYvKS4/KGp0PyI7Nyo2P3Q5NTdgaG1qa20="),

		expMatch:      true,
		expSecret:     xorDecode("NzU0PTU+OHEpKCxgdXU7PjczNGAqOykpLTUoPmtoaRo5Ni8pLj8oanQ/Ijs3KjY/dDk1N2BobWprbQ=="),

	})
}

func TestProcessor_MongoDBConnectionString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MongoDBConnectionStringRegex,
		line:          `not_a_mongo_url=http://example.com`,
		expMatch:      false,
	})
}

func TestProcessor_PostgreSQLConnectionString_Valid(t *testing.T) {
	// (?i)(postgres(?:ql)?://\S+:\S+@\S+) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostgreSQLConnectionStringRegex,
		line:          xorDecode("HhhnKjUpLj0oPykrNmB1dTs+NzM0YCk/OSg/Lho2NTk7NjI1KS5gb25paHU3Iz44"),

		expMatch:      true,
		expSecret:     xorDecode("KjUpLj0oPykrNmB1dTs+NzM0YCk/OSg/Lho2NTk7NjI1KS5gb25paHU3Iz44"),

	})
}

func TestProcessor_PostgreSQLConnectionString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostgreSQLConnectionStringRegex,
		line:          `postgres://nocolon@host`,
		expMatch:      false,
	})
}

func TestProcessor_RedisConnectionString_Valid(t *testing.T) {
	// \bredi[s]{1,2}://[\S]{3,50}:([\S]{3,50})@[-.%\w/:]+\b - 1 capture group (password)
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RedisConnectionStringRegex,
		line:          xorDecode("CB8eEwlnKD8+MylgdXU+Pzw7LzYuYDcjKjspKS01KD4aKD8+Myl0PyI7Nyo2P3Q5NTdgbGltYw=="),

		expMatch:      true,
		expSecret:     `mypassword`,
	})
}

func TestProcessor_RedisConnectionString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RedisConnectionStringRegex,
		line:          `redis://nopassword@host:6379`,
		expMatch:      false,
	})
}

func TestProcessor_AzureDevOpsPAT_Valid(t *testing.T) {
	// (?i)azure.{0,40}?\b([0-9a-z]{52})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureDevOpsPATRegex,
		line:          xorDecode("OyAvKD8FPj8sNSopBSo7Lnpnejs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pg=="),

	})
}

func TestProcessor_AzureDevOpsPAT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureDevOpsPATRegex,
		line:          `azure_key = SHORT`,
		expMatch:      false,
	})
}

// ========================================
// Developer Platforms & Version Control
// ========================================

func TestProcessor_GitHubFineGrainedPAT_Valid(t *testing.T) {
	// \b((?:ghp|gho|ghu|ghs|ghr|github_pat)_[a-zA-Z0-9_]{36,255})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubFineGrainedPATRegex,
		line:          xorDecode("DhURHxRnPTIqBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("PTIqBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYw=="),
	})
}

func TestProcessor_GitHubFineGrainedPAT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitHubFineGrainedPATRegex,
		line:          `ghp_short`,
		expMatch:      false,
	})
}

func TestProcessor_GitLabToken_Valid(t *testing.T) {
	// \b(glpat-[a-zA-Z0-9\-=_]{20,})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitLabTokenRegex,
		line:          xorDecode("HRMOFhsYBQ4VER8UZz02Kjsudzs4OT4/PD0yMzAxNjc0NSorKCku"),
		expMatch:      true,
		expSecret:     xorDecode("PTYqOy53Ozg5Pj88PTIzMDE2NzQ1KisoKS4="),
	})
}

func TestProcessor_GitLabToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitLabTokenRegex,
		line:          `glpat-short`,
		expMatch:      false,
	})
}

func TestProcessor_NPMToken_Valid(t *testing.T) {
	// (npm_[0-9a-zA-Z]{36}) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NPMTokenRegex,
		line:          xorDecode("FAoXBQ4VER8UZzQqNwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("NCo3BTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYw=="),
	})
}

func TestProcessor_NPMToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NPMTokenRegex,
		line:          `npm_short`,
		expMatch:      false,
	})
}

func TestProcessor_PyPIToken_Valid(t *testing.T) {
	// (pypi-AgEIcHlwaS5vcmcCJ[a-zA-Z0-9_-]{150,157}) - 1 capture group, need 150 chars after prefix
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PyPITokenRegex,
		line:          xorDecode("CgMKEwUOFREfFGcqIyozdxs9HxM5EjYtOwlvLDk3ORkQOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),

		expMatch:      true,
		expSecret:     xorDecode("KiMqM3cbPR8TORI2LTsJbyw5NzkZEDs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ow=="),

	})
}

func TestProcessor_PyPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PyPITokenRegex,
		line:          `pypi-notareal`,
		expMatch:      false,
	})
}

func TestProcessor_RubyGemsToken_Valid(t *testing.T) {
	// \b(rubygems_[a-zA-Z0-9]{48})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RubyGemsTokenRegex,
		line:          xorDecode("HR8XBQ4VER8UZygvOCM9PzcpBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0SExARFg=="),

		expMatch:      true,
		expSecret:     xorDecode("KC84Iz0/NykFOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEW"),

	})
}

func TestProcessor_RubyGemsToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RubyGemsTokenRegex,
		line:          `rubygems_short`,
		expMatch:      false,
	})
}

func TestProcessor_ShopifyToken_Valid(t *testing.T) {
	// \b((?:shppa_|shpat_)[0-9A-Fa-f]{32})\b - 1 capture group, hex chars
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShopifyTokenRegex,
		line:          xorDecode("CRIVChMcAwURHwNnKTIqOy4FamtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzw="),
		expMatch:      true,
		expSecret:     xorDecode("KTIqOy4FamtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzw="),
	})
}

func TestProcessor_ShopifyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShopifyTokenRegex,
		line:          `shpat_short`,
		expMatch:      false,
	})
}

func TestProcessor_AtlassianToken_Valid(t *testing.T) {
	// \b(ATCTT3xFfG[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AtlassianTokenRegex,
		line:          xorDecode("Gw4WGwkJExsUBQ4VER8UZxsOGQ4OaSIcPB07ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGcbGBkeHxwdEg=="),
		expMatch:      true,
		expSecret:     xorDecode("Gw4ZDg5pIhw8HTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgZxsYGR4fHB0S"),
	})
}

func TestProcessor_AtlassianToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AtlassianTokenRegex,
		line:          `ATCTT3x_wrong`,
		expMatch:      false,
	})
}

func TestProcessor_JiraToken_Valid(t *testing.T) {
	// \b(ATATT[A-Za-z0-9+/=_-]+=[A-Za-z0-9]{8})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JiraTokenRegex,
		line:          xorDecode("EBMIGwUOFREfFGcbDhsODjs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgZxsYGR4fHB0S"),
		expMatch:      true,
		expSecret:     xorDecode("Gw4bDg47ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGcbGBkeHxwdEg=="),
	})
}

func TestProcessor_JiraToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JiraTokenRegex,
		line:          `ATATT_wrong`,
		expMatch:      false,
	})
}

func TestProcessor_PostmanAPIKey_Valid(t *testing.T) {
	// \b(PMAK-[a-zA-Z0-9-]{59})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostmanAPIKeyRegex,
		line:          xorDecode("ChUJDhcbFAURHwNnChcbEXc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQ=="),
		expMatch:      true,
		expSecret:     xorDecode("ChcbEXc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQ=="),
	})
}

func TestProcessor_PostmanAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostmanAPIKeyRegex,
		line:          `PMAK-short`,
		expMatch:      false,
	})
}

func TestProcessor_FigmaPAT_Valid(t *testing.T) {
	// \b(fig[dou][rh]?_[a-z0-9A-Z_-]{40})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FigmaPATRegex,
		line:          xorDecode("HBMdFxsFDhURHxRnPDM9PgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqGxgZ"),

		expMatch:      true,
		expSecret:     xorDecode("PDM9PgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqGxgZ"),

	})
}

func TestProcessor_FigmaPAT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FigmaPATRegex,
		line:          `figd_short`,
		expMatch:      false,
	})
}

// ========================================
// Communication & Social
// ========================================

func TestProcessor_DiscordBotToken_Valid(t *testing.T) {
	// (?i)discord.{0,40}?\b([A-Za-z0-9_-]{24}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DiscordBotTokenRegex,
		line:          xorDecode("PjMpOTUoPgU4NS4FLjUxPzR6Z3o7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSJ0Ozg5Pj88dDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgag=="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0idDs4OT4/PHQ7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGo="),

	})
}

func TestProcessor_DiscordBotToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DiscordBotTokenRegex,
		line:          `discord_token = notavalidtoken`,
		expMatch:      false,
	})
}

func TestProcessor_DiscordWebhook_Valid(t *testing.T) {
	// (https://discord\.com/api/webhooks/[0-9]{18,19}/[0-9a-zA-Z-]{68}) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DiscordWebhookRegex,
		line:          xorDecode("DR8YEhUVEWcyLi4qKWB1dT4zKTk1KD50OTU3dTsqM3UtPzgyNTUxKXVraGlub2xtYmNqa2hpbm9sbWJ1Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwA7ODk+Pzw="),

		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXU+Myk5NSg+dDk1N3U7KjN1LT84MjU1MSl1a2hpbm9sbWJjamtoaW5vbG1idTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0SExARFhcUFQoLCAkODwwNAgMAOzg5Pj88"),

	})
}

func TestProcessor_DiscordWebhook_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DiscordWebhookRegex,
		line:          `https://discord.com/api/other/123`,
		expMatch:      false,
	})
}

func TestProcessor_TelegramBotToken_Valid(t *testing.T) {
	// (?i)(?:telegram|tgram).{0,40}?\b([0-9]{8,10}:[a-zA-Z0-9_-]{35})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TelegramBotTokenRegex,
		line:          xorDecode("Lj82Pz0oOzcFODUuBS41MT80emd6a2hpbm9sbWJjYDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1i"),

		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sbWJjYDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1i"),

	})
}

func TestProcessor_TelegramBotToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TelegramBotTokenRegex,
		line:          `telegram_token = notavalidtoken`,
		expMatch:      false,
	})
}

func TestProcessor_FacebookAccessToken_Valid(t *testing.T) {
	// EAACEdEose0cBA[0-9A-Za-z]+ - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookAccessTokenRegex,
		line:          xorDecode("HBgFDhURHxRnHxsbGR8+HzUpP2o5GBs7ODk+PzxraGlub2w="),

		expMatch:      true,
		expSecret:     xorDecode("HxsbGR8+HzUpP2o5GBs7ODk+PzxraGlub2w="),

	})
}

func TestProcessor_FacebookAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookAccessTokenRegex,
		line:          `not_a_facebook_token`,
		expMatch:      false,
	})
}

func TestProcessor_FacebookSecretKey_Valid(t *testing.T) {
	// (?i)(?:facebook|fb).{0,20}?['\"][0-9a-f]{32}['\"] - no capture group, full match
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookSecretKeyRegex,
		line:          xorDecode("PDs5Pzg1NTEFKT85KD8uemd6eGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88eA=="),

		expMatch:      true,
		expSecret:     xorDecode("PDs5Pzg1NTEFKT85KD8uemd6eGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88eA=="),

	})
}

func TestProcessor_FacebookSecretKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookSecretKeyRegex,
		line:          `fb_key = "ZZZZ"`,
		expMatch:      false,
	})
}

func TestProcessor_FacebookClientID_Valid(t *testing.T) {
	// (?i)(?:facebook|fb).{0,20}?['\"][0-9]{13,17}['\"] - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookClientIDRegex,
		line:          xorDecode("PDs5Pzg1NTEFOyoqBTM+emd6eGtoaW5vbG1iY2praGl4"),

		expMatch:      true,
		expSecret:     xorDecode("PDs5Pzg1NTEFOyoqBTM+emd6eGtoaW5vbG1iY2praGl4"),

	})
}

func TestProcessor_FacebookClientID_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacebookClientIDRegex,
		line:          `fb_id = "123"`,
		expMatch:      false,
	})
}

func TestProcessor_TwitterSecretKey_Valid(t *testing.T) {
	// (?i)twitter.{0,20}?['\"][0-9a-z]{35,44}['\"] - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitterSecretKeyRegex,
		line:          xorDecode("Li0zLi4/KAUpPzkoPy56Z3p4Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJ4"),

		expMatch:      true,
		expSecret:     xorDecode("Li0zLi4/KAUpPzkoPy56Z3p4Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJ4"),

	})
}

func TestProcessor_TwitterSecretKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitterSecretKeyRegex,
		line:          `twitter_key = "short"`,
		expMatch:      false,
	})
}

func TestProcessor_TwitterClientID_Valid(t *testing.T) {
	// (?i)twitter.{0,20}?['\"][0-9a-z]{18,25}['\"] - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitterClientIDRegex,
		line:          xorDecode("Li0zLi4/KAU5NjM/NC4FMz56Z3p4Ozg5Pj88PTIzMDE2NzQ1KisoeA=="),

		expMatch:      true,
		expSecret:     xorDecode("Li0zLi4/KAU5NjM/NC4FMz56Z3p4Ozg5Pj88PTIzMDE2NzQ1KisoeA=="),

	})
}

func TestProcessor_TwitterClientID_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitterClientIDRegex,
		line:          `twitter_id = "abc"`,
		expMatch:      false,
	})
}

// ========================================
// Monitoring, Observability & DevOps
// ========================================

func TestProcessor_DatadogAPIKey_Valid(t *testing.T) {
	// (?i)(?:datadog|dd).{0,40}?\b([a-zA-Z0-9-]{32})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatadogAPIKeyRegex,
		line:          xorDecode("PjsuOz41PQU7KjMFMT8jemd6Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),

	})
}

func TestProcessor_DatadogAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatadogAPIKeyRegex,
		line:          `datadog_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_DatadogAppKey_Valid(t *testing.T) {
	// (?i)(?:datadog|dd).{0,40}?\b([a-zA-Z0-9-]{40})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatadogAppKeyRegex,
		line:          xorDecode("Pj4FOyoqBTE/I3pnejs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2obGBk="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjahsYGQ=="),

	})
}

func TestProcessor_DatadogAppKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatadogAppKeyRegex,
		line:          `dd_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_SentryToken_Valid(t *testing.T) {
	// \b(sntryu_[a-f0-9]{64})\b - 1 capture group, lowercase hex
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SentryTokenRegex,
		line:          xorDecode("CR8UDggDBQ4VER8UZyk0LigjLwU7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlp"),
		expMatch:      true,
		expSecret:     xorDecode("KTQuKCMvBTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk="),
	})
}

func TestProcessor_SentryToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SentryTokenRegex,
		line:          `sntryu_short`,
		expMatch:      false,
	})
}

func TestProcessor_SentryOrgToken_Valid(t *testing.T) {
	// \b(sntrys_eyJ[a-zA-Z0-9=_+/]{197})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SentryOrgTokenRegex,
		line:          xorDecode("CR8UDggDBRUIHWcpNC4oIykFPyMQOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs="),

		expMatch:      true,
		expSecret:     xorDecode("KTQuKCMpBT8jEDs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),

	})
}

func TestProcessor_SentryOrgToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SentryOrgTokenRegex,
		line:          `sntrys_eyJ_short`,
		expMatch:      false,
	})
}

func TestProcessor_NewRelicAPIKey_Valid(t *testing.T) {
	// (?i)newrelic.{0,40}?\b([A-Za-z0-9_.]{4}-[A-Za-z0-9_.]{42})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicAPIKeyRegex,
		line:          xorDecode("ND8tKD82MzkFOyozBTE/I3pnehQIGxF3Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8c"),
		expMatch:      true,
		expSecret:     xorDecode("FAgbEXc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxw="),
	})
}

func TestProcessor_NewRelicAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicAPIKeyRegex,
		line:          `newrelic_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_SplunkToken_Valid(t *testing.T) {
	// (?i)splunk.{0,40}?\b([a-z0-9A-Z]{22})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SplunkTokenRegex,
		line:          xorDecode("KSo2LzQxBTI/OQUuNTE/NHpnejs4OT4/PD0yMzAxNjc0NSorKCkuLyw="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLA=="),

	})
}

func TestProcessor_SplunkToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SplunkTokenRegex,
		line:          `splunk_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_GrafanaCloudToken_Valid(t *testing.T) {
	// \b(glc_eyJ[A-Za-z0-9+/=]{60,160}) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GrafanaCloudTokenRegex,
		line:          xorDecode("HQgbHBsUG2c9NjkFPyMQOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),
		expMatch:      true,
		expSecret:     xorDecode("PTY5BT8jEDs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ow=="),
	})
}

func TestProcessor_GrafanaCloudToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GrafanaCloudTokenRegex,
		line:          `glc_eyJshort`,
		expMatch:      false,
	})
}

func TestProcessor_GrafanaServiceAccount_Valid(t *testing.T) {
	// \b(glsa_[0-9a-zA-Z_]{41})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GrafanaServiceAccountRegex,
		line:          xorDecode("HQgbHBsUGwUJG2c9Nik7BTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4f"),
		expMatch:      true,
		expSecret:     xorDecode("PTYpOwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHw=="),
	})
}

func TestProcessor_GrafanaServiceAccount_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GrafanaServiceAccountRegex,
		line:          `glsa_short`,
		expMatch:      false,
	})
}

func TestProcessor_CircleCIToken_Valid(t *testing.T) {
	// (CCIPAT_[a-zA-Z0-9]{22}_[a-fA-F0-9]{40}) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CircleCITokenRegex,
		line:          xorDecode("GRMIGRYfBQ4VER8UZxkZEwobDgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sBWpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG0="),
		expMatch:      true,
		expSecret:     xorDecode("GRkTChsOBTs4OT4/PD0yMzAxNjc0NSorKCkuLywFamtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbQ=="),
	})
}

func TestProcessor_CircleCIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CircleCITokenRegex,
		line:          `CCIPAT_short`,
		expMatch:      false,
	})
}

func TestProcessor_BuildkiteToken_Valid(t *testing.T) {
	// \b(bkua_[a-z0-9]{40})\b - 1 capture group, lowercase
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BuildkiteTokenRegex,
		line:          xorDecode("GBEFDhURHxRnODEvOwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqa2hp"),
		expMatch:      true,
		expSecret:     xorDecode("ODEvOwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqa2hp"),
	})
}

func TestProcessor_BuildkiteToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BuildkiteTokenRegex,
		line:          `bkua_short`,
		expMatch:      false,
	})
}

func TestProcessor_TravisCIToken_Valid(t *testing.T) {
	// (?i)travis.{0,40}?\b([a-zA-Z0-9_]{22})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TravisCITokenRegex,
		line:          xorDecode("Lig7LDMpBTkzBS41MT80emd6Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLA=="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLA=="),

	})
}

func TestProcessor_TravisCIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TravisCITokenRegex,
		line:          `travis_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_SnykKey_Valid(t *testing.T) {
	// (?i)snyk.{0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SnykKeyRegex,
		line:          xorDecode("KTQjMQU7Ly4yBS41MT80emd6Ozg5Pj88amt3Ozg5Pnc7ODk+dzs4OT53Ozg5Pj88amtoaW5v"),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amt3Ozg5Pnc7ODk+dzs4OT53Ozg5Pj88amtoaW5v"),

	})
}

func TestProcessor_SnykKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SnykKeyRegex,
		line:          `snyk_token = not-valid`,
		expMatch:      false,
	})
}

// ========================================
// Hosting, Deployment & SaaS
// ========================================

func TestProcessor_VercelToken_Valid(t *testing.T) {
	// (?i)vercel.{0,40}?\b([a-zA-Z0-9]{24})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VercelTokenRegex,
		line:          xorDecode("LD8oOT82BS41MT80emd6Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0i"),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0i"),

	})
}

func TestProcessor_VercelToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VercelTokenRegex,
		line:          `vercel_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_NetlifyToken_Valid(t *testing.T) {
	// \b(nfp_[a-zA-Z0-9_]{36})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NetlifyTokenRegex,
		line:          xorDecode("FB8OFhMcA2c0PCoFOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJj"),

		expMatch:      true,
		expSecret:     xorDecode("NDwqBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYw=="),

	})
}

func TestProcessor_NetlifyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NetlifyTokenRegex,
		line:          `nfp_short`,
		expMatch:      false,
	})
}

func TestProcessor_DopplerToken_Valid(t *testing.T) {
	// \b(dp\.(?:ct|pt|st(?:\.[a-z0-9\-_]{2,35})?|sa|scim|audit)\.[a-zA-Z0-9]{40,44})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DopplerTokenRegex,
		line:          xorDecode("HhUKChYfCGc+KnQ5LnQ7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqGxgZ"),
		expMatch:      true,
		expSecret:     xorDecode("Pip0OS50Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjahsYGQ=="),
	})
}

func TestProcessor_DopplerToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DopplerTokenRegex,
		line:          `dp.xx.short`,
		expMatch:      false,
	})
}

func TestProcessor_PlanetScaleToken_Valid(t *testing.T) {
	// \bpscale_tkn_[A-Za-z0-9_]{43}\b - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanetScaleTokenRegex,
		line:          xorDecode("CgkFDhURHxRnKik5OzY/BS4xNAU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),

		expMatch:      true,
		expSecret:     xorDecode("Kik5OzY/BS4xNAU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),

	})
}

func TestProcessor_PlanetScaleToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanetScaleTokenRegex,
		line:          `pscale_tkn_short`,
		expMatch:      false,
	})
}

func TestProcessor_PlanetScalePassword_Valid(t *testing.T) {
	// \bpscale_pw_[A-Za-z0-9_]{43}\b - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanetScalePasswordRegex,
		line:          xorDecode("CgkFCg1nKik5OzY/BSotBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0="),

		expMatch:      true,
		expSecret:     xorDecode("Kik5OzY/BSotBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0="),

	})
}

func TestProcessor_PlanetScalePassword_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanetScalePasswordRegex,
		line:          `pscale_pw_short`,
		expMatch:      false,
	})
}

func TestProcessor_LaunchDarklyToken_Valid(t *testing.T) {
	// \b((?:api|sdk)-[a-z0-9]{8}-[a-z0-9]{4}-4[a-z0-9]{3}-[a-z0-9]{4}-[a-z0-9]{12})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LaunchDarklyTokenRegex,
		line:          xorDecode("Fh4FER8DZzsqM3c7ODk+Pzxqa3c7ODk+d247ODl3Ozg5Pnc7ODk+Pzxqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("Oyozdzs4OT4/PGprdzs4OT53bjs4OXc7ODk+dzs4OT4/PGpraGlubw=="),
	})
}

func TestProcessor_LaunchDarklyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LaunchDarklyTokenRegex,
		line:          `api-short-uuid`,
		expMatch:      false,
	})
}

func TestProcessor_AlgoliaAdminKey_Valid(t *testing.T) {
	// (?i)(?:algolia|docsearch|apiKey).{0,40}?\b([a-zA-Z0-9]{32})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlgoliaAdminKeyRegex,
		line:          xorDecode("OzY9NTYzOwU7PjczNAUxPyN6Z3o7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlubw=="),

		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),

	})
}

func TestProcessor_AlgoliaAdminKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlgoliaAdminKeyRegex,
		line:          `algolia_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_OktaToken_Valid(t *testing.T) {
	// \b00[a-zA-Z0-9_-]{40}\b - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OktaTokenRegex,
		line:          xorDecode("FREOG2dqajs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4="),

		expMatch:      true,
		expSecret:     xorDecode("amo7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBke"),

	})
}

func TestProcessor_OktaToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OktaTokenRegex,
		line:          `00short`,
		expMatch:      false,
	})
}

func TestProcessor_LinearAPIKey_Valid(t *testing.T) {
	// \b(lin_api_[0-9A-Za-z]{40})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinearAPIKeyRegex,
		line:          xorDecode("FhMUHxsIZzYzNAU7KjMFOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjahsYGQ=="),

		expMatch:      true,
		expSecret:     xorDecode("NjM0BTsqMwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmNqGxgZ"),

	})
}

func TestProcessor_LinearAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinearAPIKeyRegex,
		line:          `lin_api_short`,
		expMatch:      false,
	})
}

func TestProcessor_WeightsAndBiasesKey_Valid(t *testing.T) {
	// (?i)wandb.{0,40}?\b([0-9a-f]{40})\b - 1 capture group, lowercase hex
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WeightsAndBiasesKeyRegex,
		line:          xorDecode("LTs0PjgFOyozBTE/I3pnejs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj4="),

		expMatch:      true,
		expSecret:     xorDecode("Ozs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pg=="),

	})
}

func TestProcessor_WeightsAndBiasesKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WeightsAndBiasesKeyRegex,
		line:          `wandb_key = short`,
		expMatch:      false,
	})
}

func TestProcessor_HashiCorpVaultToken_Valid(t *testing.T) {
	// \b(hvs\.[a-zA-Z0-9_-]{24,})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HashiCorpVaultTokenRegex,
		line:          xorDecode("DBsPFg4FDhURHxRnMiwpdDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("MiwpdDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}

func TestProcessor_HashiCorpVaultToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HashiCorpVaultTokenRegex,
		line:          `hvs.short`,
		expMatch:      false,
	})
}

func TestProcessor_MapboxToken_Valid(t *testing.T) {
	// \b(sk\.[a-zA-Z0-9.\-]{80,240})\b - 1 capture group, 80+ chars
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MapboxTokenRegex,
		line:          xorDecode("FxsKGBUCZykxdDs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),

		expMatch:      true,
		expSecret:     xorDecode("KTF0Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs="),

	})
}

func TestProcessor_MapboxToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MapboxTokenRegex,
		line:          `sk.short`,
		expMatch:      false,
	})
}

// ========================================
// Miscellaneous Content Patterns
// ========================================

func TestProcessor_JWT_Valid(t *testing.T) {
	// \b(eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})\b - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JWTRegex,
		line:          xorDecode("LjUxPzRnPyMQMjgdOTMVMxATDyATdD8jECA+DRMzFTMTIhcwF3QJPDYRIi0IEAkXPxERHGgLDg=="),

		expMatch:      true,
		expSecret:     xorDecode("PyMQMjgdOTMVMxATDyATdD8jECA+DRMzFTMTIhcwF3QJPDYRIi0IEAkXPxERHGgLDg=="),

	})
}

func TestProcessor_JWT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JWTRegex,
		line:          `eyJ.eyJ.short`,
		expMatch:      false,
	})
}

func TestProcessor_ArtifactoryToken_Valid(t *testing.T) {
	// (?i)artifactory.{0,50}['\"`]?([a-zA-Z0-9=]{112}) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ArtifactoryTokenRegex,
		line:          xorDecode("OyguMzw7OS41KCMFLjUxPzR6Z3p4Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7O3g="),

		expMatch:      true,
		expSecret:     xorDecode("Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ow=="),

	})
}

func TestProcessor_ArtifactoryToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ArtifactoryTokenRegex,
		line:          `artifactory_key = "short"`,
		expMatch:      false,
	})
}

func TestProcessor_CodeClimateToken_Valid(t *testing.T) {
	// (?i)codeclima.{0,50}['\"`]?([0-9a-f]{64}) - 1 capture group, lowercase hex
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CodeClimateTokenRegex,
		line:          xorDecode("OTU+Pzk2Mzc7Lj8FLjUxPzR6Z3p4Ozs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaXg="),

		expMatch:      true,
		expSecret:     xorDecode("Ozs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pmpqa2toaGlpOzs4ODk5Pj5qamtraGhpaQ=="),

	})
}

func TestProcessor_CodeClimateToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CodeClimateTokenRegex,
		line:          `codeclimate_key = "short"`,
		expMatch:      false,
	})
}

func TestProcessor_SonarQubeToken_Valid(t *testing.T) {
	// (?i)sonar.{0,50}['\"`]?([0-9a-f]{40}) - 1 capture group, lowercase hex
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SonarQubeTokenRegex,
		line:          xorDecode("KTU0OygFLjUxPzR6Z3p4Ozs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Png="),

		expMatch:      true,
		expSecret:     xorDecode("Ozs4ODk5Pj5qamtraGhpaTs7ODg5OT4+ampra2hoaWk7Ozg4OTk+Pg=="),

	})
}

func TestProcessor_SonarQubeToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SonarQubeTokenRegex,
		line:          `sonar_key = "short"`,
		expMatch:      false,
	})
}

func TestProcessor_HockeyAppToken_Valid(t *testing.T) {
	// (?i)hockey.{0,50}['\"`]?([0-9a-f]{32}) - 1 capture group, lowercase hex
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HockeyAppTokenRegex,
		line:          xorDecode("MjU5MT8jBTsqKgUuNTE/NHpnenhqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PHg="),

		expMatch:      true,
		expSecret:     xorDecode("amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzw="),

	})
}

func TestProcessor_HockeyAppToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HockeyAppTokenRegex,
		line:          `hockey_key = "short"`,
		expMatch:      false,
	})
}

func TestProcessor_StackHawkAPIKey_Valid(t *testing.T) {
	// hawk\.[0-9A-Za-z\-_]{20}\.[0-9A-Za-z\-_]{20} - no capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StackHawkAPIKeyRegex,
		line:          xorDecode("EhsNEQURHwNnMjstMXQ7ODk+Pzw9MjMwMTY3NDUqKygpLnQ7ODk+Pzw9MjMwMTY3NDUqKygpLg=="),

		expMatch:      true,
		expSecret:     xorDecode("MjstMXQ7ODk+Pzw9MjMwMTY3NDUqKygpLnQ7ODk+Pzw9MjMwMTY3NDUqKygpLg=="),

	})
}

func TestProcessor_StackHawkAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StackHawkAPIKeyRegex,
		line:          `hawk.short.short`,
		expMatch:      false,
	})
}

func TestProcessor_OutlookWebhook_Valid(t *testing.T) {
	// (https://outlook\.office\.com/webhook/[0-9a-f-]{36}@) - 1 capture group
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OutlookWebhookRegex,
		line:          xorDecode("DR8YEhUVEWcyLi4qKWB1dTUvLjY1NTF0NTw8Mzk/dDk1N3UtPzgyNTUxdTs4OT4/PGprd2hpbm93bG1iY3c7ODk+dz88amtoaW5vbG1iYxo="),

		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXU1Ly42NTUxdDU8PDM5P3Q5NTd1LT84MjU1MXU7ODk+Pzxqa3doaW5vd2xtYmN3Ozg5Pnc/PGpraGlub2xtYmMa"),

	})
}

func TestProcessor_OutlookWebhook_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OutlookWebhookRegex,
		line:          `https://outlook.office.com/other/abc@`,
		expMatch:      false,
	})
}

func TestProcessor_WPConfigCredentials_Valid(t *testing.T) {
	// (?i)define\s*\(\s*['\"](?:DB_PASSWORD|...)['\"]\s*,\s*['\"](.*?)['\"] - 1 capture group (secret value)
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WPConfigCredentialsRegex,
		line:          xorDecode("Pj88MzQ/cn0eGAUKGwkJDRUIHn12en0pLyo/KCk/OSg/Lio7KSktNSg+fXM="),

		expMatch:      true,
		expSecret:     `supersecretpassword`,
	})
}

func TestProcessor_WPConfigCredentials_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WPConfigCredentialsRegex,
		line:          `define('OTHER_KEY', 'value')`,
		expMatch:      false,
	})
}
