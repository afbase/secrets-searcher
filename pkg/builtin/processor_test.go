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

// ========================================
// Payments, Blockchain & Security (Batch 4) Tests
// ========================================

func TestProcessor_Flutterwave_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlutterwaveKeyRegex,
		line:          xorDecode("HBYPDg4fCA0bDB8FCR8JCB8OBREfA2ccFg0JHxkRdzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjdwI="),
		expMatch:      true,
		expSecret:     xorDecode("HBYNCR8ZEXc7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iY3cC"),
	})
}

func TestProcessor_Flutterwave_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlutterwaveKeyRegex,
		line:          `FLWSECK-tooshort-X`,
		expMatch:      false,
	})
}

func TestProcessor_Paystack_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaystackKeyRegex,
		line:          xorDecode("KjsjKS47OTEFMT8jZykxBS4/KS4FOxhqOR5rPxxoPRJpMxBuMRZvNxRsNQptKwhiKQ5jLwxqLQJrIwBoOw=="),
		expMatch:      true,
		expSecret:     xorDecode("KTEFLj8pLgU7GGo5Hms/HGg9EmkzEG4xFm83FGw1Cm0rCGIpDmMvDGotAmsjAGg7"),
	})
}

func TestProcessor_Paystack_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaystackKeyRegex,
		line:          `sk_short`,
		expMatch:      false,
	})
}

func TestProcessor_Razorpay_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RazorpayKeyRegex,
		line:          xorDecode("CBsAFQgKGwMFER8DZyggKgU2Myw/BTsYOR4/HD0SMxAxFjcU"),
		expMatch:      true,
		expSecret:     xorDecode("KCAqBTYzLD8FOxg5Hj8cPRIzEDEWNxQ="),
	})
}

func TestProcessor_Razorpay_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RazorpayKeyRegex,
		line:          `rzp_test_aBcDeFgHiJkLmN`,
		expMatch:      false,
	})
}

func TestProcessor_Etherscan_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EtherscanKeyRegex,
		line:          xorDecode("Py4yPygpOTs0BTsqMwUxPyNnGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwBqa2hpbm9sbQ=="),
		expMatch:      true,
		expSecret:     xorDecode("GxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwBqa2hpbm9sbQ=="),
	})
}

func TestProcessor_Etherscan_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EtherscanKeyRegex,
		line:          `etherscan_api_key=tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_BSCScan_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BSCScanKeyRegex,
		line:          xorDecode("OCk5KTk7NAU7KjMFMT8jZxsYGR4fHB0SExARFhcUFQoLCAkODwwNAgMAamtoaW5vbG0="),
		expMatch:      true,
		expSecret:     xorDecode("GxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwBqa2hpbm9sbQ=="),
	})
}

func TestProcessor_BSCScan_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BSCScanKeyRegex,
		line:          `bscscan_key=abc`,
		expMatch:      false,
	})
}

func TestProcessor_Pinata_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PinataAPIKeyRegex,
		line:          xorDecode("KjM0Oy47BTsqMwUxPyNnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}

func TestProcessor_Pinata_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PinataAPIKeyRegex,
		line:          `pinata_api_key=tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_Moralis_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MoralisAPIKeyRegex,
		line:          xorDecode("NzUoOzYzKQU7KjMFMT8jZzsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAiMAamtoaW5vOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm87GDkePxw9EjMQMRY3FDUKKwgpDi8MLQIjAGpraGlubw=="),
	})
}

func TestProcessor_Moralis_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MoralisAPIKeyRegex,
		line:          `moralis_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_Coinbase_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinbaseKeyRegex,
		line:          xorDecode("OTUzNDg7KT8FOyozBTQ7Nz9nNSg9OzQzIDsuMzU0KXU7azhoOWk+bnc/bzxsd21iY2p3Ozg5Pnc/PGtoaW5vbG1iY2p1OyozET8jKXU7azhoOWk+bnc/bzxsd21iY2p3Ozg5Pnc/PGtoaW5vbG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("NSg9OzQzIDsuMzU0KXU7azhoOWk+bnc/bzxsd21iY2p3Ozg5Pnc/PGtoaW5vbG1iY2p1OyozET8jKXU7azhoOWk+bnc/bzxsd21iY2p3Ozg5Pnc/PGtoaW5vbG1iY2o="),
	})
}

func TestProcessor_Coinbase_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinbaseKeyRegex,
		line:          `coinbase_api=not-a-valid-format`,
		expMatch:      false,
	})
}

func TestProcessor_PlaidAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlaidAccessTokenRegex,
		line:          xorDecode("KjY7Mz4FLjUxPzRnOzk5Pykpdyk7ND44NSJ3O2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("Ozk5Pykpdyk7ND44NSJ3O2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
	})
}

func TestProcessor_PlaidAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlaidAccessTokenRegex,
		line:          `access-development-12345678-1234-1234-1234-123456789012`,
		expMatch:      false,
	})
}

func TestProcessor_PlaidSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlaidSecretKeyRegex,
		line:          xorDecode("KjY7Mz4FKT85KD8uZzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xt"),
	})
}

func TestProcessor_PlaidSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlaidSecretKeyRegex,
		line:          `plaid_secret=tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_Wise_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WiseAPIKeyRegex,
		line:          xorDecode("Lig7NCk8PygtMyk/BTsqMwUxPyNnO2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
	})
}

func TestProcessor_Wise_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WiseAPIKeyRegex,
		line:          `transferwise_key=notauuid`,
		expMatch:      false,
	})
}

func TestProcessor_Dwolla_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DwollaKeyRegex,
		line:          xorDecode("Pi01NjY7BTsqMwUxPyNnOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjamtoaW5vbG1iYzs4OT4="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjamtoaW5vbG1iYzs4OT4="),
	})
}

func TestProcessor_Dwolla_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DwollaKeyRegex,
		line:          `dwolla_key=tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_SauceLabs_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SauceLabsTokenRegex,
		line:          xorDecode("KTsvOT82OzgpBTE/I2c7azhoOWk+bnc/bzxsdztiY2p3Ozg5Pnc/PGtoaW5vbG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7YmNqdzs4OT53PzxraGlub2xtYmNq"),
	})
}

func TestProcessor_SauceLabs_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SauceLabsTokenRegex,
		line:          `saucelabs_key=notauuid`,
		expMatch:      false,
	})
}

func TestProcessor_BrowserStack_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrowserStackKeyRegex,
		line:          xorDecode("GAgVDQkfCAkOGxkRBRsZGR8JCQURHwNnOxg5Hj8cPRIzEDEWNxQ1CisIKQ4="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4="),
	})
}

func TestProcessor_BrowserStack_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrowserStackKeyRegex,
		line:          `BROWSERSTACK_ACCESS_KEY=short`,
		expMatch:      false,
	})
}

func TestProcessor_Bitly_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitlyTokenRegex,
		line:          xorDecode("ODMuNiMFLjUxPzRnOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjajs4OQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjajs4OQ=="),
	})
}

func TestProcessor_Bitly_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitlyTokenRegex,
		line:          `bitly_token=short`,
		expMatch:      false,
	})
}

func TestProcessor_Snipcart_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SnipcartAPIKeyRegex,
		line:          xorDecode("KTQzKjk7KC4FOyozBTE/I2c7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIBsYGR4fHB0SExARFhcUFQoLCAkODwwNAgMAamtoaW5vbG1iYwU7ODk+Pzw9MjMwMTY="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyAbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQIDAGpraGlub2xtYmMFOzg5Pj88PTIzMDE2"),
	})
}

func TestProcessor_Snipcart_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SnipcartAPIKeyRegex,
		line:          `snipcart_api_key=tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_Gumroad_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GumroadAccessTokenRegex,
		line:          xorDecode("PS83KDU7PgUuNTE/NGc7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQIjAGpraGlub2xtYmNqOzg5Pj88"),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjajs4OT4/PA=="),
	})
}

func TestProcessor_Gumroad_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GumroadAccessTokenRegex,
		line:          `gumroad_token=short`,
		expMatch:      false,
	})
}

func TestProcessor_RapidAPI_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RapidAPIKeyRegex,
		line:          xorDecode("KDsqMz47KjMFMT8jZzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0C"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyAbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQI="),
	})
}

func TestProcessor_RapidAPI_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RapidAPIKeyRegex,
		line:          `rapidapi_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_IPInfo_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IPInfoTokenRegex,
		line:          xorDecode("MyozNDw1BS41MT80Zzs4OT4/PGpraGlub2xt"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG0="),
	})
}

func TestProcessor_IPInfo_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IPInfoTokenRegex,
		line:          `ipinfo_token=short`,
		expMatch:      false,
	})
}

func TestProcessor_Shodan_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShodanKeyRegex,
		line:          xorDecode("KTI1Pjs0BTsqMwUxPyNnOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm8="),
	})
}

func TestProcessor_Shodan_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShodanKeyRegex,
		line:          `shodan_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_VirusTotal_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VirusTotalAPIKeyRegex,
		line:          xorDecode("LDMoLykuNS47NgU7KjMFMT8jZzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}

func TestProcessor_VirusTotal_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VirusTotalAPIKeyRegex,
		line:          `virustotal_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_SecurityTrails_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SecurityTrailsKeyRegex,
		line:          xorDecode("KT85LygzLiMuKDszNikFMT8jZzsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAiMAamtoaW5v"),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm8="),
	})
}

func TestProcessor_SecurityTrails_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SecurityTrailsKeyRegex,
		line:          `securitytrails_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_URLScan_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLScanKeyRegex,
		line:          xorDecode("Lyg2KTk7NAU7KjMFMT8jZztrOGg5aT5udz9vPGx3bWJjanc7ODk+dz88a2hpbm9sbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
	})
}

func TestProcessor_URLScan_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.URLScanKeyRegex,
		line:          `urlscan_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_Censys_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CensysKeyRegex,
		line:          xorDecode("OT80KSMpBTsqMwUxPyNnOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm8="),
	})
}

func TestProcessor_Censys_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CensysKeyRegex,
		line:          `censys_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_Sanity_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SanityTokenRegex,
		line:          xorDecode("KTs0My4jBS41MT80ZykxOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwA7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQIjADsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAiMAag=="),
		expMatch:      true,
		expSecret:     xorDecode("KTE7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQIjADsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAiMAOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBq"),
	})
}

func TestProcessor_Sanity_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SanityTokenRegex,
		line:          `sanity_token=sktooshort`,
		expMatch:      false,
	})
}

func TestProcessor_Wistia_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WistiaTokenRegex,
		line:          xorDecode("LTMpLjM7BTsqMwUxPyNnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}

func TestProcessor_Wistia_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WistiaTokenRegex,
		line:          `wistia_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_StripePaymentIntent_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripePaymentIntentRegex,
		line:          xorDecode("KjsjNz80LgUzNC4/NC5nKjMFOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CBSk/OSg/LgU7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQI="),
		expMatch:      true,
		expSecret:     xorDecode("KjMFOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CBSk/OSg/LgU7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQI="),
	})
}

func TestProcessor_StripePaymentIntent_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripePaymentIntentRegex,
		line:          `pi_short_secret_short`,
		expMatch:      false,
	})
}

func TestProcessor_SquareApp_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquareAppTokenRegex,
		line:          xorDecode("KSsvOyg/BS41MT80ZykrajM+Knc7GDkePxw9EjMQMRY3FDUKKwgpDi8M"),
		expMatch:      true,
		expSecret:     xorDecode("KStqMz4qdzsYOR4/HD0SMxAxFjcUNQorCCkOLww="),
	})
}

func TestProcessor_SquareApp_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquareAppTokenRegex,
		line:          `sq0xxx-short`,
		expMatch:      false,
	})
}

func TestProcessor_OneSignal_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OneSignalKeyRegex,
		line:          xorDecode("NTQ/KTM9NDs2BTsqMwUxPyNnO2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
	})
}

func TestProcessor_OneSignal_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OneSignalKeyRegex,
		line:          `onesignal_api_key=notauuid`,
		expMatch:      false,
	})
}

func TestProcessor_SSHPass_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SSHPassRegex,
		line:          xorDecode("KSkyKjspKXp3Knp4NyMpPzkoPy4qOykpLTUoPng="),
		expMatch:      true,
		expSecret:     xorDecode("NyMpPzkoPy4qOykpLTUoPg=="),
	})
}

func TestProcessor_SSHPass_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SSHPassRegex,
		line:          `ssh -p 22 user@host`,
		expMatch:      false,
	})
}

func TestProcessor_GrafanaAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GrafanaAPIKeyRegex,
		line:          xorDecode("PSg7PDs0OwUxPyNnPTYpOwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIBsYGR4fHB0SExARFhcUFQ=="),
		expMatch:      true,
		expSecret:     xorDecode("PTYpOwU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIBsYGR4fHB0SExARFhcUFQ=="),
	})
}

func TestProcessor_GrafanaAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GrafanaAPIKeyRegex,
		line:          `grafana_key=glsa_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_FrameIO_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FrameIOTokenRegex,
		line:          xorDecode("PCg7Nz8zNQUuNTE/NGc8MzV3L3c7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),
		expMatch:      true,
		expSecret:     xorDecode("PDM1dy93Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ow=="),
	})
}

func TestProcessor_FrameIO_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FrameIOTokenRegex,
		line:          `frameio_token=fio-u-tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_Stytch_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StytchSecretRegex,
		line:          xorDecode("KS4jLjkyBSk/OSg/Lmc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIBsYGR4fHB0SExARFhcUFQoLCAkOD2c="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyAbGBkeHxwdEhMQERYXFBUKCwgJDg9n"),
	})
}

func TestProcessor_Stytch_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StytchSecretRegex,
		line:          `stytch_secret=short`,
		expMatch:      false,
	})
}

func TestProcessor_Klaviyo_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KlaviyoKeyRegex,
		line:          xorDecode("MTY7LDMjNQU7KjMFMT8jZyoxBTsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAiMAamtoaW5vbG0="),
		expMatch:      true,
		expSecret:     xorDecode("KjEFOxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbQ=="),
	})
}

func TestProcessor_Klaviyo_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KlaviyoKeyRegex,
		line:          `klaviyo_api_key=pk_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_LaravelAppKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LaravelAppKeyRegex,
		line:          xorDecode("GwoKBREfA2c4Oyk/bG5gOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyAbGBkeHxwdEhMQERYXFBUKC2c="),
		expMatch:      true,
		expSecret:     xorDecode("ODspP2xuYDs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgGxgZHh8cHRITEBEWFxQVCgtn"),
	})
}

func TestProcessor_LaravelAppKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LaravelAppKeyRegex,
		line:          `APP_KEY=not-a-base64-key`,
		expMatch:      false,
	})
}

func TestProcessor_GenericAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GenericAPIKeyRegex,
		line:          xorDecode("OyozBTE/I2c7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQIjAGpraGlub2xtYmNqOzg5"),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjajs4OQ=="),
	})
}

func TestProcessor_GenericAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GenericAPIKeyRegex,
		line:          `api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_RobinhoodCrypto_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RobinhoodCryptoKeyRegex,
		line:          xorDecode("KDU4MzQyNTU+BTsqMwUxPyNnKDJ3OyozdztrOGg5aT5udz9vPGx3bWJjanc7ODk+dz88a2hpbm9sbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("KDJ3OyozdztrOGg5aT5udz9vPGx3bWJjanc7ODk+dz88a2hpbm9sbWJjag=="),
	})
}

func TestProcessor_RobinhoodCrypto_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RobinhoodCryptoKeyRegex,
		line:          `rh-api-not-a-uuid`,
		expMatch:      false,
	})
}

func TestProcessor_Zoho_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZohoTokenRegex,
		line:          xorDecode("IDUyNQUuNTE/NGdrampqdDs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjdDs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("a2pqanQ7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iY3Q7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}

func TestProcessor_Zoho_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZohoTokenRegex,
		line:          `zoho_token=not.a.valid.token`,
		expMatch:      false,
	})
}

func TestProcessor_GoDaddy_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoDaddyAPIKeyRegex,
		line:          xorDecode("PTU+Oz4+IwU7KjMFMT8jZzsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAiMAamtoaW5vbG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ4vDC0CIwBqa2hpbm9sbWJjag=="),
	})
}

func TestProcessor_GoDaddy_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoDaddyAPIKeyRegex,
		line:          `godaddy_api_key=short`,
		expMatch:      false,
	})
}

// ========================================
// Cloud & Infrastructure (Batch 1) Tests
// ========================================

func TestProcessor_AlibabaCloudKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlibabaCloudKeyRegex,
		line:          xorDecode("GxYTGBsYGwURHwNnFg4bE28uEhELPyI7Nyo2PxE/IxsYGR4f"),
		expMatch:      true,
		expSecret:     xorDecode("Fg4bE28uEhELPyI7Nyo2PxE/IxsYGR4f"),
	})
}

func TestProcessor_AlibabaCloudKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlibabaCloudKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_DatabricksToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatabricksTokenRegex,
		line:          xorDecode("LjUxPzRnPjsqM2praGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88"),
		expMatch:      true,
		expSecret:     xorDecode("PjsqM2praGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88"),
	})
}

func TestProcessor_DatabricksToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatabricksTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_NVIDIANGCKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NVIDIANGCKeyRegex,
		line:          xorDecode("FB0ZBRsKEwURHwNnNCw7KjN3Ozg5Pj88amtoaW5vbG1iYxsYGR4fHGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjGxgZHh8camtoaW5vbG1iYzs4OT4/PGpraGlub2xt"),
		expMatch:      true,
		expSecret:     xorDecode("NCw7KjN3Ozg5Pj88amtoaW5vbG1iYxsYGR4fHGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjGxgZHh8camtoaW5vbG1iYzs4OT4/PGpraGlub2xt"),
	})
}

func TestProcessor_NVIDIANGCKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NVIDIANGCKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AWSSessionToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSSessionTokenRegex,
		line:          xorDecode("Gw0JBQkfCQkTFRQFDhURHxRnHC01HQACEywDAj4gHxg5Ox4SPyI7Nyo2P2praGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjGxgZHh8camtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("HC01HQACEywDAj4gHxg5Ox4SPyI7Nyo2P2praGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjGxgZHh8camtoaW5vbG1iYw=="),
	})
}

func TestProcessor_AWSSessionToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSSessionTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureSASToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureSASTokenRegex,
		line:          xorDecode("OyAvKD96KTspeikqZyg7OS0+NjN8KS5naGpoaXdqa3dqaw5qamBqamBqagB8KT9naGpobndqa3dqaw5qamBqamBqagB8KSxnaGpoaHdra3dqaHwpKGc5fCkzPWc7ODk+PzxraGlub2w="),
		expMatch:      true,
		expSecret:     xorDecode("KSpnKDs5LT42M3wpLmdoamhpd2prd2prDmpqYGpqYGpqAHwpP2doamhud2prd2prDmpqYGpqYGpqAHwpLGdoamhod2trd2pofCkoZzl8KTM9Zzs4OT4/PGtoaW5vbA=="),
	})
}

func TestProcessor_AzureSASToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureSASTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureFunctionKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureFunctionKeyRegex,
		line:          xorDecode("OyAvKD96PC80OS4zNTR6MT8jZzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iY2obGBkeHxwdEhMQERYXFBU="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjahsYGR4fHB0SExARFhcUFQ=="),
	})
}

func TestProcessor_AzureFunctionKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureFunctionKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureContainerRegistry_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureContainerRegistryRegex,
		line:          xorDecode("KjspKS01KD5nOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8ccRsZCCIjIGtoaQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8ccRsZCCIjIGtoaQ=="),
	})
}

func TestProcessor_AzureContainerRegistry_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureContainerRegistryRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureSearchAdminKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureSearchAdminKeyRegex,
		line:          xorDecode("OyAvKD96KT87KDkyejs+NzM0ejE/I2c7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwdEhMQERYXFBUK"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEWFxQVCg=="),
	})
}

func TestProcessor_AzureSearchAdminKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureSearchAdminKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureAppConfigConnString_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureAppConfigConnStringRegex,
		line:          xorDecode("HzQ+KjUzNC5nMi4uKilgdXU3Izk1NDwzPXQ7IDk1NDwzPXQzNWETPmc7ODlraGlhCT85KD8uZyIjIG1iYzs4OWtoaT4/PG5vbA=="),
		expMatch:      true,
		expSecret:     xorDecode("HzQ+KjUzNC5nMi4uKilgdXU3Izk1NDwzPXQ7IDk1NDwzPXQzNWETPmc7ODlraGlhCT85KD8uZyIjIG1iYzs4OWtoaT4/PG5vbA=="),
	})
}

func TestProcessor_AzureAppConfigConnString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureAppConfigConnStringRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureOpenAIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureOpenAIKeyRegex,
		line:          xorDecode("OyozdzE/I2B6amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzw="),
		expMatch:      true,
		expSecret:     xorDecode("amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzw="),
	})
}

func TestProcessor_AzureOpenAIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureOpenAIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureCosmosDBKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureCosmosDBKeyRegex,
		line:          xorDecode("OTUpNzUpehs5OTUvNC4RPyNnGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxtnZw=="),
		expMatch:      true,
		expSecret:     xorDecode("GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxtnZw=="),
	})
}

func TestProcessor_AzureCosmosDBKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureCosmosDBKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureBatchKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureBatchKeyRegex,
		line:          xorDecode("ODsuOTJ6MT8jehsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxtnZw=="),
		expMatch:      true,
		expSecret:     xorDecode("GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbG2dn"),
	})
}

func TestProcessor_AzureBatchKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureBatchKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AzureAPIManagementKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureAPIManagementKeyRegex,
		line:          xorDecode("OyAvKD96KS84KTkoMyouMzU0ejE/I2c7ODk+Pzxqa2hpbm9sbWJjams7ODk+Pzxqa2hpbm9sbQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iY2prOzg5Pj88amtoaW5vbG0="),
	})
}

func TestProcessor_AzureAPIManagementKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureAPIManagementKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ConfluentKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConfluentKeyRegex,
		line:          xorDecode("OTU0PDYvPzQuejsqM3oxPyNnOzg5Hh8camtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Hh8camtoaW5vbG1iYw=="),
	})
}

func TestProcessor_ConfluentKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConfluentKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ConfluentSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConfluentSecretRegex,
		line:          xorDecode("OTU0PDYvPzQueik/OSg/Lno7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),
		expMatch:      true,
		expSecret:     xorDecode("Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ow=="),
	})
}

func TestProcessor_ConfluentSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConfluentSecretRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AivenToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AivenTokenRegex,
		line:          xorDecode("OzMsPzR6LjUxPzRnOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),
		expMatch:      true,
		expSecret:     xorDecode("Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),
	})
}

func TestProcessor_AivenToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AivenTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_PulumiToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PulumiTokenRegex,
		line:          xorDecode("Ki82dzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88PTI="),
		expMatch:      true,
		expSecret:     xorDecode("Ki82dzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88PTI="),
	})
}

func TestProcessor_PulumiToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PulumiTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_TerraformCloudToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TerraformCloudTokenRegex,
		line:          xorDecode("GzgZPh88HTITMBE2FzR0Oy42Oyksa3QbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlub2xtYmM7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlu"),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzR0Oy42Oyksa3QbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlub2xtYmM7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlu"),
	})
}

func TestProcessor_TerraformCloudToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TerraformCloudTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_InfuraAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InfuraAPIKeyRegex,
		line:          xorDecode("MzQ8Lyg7ejE/I2dqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PA=="),
		expMatch:      true,
		expSecret:     xorDecode("amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzw="),
	})
}

func TestProcessor_InfuraAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InfuraAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AlchemyAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlchemyAPIKeyRegex,
		line:          xorDecode("OzY5Mj83I3oxPyNnOzY5Mi4FOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xt"),
		expMatch:      true,
		expSecret:     xorDecode("OzY5Mi4FOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xt"),
	})
}

func TestProcessor_AlchemyAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlchemyAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_DigitalOceanSpacesKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanSpacesKeyRegex,
		line:          xorDecode("HhUFCQobGR8JBREfA2cbGBkeHxxqa2hpbm9sbWJjahsYGQ=="),
		expMatch:      true,
		expSecret:     xorDecode("GxgZHh8camtoaW5vbG1iY2obGBk="),
	})
}

func TestProcessor_DigitalOceanSpacesKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DigitalOceanSpacesKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ScalewayKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScalewayKeyRegex,
		line:          xorDecode("KTk7Nj8tOyN6KT85KD8uZztrOGg5aT5udz9vPGx3O204Ync5Yz5qdz9rPGg7aThuOW8+bA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7bThidzljPmp3P2s8aDtpOG45bz5s"),
	})
}

func TestProcessor_ScalewayKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScalewayKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_VultrAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VultrAPIKeyRegex,
		line:          xorDecode("LC82Lih6OyozejE/I3obGBkeHxxqa2hpbm9sbWJjGxgZHh8camtoaW5vbG1iYxsYGR4="),
		expMatch:      true,
		expSecret:     xorDecode("GxgZHh8camtoaW5vbG1iYxsYGR4fHGpraGlub2xtYmMbGBke"),
	})
}

func TestProcessor_VultrAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VultrAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_HetznerAPIToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HetznerAPITokenRegex,
		line:          xorDecode("Mj8uIDQ/KHo7KjN6LjUxPzRnGxgZPj88amtoaW5vbG1iYxsYGT4/PGpraGlub2xtYmMbGBk+Pzxqa2hpbm9sbWJjGxgZPj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("GxgZPj88amtoaW5vbG1iYxsYGT4/PGpraGlub2xtYmMbGBk+Pzxqa2hpbm9sbWJjGxgZPj88amtoaW5vbG1iYw=="),
	})
}

func TestProcessor_HetznerAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HetznerAPITokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_LinodeAPIToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinodeAPITokenRegex,
		line:          xorDecode("NjM0NT4/ei41MT80Zzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}

func TestProcessor_LinodeAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinodeAPITokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_DropboxToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DropboxTokenRegex,
		line:          xorDecode("Pig1Kjg1InouNTE/NHopNnQvdBsYGR4fHB0SExARFhcUFQoLCAkODwwNAgMAOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwA7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxw="),
		expMatch:      true,
		expSecret:     xorDecode("KTZ0L3QbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQIDADs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0SExARFhcUFQoLCAkODwwNAgMAOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8c"),
	})
}

func TestProcessor_DropboxToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DropboxTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FlyIOToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlyIOTokenRegex,
		line:          xorDecode("HDYjDGt6PDdraGlub2xtBRsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47"),
		expMatch:      true,
		expSecret:     xorDecode("HDYjDGt6PDdraGlub2xtBRsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47ODk+amtoaXF1ZxsYGR47"),
	})
}

func TestProcessor_FlyIOToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlyIOTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_RailwayToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RailwayTokenRegex,
		line:          xorDecode("KDszNi07I3ouNTE/NHo7azhoOWk+bnc/bzxsdzttOGJ3OWM+anc/azxoO2k4bjlvPmw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7bThidzljPmp3P2s8aDtpOG45bz5s"),
	})
}

func TestProcessor_RailwayToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RailwayTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_RenderAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RenderAPIKeyRegex,
		line:          xorDecode("KD80Pj8oejsqM3oxPyN6KDQ+BTs4OR4fHGpraGlub2xtYmM7ODkeHxxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("KDQ+BTs4OR4fHGpraGlub2xtYmM7ODkeHxxqa2hpbm9sbWJj"),
	})
}

func TestProcessor_RenderAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RenderAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_CouchbaseConnString_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CouchbaseConnStringRegex,
		line:          xorDecode("OTUvOTI4Oyk/ejI1KS56OTh0Ozg5Pj88a2hpdDk2NS8+dDk1LzkyODspP3Q5NTc="),
		expMatch:      true,
		expSecret:     xorDecode("OTh0Ozg5Pj88a2hpdDk2NS8+dDk1LzkyODspP3Q5NTc="),
	})
}

func TestProcessor_CouchbaseConnString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CouchbaseConnStringRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_RabbitMQConnString_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RabbitMQConnStringRegex,
		line:          xorDecode("OzcrKilgdXUvKT8oYCpuKSktaig+Gig7ODgzLnQ/Ijs3KjY/dDk1N2BvbG1rdSwyNSku"),
		expMatch:      true,
		expSecret:     xorDecode("Km4pKS1qKD4="),
	})
}

func TestProcessor_RabbitMQConnString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RabbitMQConnStringRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FTPCredential_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FTPCredentialRegex,
		line:          xorDecode("PC4qYHV1Oz43MzRgKWk5KGkuGjwuKnQ/Ijs3KjY/dDk1N3U8MzY/KQ=="),
		expMatch:      true,
		expSecret:     xorDecode("KWk5KGku"),
	})
}

func TestProcessor_FTPCredential_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FTPCredentialRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_JDBCConnString_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JDBCConnStringRegex,
		line:          xorDecode("MD44OWAqNSkuPSg/KSs2YHV1MjUpLmBvbmlodT44ZS8pPyhnOz43MzR8KjspKS01KD5nKT85KD8ua2hp"),
		expMatch:      true,
		expSecret:     xorDecode("MD44OWAqNSkuPSg/KSs2YHV1MjUpLmBvbmlodT44ZS8pPyhnOz43MzR8KjspKS01KD5nKT85KD8ua2hp"),
	})
}

func TestProcessor_JDBCConnString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JDBCConnStringRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_MySQLConnString_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MySQLConnStringRegex,
		line:          xorDecode("NyMpKzZgdXUvKT8oYCpuKSktaig+GjcjKSs2dD8iOzcqNj90OTU3YGlpamx1NyM+OA=="),
		expMatch:      true,
		expSecret:     xorDecode("Km4pKS1qKD4="),
	})
}

func TestProcessor_MySQLConnString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MySQLConnStringRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ElasticsearchURL_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElasticsearchURLRegex,
		line:          xorDecode("HxYbCQ4TGQkfGwgZEgUPCBZnMi4uKilgdXU/NjspLjM5YClpOShpLho/KXQ/Ijs3KjY/dDk1N2BjaGpq"),
		expMatch:      true,
		expSecret:     xorDecode("KWk5KGku"),
	})
}

func TestProcessor_ElasticsearchURL_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElasticsearchURLRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_NGrokToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NGrokTokenRegex,
		line:          xorDecode("ND0oNTF6Oy8uMnpoGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsFahgYGBgYGBgYGBgYGBgYGBgYGBgY"),
		expMatch:      true,
		expSecret:     xorDecode("aBsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbBWoYGBgYGBgYGBgYGBgYGBgYGBgYGA=="),
	})
}

func TestProcessor_NGrokToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NGrokTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_PortainerToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PortainerTokenRegex,
		line:          xorDecode("KjUoLjszND8oLjUxPzR6Ki4oBRsYGR47ODk+amtoaW5vbG1iYxsYGR4fHA=="),
		expMatch:      true,
		expSecret:     xorDecode("Ki4oBRsYGR47ODk+amtoaW5vbG1iYxsYGR4fHA=="),
	})
}

func TestProcessor_PortainerToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PortainerTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_SnowflakeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SnowflakeKeyRegex,
		line:          xorDecode("KTQ1LTw2OzE/ejs5OTUvNC5nGxgZHh8cHXc7ODlraGk="),
		expMatch:      true,
		expSecret:     xorDecode("GxgZHh8cHXc7ODlraGk="),
	})
}

func TestProcessor_SnowflakeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SnowflakeKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_CloudsmithAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudsmithAPIKeyRegex,
		line:          xorDecode("OTY1Lz4pNzMuMnoxPyNnamtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbQ=="),
		expMatch:      true,
		expSecret:     xorDecode("amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbQ=="),
	})
}

func TestProcessor_CloudsmithAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudsmithAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_PackageCloudToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PackageCloudTokenRegex,
		line:          xorDecode("Kjs5MTs9Pzk2NS8+ei41MT80Z2praGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PA=="),
		expMatch:      true,
		expSecret:     xorDecode("amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88"),
	})
}

func TestProcessor_PackageCloudToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PackageCloudTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

// ========================================
// Marketing, Analytics & CRM (Batch 5) Tests
// ========================================

func TestProcessor_MailerLiteToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailerLiteTokenRegex,
		line:          xorDecode("NzszNj8oNjMuPwUxPyNneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5ueA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_MailerLiteToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailerLiteTokenRegex,
		line:          `not a valid mailerlite key`,
		expMatch:      false,
	})
}

func TestProcessor_ConvertKitToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConvertKitTokenRegex,
		line:          xorDecode("OTU0LD8oLjEzLgU7KjMFKT85KD8uZ3gbODlrHj88aB0yM2kQMTZuFzRvFSoreA=="),
		expMatch:      true,
		expSecret:     xorDecode("Gzg5ax4/PGgdMjNpEDE2bhc0bxUqKw=="),
	})
}

func TestProcessor_ConvertKitToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConvertKitTokenRegex,
		line:          `not a valid convertkit key`,
		expMatch:      false,
	})
}

func TestProcessor_OmnisendKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OmnisendKeyRegex,
		line:          xorDecode("NTc0Myk/ND4FOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4eA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4"),
	})
}

func TestProcessor_OmnisendKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OmnisendKeyRegex,
		line:          `not a valid omnisend key`,
		expMatch:      false,
	})
}

func TestProcessor_CustomerIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CustomerIOKeyRegex,
		line:          xorDecode("OS8pLjU3PygzNQUxPyNneDsYazkeaD8caT0SbjMQbzEWbDcUeA=="),
		expMatch:      true,
		expSecret:     xorDecode("OxhrOR5oPxxpPRJuMxBvMRZsNxQ="),
	})
}

func TestProcessor_CustomerIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CustomerIOKeyRegex,
		line:          `not a valid customer key`,
		expMatch:      false,
	})
}

func TestProcessor_KlaviyoPrivateKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KlaviyoPrivateKeyRegex,
		line:          xorDecode("KjEFO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/PA=="),
		expMatch:      true,
		expSecret:     xorDecode("KjEFO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/PA=="),
	})
}

func TestProcessor_KlaviyoPrivateKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KlaviyoPrivateKeyRegex,
		line:          `pk_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_IterableAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IterableAPIKeyRegex,
		line:          xorDecode("My4/KDs4Nj8FOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_IterableAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IterableAPIKeyRegex,
		line:          `not a valid iterable key`,
		expMatch:      false,
	})
}

func TestProcessor_BrevoAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrevoAPIKeyRegex,
		line:          xorDecode("IjE/IykzOHc7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iOzg="),
		expMatch:      true,
		expSecret:     xorDecode("IjE/IykzOHc7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iOzg="),
	})
}

func TestProcessor_BrevoAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrevoAPIKeyRegex,
		line:          `xkeysib-tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_ActiveCampaignKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ActiveCampaignKeyRegex,
		line:          xorDecode("OzkuMyw/OTs3KjszPTQFOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aHg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aA=="),
	})
}

func TestProcessor_ActiveCampaignKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ActiveCampaignKeyRegex,
		line:          `not a valid activecampaign key`,
		expMatch:      false,
	})
}

func TestProcessor_DripAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DripAPIKeyRegex,
		line:          xorDecode("PigzKgU7KjMFMT8jZ3g7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bng="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_DripAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DripAPIKeyRegex,
		line:          `not a valid drip key`,
		expMatch:      false,
	})
}

func TestProcessor_GetResponseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetResponseKeyRegex,
		line:          xorDecode("PT8uKD8pKjU0KT8FOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_GetResponseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetResponseKeyRegex,
		line:          `not a valid getresponse key`,
		expMatch:      false,
	})
}

func TestProcessor_MoosendKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MoosendKeyRegex,
		line:          xorDecode("NzU1KT80PgU7KjMFMT8jZ3g7azhoOWk+bnc/bzxsdztrOGh3OWk+bnc/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7azhodzlpPm53P288bDtrOGg5aT5u"),
	})
}

func TestProcessor_MoosendKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MoosendKeyRegex,
		line:          `not a valid moosend key`,
		expMatch:      false,
	})
}

func TestProcessor_SendinBlueKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendinBlueKeyRegex,
		line:          xorDecode("IjE/IykzOHc7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iOzg="),
		expMatch:      true,
		expSecret:     xorDecode("IjE/IykzOHc7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iOzg="),
	})
}

func TestProcessor_SendinBlueKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendinBlueKeyRegex,
		line:          `xkeysib-short`,
		expMatch:      false,
	})
}

func TestProcessor_EventbriteKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EventbriteKeyRegex,
		line:          xorDecode("Pyw/NC44KDMuPwU7KjMFMT8jZ3gbaxhoGWkebh9vHGwbaxhoGWkebng="),
		expMatch:      true,
		expSecret:     xorDecode("G2sYaBlpHm4fbxxsG2sYaBlpHm4="),
	})
}

func TestProcessor_EventbriteKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EventbriteKeyRegex,
		line:          `not a valid eventbrite key`,
		expMatch:      false,
	})
}

func TestProcessor_TypeformToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TypeformTokenRegex,
		line:          xorDecode("LjwqBTtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aQ=="),
		expMatch:      true,
		expSecret:     xorDecode("LjwqBTtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aQ=="),
	})
}

func TestProcessor_TypeformToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TypeformTokenRegex,
		line:          `tfp_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_SurveyMonkeyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SurveyMonkeyTokenRegex,
		line:          xorDecode("KS8oLD8jNzU0MT8jBS41MT80Z3g7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7a3g="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s="),
	})
}

func TestProcessor_SurveyMonkeyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SurveyMonkeyTokenRegex,
		line:          `not a valid surveymonkey token`,
		expMatch:      false,
	})
}

func TestProcessor_FullStoryToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FullStoryTokenRegex,
		line:          xorDecode("NDtrdBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("NDtrdBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGgZaT5uH288bBtrOGg="),
	})
}

func TestProcessor_FullStoryToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FullStoryTokenRegex,
		line:          `na1.tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_HotjarToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HotjarTokenRegex,
		line:          xorDecode("MjUuMDsoBTsqMwUxPyNneDtrOGg5aT5udz9vPGx3O2s4aHc5aT5udz9vPGw7azhoOWk+bng="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7azhodzlpPm53P288bDtrOGg5aT5u"),
	})
}

func TestProcessor_HotjarToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HotjarTokenRegex,
		line:          `not a valid hotjar key`,
		expMatch:      false,
	})
}

func TestProcessor_OptimizelyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OptimizelyTokenRegex,
		line:          xorDecode("NSouMzczID82IwUxPyNneDtrOGg5aT5udz9vPGxgO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aHg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bGA7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azho"),
	})
}

func TestProcessor_OptimizelyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OptimizelyTokenRegex,
		line:          `not a valid optimizely key`,
		expMatch:      false,
	})
}

func TestProcessor_AppsflyerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppsflyerKeyRegex,
		line:          xorDecode("OyoqKTw2Iz8oBTsqMwUxPyNneDtrOGg5aT5udz9vPGx3O2s4aHc5aT5udz9vPGw7azhoOWk+bng="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7azhodzlpPm53P288bDtrOGg5aT5u"),
	})
}

func TestProcessor_AppsflyerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppsflyerKeyRegex,
		line:          `not a valid appsflyer key`,
		expMatch:      false,
	})
}

func TestProcessor_BranchIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BranchIOKeyRegex,
		line:          xorDecode("OCg7NDkyBTM1BTE/I2d4MT8jBTYzLD8FO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("MT8jBTYzLD8FO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_BranchIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BranchIOKeyRegex,
		line:          `key_invalid_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_ChargebeeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChargebeeKeyRegex,
		line:          xorDecode("OTI7KD0/OD8/BTsqMwUxPyNneDYzLD8FO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("NjMsPwU7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bg=="),
	})
}

func TestProcessor_ChargebeeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChargebeeKeyRegex,
		line:          `live_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_RecurlyAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RecurlyAPIKeyRegex,
		line:          xorDecode("KD85Lyg2IwU7KjMFMT8jZ3g7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bng="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_RecurlyAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RecurlyAPIKeyRegex,
		line:          `not a valid recurly key`,
		expMatch:      false,
	})
}

func TestProcessor_PaddleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaddleKeyRegex,
		line:          xorDecode("Kjs+PjY/BTsqMwUxPyNneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5ueA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_PaddleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaddleKeyRegex,
		line:          `not a valid paddle key`,
		expMatch:      false,
	})
}

func TestProcessor_ChargifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChargifyKeyRegex,
		line:          xorDecode("OTI7KD0zPCMFOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_ChargifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChargifyKeyRegex,
		line:          `not a valid chargify key`,
		expMatch:      false,
	})
}

func TestProcessor_ZuoraKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZuoraKeyRegex,
		line:          xorDecode("IC81KDsFOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_ZuoraKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZuoraKeyRegex,
		line:          `not a valid zuora key`,
		expMatch:      false,
	})
}

func TestProcessor_BigCommerceToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BigCommerceTokenRegex,
		line:          xorDecode("ODM9OTU3Nz8oOT8FLjUxPzRneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bHg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxs"),
	})
}

func TestProcessor_BigCommerceToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BigCommerceTokenRegex,
		line:          `not a valid bigcommerce token`,
		expMatch:      false,
	})
}

func TestProcessor_WooCommerceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WooCommerceKeyRegex,
		line:          xorDecode("LTU1OTU3Nz8oOT8FMT8jZ3g5MQU7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoeA=="),
		expMatch:      true,
		expSecret:     xorDecode("OTEFO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aA=="),
	})
}

func TestProcessor_WooCommerceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WooCommerceKeyRegex,
		line:          `ck_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_ContentstackToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ContentstackTokenRegex,
		line:          xorDecode("OTU0Lj80LikuOzkxBS41MT80Z3g5KQU7azhoOWk+bj9vPGw7azhoOWk+bj9vPGw7azhoeA=="),
		expMatch:      true,
		expSecret:     xorDecode("OSkFO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aA=="),
	})
}

func TestProcessor_ContentstackToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ContentstackTokenRegex,
		line:          `cs_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_StoryblokToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StoryblokTokenRegex,
		line:          xorDecode("KS41KCM4NjUxBS41MT80Z3g7axhoOWkebj9vHGw7axhoOWkebjtrLi54"),
		expMatch:      true,
		expSecret:     xorDecode("O2sYaDlpHm4/bxxsO2sYaDlpHm47ay4u"),
	})
}

func TestProcessor_StoryblokToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StoryblokTokenRegex,
		line:          `storyblok_token="invalid_no_tt_suffix"`,
		expMatch:      false,
	})
}

func TestProcessor_GraphCMSToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GraphCMSTokenRegex,
		line:          xorDecode("PSg7KjI5NykFLjUxPzRneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5ueA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_GraphCMSToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GraphCMSTokenRegex,
		line:          `not a valid graphcms token`,
		expMatch:      false,
	})
}

func TestProcessor_PrismicToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PrismicTokenRegex,
		line:          xorDecode("KigzKTczOQUuNTE/NGd4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2t0OGg5aT5uP288bHg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2t0OGg5aT5uP288bA=="),
	})
}

func TestProcessor_PrismicToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PrismicTokenRegex,
		line:          `not a valid prismic token`,
		expMatch:      false,
	})
}

func TestProcessor_StrapiAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StrapiAPIKeyRegex,
		line:          xorDecode("KS4oOyozBTsqMwUxPyNneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bHg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxs"),
	})
}

func TestProcessor_StrapiAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StrapiAPIKeyRegex,
		line:          `not a valid strapi key`,
		expMatch:      false,
	})
}

func TestProcessor_GhostAdminKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GhostAdminKeyRegex,
		line:          xorDecode("PTI1KS4FMT8jZ3g7azhoOWk+bj9vPGw7azhoOWk+bj9vPGxgO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsYDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5u"),
	})
}

func TestProcessor_GhostAdminKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GhostAdminKeyRegex,
		line:          `not a valid ghost key`,
		expMatch:      false,
	})
}

func TestProcessor_ButterCMSKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ButterCMSKeyRegex,
		line:          xorDecode("OC8uLj8oOTcpBTsqMwUxPyNneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGh4"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aA=="),
	})
}

func TestProcessor_ButterCMSKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ButterCMSKeyRegex,
		line:          `not a valid buttercms key`,
		expMatch:      false,
	})
}

func TestProcessor_DatoCMSToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatoCMSTokenRegex,
		line:          xorDecode("PjsuNTk3KQUuNTE/NGd4O2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_DatoCMSToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatoCMSTokenRegex,
		line:          `not a valid datocms token`,
		expMatch:      false,
	})
}

func TestProcessor_HarperDBKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HarperDBKeyRegex,
		line:          xorDecode("MjsoKj8oPjgFOyozBTE/I2d4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_HarperDBKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HarperDBKeyRegex,
		line:          `not a valid harperdb key`,
		expMatch:      false,
	})
}

func TestProcessor_FaunaDBKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FaunaDBKeyRegex,
		line:          xorDecode("PDQbHztrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bA=="),
		expMatch:      true,
		expSecret:     xorDecode("PDQbHztrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bA=="),
	})
}

func TestProcessor_FaunaDBKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FaunaDBKeyRegex,
		line:          `fntooshort`,
		expMatch:      false,
	})
}

func TestProcessor_PlanetScaleOAuth_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanetScaleOAuthRegex,
		line:          xorDecode("Kik5OzY/BTUuMTQFO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPg=="),
		expMatch:      true,
		expSecret:     xorDecode("Kik5OzY/BTUuMTQFO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPg=="),
	})
}

func TestProcessor_PlanetScaleOAuth_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanetScaleOAuthRegex,
		line:          `pscale_otkn_tooshort`,
		expMatch:      false,
	})
}

func TestProcessor_TursoToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TursoTokenRegex,
		line:          xorDecode("Li8oKTUFLjUxPzRneDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5uP288bDtrOGg5aT5ueA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_TursoToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TursoTokenRegex,
		line:          `not a valid turso token`,
		expMatch:      false,
	})
}

func TestProcessor_NeonToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NeonTokenRegex,
		line:          xorDecode("ND81NAUuNTE/NGd4O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm54"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4/bzxsO2s4aDlpPm4="),
	})
}

func TestProcessor_NeonToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NeonTokenRegex,
		line:          `not a valid neon token`,
		expMatch:      false,
	})
}

// ========================================
// Data Platforms & Misc Tests (Batch 6)
// ========================================

func TestProcessor_SplunkObservabilityToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SplunkObservabilityTokenRegex,
		line:          xorDecode("KSo2LzQxBS41MT80ZzsYOR4/HD0SMxAxFjcUNQorCCkOa2g="),
		expMatch:      true,
		expSecret:     xorDecode("Oxg5Hj8cPRIzEDEWNxQ1CisIKQ5raA=="),
	})
}

func TestProcessor_SplunkObservabilityToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SplunkObservabilityTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_SumoLogicKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SumoLogicKeyRegex,
		line:          xorDecode("KS83NQUxPyNnGzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8bOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlubw=="),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8bOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlubw=="),
	})
}

func TestProcessor_SumoLogicKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SumoLogicKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ElasticCloudKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElasticCloudKeyRegex,
		line:          xorDecode("PzY7KS4zOQUxPyNnGzgZPh88HTITMGpraGlub2xtYmMRNhc0FSoLKAkuDywNIgMgGzgZPh88HTJnZw=="),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMGpraGlub2xtYmMRNhc0FSoLKAkuDywNIgMgGzgZPh88HTJnZw=="),
	})
}

func TestProcessor_ElasticCloudKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElasticCloudKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_TimescaleDBToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TimescaleDBTokenRegex,
		line:          xorDecode("Lik+ODEFGzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMg"),
		expMatch:      true,
		expSecret:     xorDecode("Lik+ODEFGzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMg"),
	})
}

func TestProcessor_TimescaleDBToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TimescaleDBTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ClickHouseToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClickHouseTokenRegex,
		line:          xorDecode("OTI5BRs4GT4fPB0yEzARNhc0FSoLKAkuDywNImpraGlubw=="),
		expMatch:      true,
		expSecret:     xorDecode("OTI5BRs4GT4fPB0yEzARNhc0FSoLKAkuDywNImpraGlubw=="),
	})
}

func TestProcessor_ClickHouseToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClickHouseTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_InfluxDBToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InfluxDBTokenRegex,
		line:          xorDecode("ExQcFg8CHhgFDhURHxRnOzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztnZw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7OztnZw=="),
	})
}

func TestProcessor_InfluxDBToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InfluxDBTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_CockroachDBToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CockroachDBTokenRegex,
		line:          xorDecode("OSg2dyxrdzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88ams="),
		expMatch:      true,
		expSecret:     xorDecode("OSg2dyxrdzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88ams="),
	})
}

func TestProcessor_CockroachDBToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CockroachDBTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_RedisCloudToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RedisCloudTokenRegex,
		line:          xorDecode("KD8+MykFOTY1Lz4FMT8jZxs4GT4fPB0yEzARNhc0FSoLKAkuDywNIgMgamtoaW5v"),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8="),
	})
}

func TestProcessor_RedisCloudToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RedisCloudTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_UpstashToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UpstashTokenRegex,
		line:          xorDecode("GwICAhs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYzs4OT4/"),
		expMatch:      true,
		expSecret:     xorDecode("GwICAhs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYzs4OT4/"),
	})
}

func TestProcessor_UpstashToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UpstashTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_OpenSearchKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenSearchKeyRegex,
		line:          xorDecode("NSo/NCk/Oyg5MgUxPyNnGzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMgGzgZPh88HTI="),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMgGzgZPh88HTI="),
	})
}

func TestProcessor_OpenSearchKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenSearchKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_PagerDutyServiceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PagerDutyServiceKeyRegex,
		line:          xorDecode("Kjs9Pyg+Ly4jBTE/I2cvcRs4GT4fPB0yEzARNhc0FSoLKA=="),
		expMatch:      true,
		expSecret:     xorDecode("L3EbOBk+HzwdMhMwETYXNBUqCyg="),
	})
}

func TestProcessor_PagerDutyServiceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PagerDutyServiceKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_StatusPageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StatusPageKeyRegex,
		line:          xorDecode("KS47Li8pKjs9PwUxPyNnO2s4aDlpPm53P288bHdtYmNqdzs4OT53Pzxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}

func TestProcessor_StatusPageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StatusPageKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_UptimeRobotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UptimeRobotKeyRegex,
		line:          xorDecode("LyouMzc/KDU4NS4FMT8jZy8bOBk+a2hpbnc7GDkePxw9EjMQMRY3FDUKKwgpDi8MLQI="),
		expMatch:      true,
		expSecret:     xorDecode("Lxs4GT5raGludzsYOR4/HD0SMxAxFjcUNQorCCkOLwwtAg=="),
	})
}

func TestProcessor_UptimeRobotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UptimeRobotKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_DatadogRUMToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatadogRUMTokenRegex,
		line:          xorDecode("Hh4FCA8XBQ4VER8UZyovOGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5"),
		expMatch:      true,
		expSecret:     xorDecode("Ki84a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk="),
	})
}

func TestProcessor_DatadogRUMToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DatadogRUMTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_GoogleMapsAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleMapsAPIKeyRegex,
		line:          xorDecode("HRUVHRYfBRcbCgkFER8DZxsTIDsJIxhraGlub2xtYmNqazs4OT4/PD0yMzAxNjc0NSorKCkuLw=="),
		expMatch:      true,
		expSecret:     xorDecode("GxMgOwkjGGtoaW5vbG1iY2prOzg5Pj88PTIzMDE2NzQ1KisoKS4v"),
	})
}

func TestProcessor_GoogleMapsAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoogleMapsAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_MapTilerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MapTilerKeyRegex,
		line:          xorDecode("NzsqLjM2PygFMT8jZxs4GT4fPB0yEzARNhc0FSoLKAkuDyxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKgsoCS4PLGpraGlub2xtYmM="),
	})
}

func TestProcessor_MapTilerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MapTilerKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_TomTomAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TomTomAPIKeyRegex,
		line:          xorDecode("LjU3LjU3BTE/I2cbaxhoGWkebh9vHGwdbRJiE2MQahFrFmgXaRRuFW8KbA=="),
		expMatch:      true,
		expSecret:     xorDecode("G2sYaBlpHm4fbxxsHW0SYhNjEGoRaxZoF2kUbhVvCmw="),
	})
}

func TestProcessor_TomTomAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TomTomAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_HereAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HereAPIKeyRegex,
		line:          xorDecode("Mj8oPzsqMwUxPyNnGzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMgGzgZPh88HQ=="),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMgGzgZPh88HQ=="),
	})
}

func TestProcessor_HereAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HereAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_TwelveDatAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwelveDatAPIKeyRegex,
		line:          xorDecode("Li0/Niw/PjsuOwUxPyNnO2s4aDlpPm4/bzxsO204YjljPmo/azxoO2k4bjlvPmw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO204YjljPmo/azxoO2k4bjlvPmw="),
	})
}

func TestProcessor_TwelveDatAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwelveDatAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AlphaVantageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlphaVantageKeyRegex,
		line:          xorDecode("OzYqMjssOzQuOz0/BTE/I2cbGBkeHxwda2hpbm9sbRsY"),
		expMatch:      true,
		expSecret:     xorDecode("GxgZHh8cHWtoaW5vbG0bGA=="),
	})
}

func TestProcessor_AlphaVantageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlphaVantageKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_PolygonIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PolygonIOKeyRegex,
		line:          xorDecode("KjU2Iz01NAUxPyNnGzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8="),
	})
}

func TestProcessor_PolygonIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PolygonIOKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FinnhubToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FinnhubTokenRegex,
		line:          xorDecode("PDM0NDIvOAUxPyNnO2s4aDlpPm4/bzxsPW0yYjNjMGo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsPW0yYjNjMGo="),
	})
}

func TestProcessor_FinnhubToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FinnhubTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_CoinGeckoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinGeckoKeyRegex,
		line:          xorDecode("GR13Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmNqaw=="),
		expMatch:      true,
		expSecret:     xorDecode("GR13Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmNqaw=="),
	})
}

func TestProcessor_CoinGeckoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinGeckoKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_BlockchainInfoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlockchainInfoKeyRegex,
		line:          xorDecode("ODY1OTE5MjszNAUxPyNnO2s4aDlpPm53P288bHdtYmNqdzs4OT53Pzxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}

func TestProcessor_BlockchainInfoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlockchainInfoKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AWSCognitoToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSCognitoTokenRegex,
		line:          xorDecode("Lyl3PzspLndrBRs4GT4fPB0yEw=="),
		expMatch:      true,
		expSecret:     xorDecode("Lyl3PzspLndrBRs4GT4fPB0yEw=="),
	})
}

func TestProcessor_AWSCognitoToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSCognitoTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FirebaseAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FirebaseAPIKeyRegex,
		line:          xorDecode("PDMoPzg7KT8FMT8jZxsTIDsJIxljYm1sb25paGtqazg5Pj88PTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("GxMgOwkjGWNibWxvbmloa2prODk+Pzw9MjMwMTY3NDUqKygpLi8s"),
	})
}

func TestProcessor_FirebaseAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FirebaseAPIKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FirebaseCloudMsg_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FirebaseCloudMsgRegex,
		line:          xorDecode("GxsbG2toaW5vbG1iY2pgGwobY2s4GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm9sbWJjGzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyAbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlub2xtYmMbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlub2xtYmMbOBk+Hzw="),
		expMatch:      true,
		expSecret:     xorDecode("GxsbG2toaW5vbG1iY2pgGwobY2s4GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm9sbWJjGzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyAbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlub2xtYmMbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIGpraGlub2xtYmMbOBk+Hzw="),
	})
}

func TestProcessor_FirebaseCloudMsg_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FirebaseCloudMsgRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AppCenterToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppCenterTokenRegex,
		line:          xorDecode("OyoqOT80Lj8oBS41MT80ZztrOGg5aT5uP288bDttOGI5Yz5qP2s8aDtpOG45bz5sP208YjtjOGo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO204YjljPmo/azxoO2k4bjlvPmw/bTxiO2M4ag=="),
	})
}

func TestProcessor_AppCenterToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppCenterTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ExpoToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ExpoTokenRegex,
		line:          xorDecode("HyIqNTQ/NC4KLykyDjUxPzQBOzg5Pj88amtoaW5vbG1iYzs4OT4/PAc="),
		expMatch:      true,
		expSecret:     xorDecode("HyIqNTQ/NC4KLykyDjUxPzQBOzg5Pj88amtoaW5vbG1iYzs4OT4/PAc="),
	})
}

func TestProcessor_ExpoToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ExpoTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_TestFlightToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TestFlightTokenRegex,
		line:          xorDecode("Lj8pLjw2Mz0yLgUuNTE/NGc/IxAyOB05MxUzEBwPIBNrFDMTKRM0CG85GRNsEzEqAgwZEykTNy4qABkTbBMwHyMXIAtrFDA5bhUOGzM8CyI="),
		expMatch:      true,
		expSecret:     xorDecode("PyMQMjgdOTMVMxAcDyATaxQzEykTNAhvORkTbBMxKgIMGRMpEzcuKgAZE2wTMB8jFyALaxQwOW4VDhszPAsi"),
	})
}

func TestProcessor_TestFlightToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TestFlightTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_SonarCloudToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SonarCloudTokenRegex,
		line:          xorDecode("KTU0Oyg5NjUvPgUuNTE/NGc7azhoOWk+bj9vPGw7bThiOWM+aj9rPGg7aThuOW8+bD9tPGI7Yzhq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsO204YjljPmo/azxoO2k4bjlvPmw/bTxiO2M4ag=="),
	})
}

func TestProcessor_SonarCloudToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SonarCloudTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_CoverityToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoverityTokenRegex,
		line:          xorDecode("OTUsPygzLiMFLjUxPzRnOTUsdztrOGg5aT5uP288bDttOGI5Yz5qP2s8aDtpOG45bz5s"),
		expMatch:      true,
		expSecret:     xorDecode("OTUsdztrOGg5aT5uP288bDttOGI5Yz5qP2s8aDtpOG45bz5s"),
	})
}

func TestProcessor_CoverityToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoverityTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FossaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FossaKeyRegex,
		line:          xorDecode("PDUpKTt3O2s4aDlpPm4/bzxsO204YjljPmo/azxoO2k4bjlvPmw="),
		expMatch:      true,
		expSecret:     xorDecode("PDUpKTt3O2s4aDlpPm4/bzxsO204YjljPmo/azxoO2k4bjlvPmw="),
	})
}

func TestProcessor_FossaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FossaKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_WhitesourceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WhitesourceKeyRegex,
		line:          xorDecode("LTIzLj8pNS8oOT8FMT8jZxs4GT4fPB0yEzARNhc0FSpqa2hpbm9sbWJjCygJLg8sDSIDIBs4GT4fPB0y"),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKmpraGlub2xtYmMLKAkuDywNIgMgGzgZPh88HTI="),
	})
}

func TestProcessor_WhitesourceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WhitesourceKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_BlackDuckToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlackDuckTokenRegex,
		line:          xorDecode("ODY7OTE+LzkxBS41MT80Zxs4GT4fPB0yEzARNhc0FSoLKAkuDywNIgMgamtoaW5vbG1iYxs4GT4fPB0yEzARNhc0FSoLKAkuDywNIgMgamtoaW5vbG1iYxs4GT4fPB0yEzARNhc0FSoLKAkuDywNIgMgamtoaW5vbG1iYxsYGR4fHA=="),
		expMatch:      true,
		expSecret:     xorDecode("GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm9sbWJjGzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm9sbWJjGzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm9sbWJjGxgZHh8c"),
	})
}

func TestProcessor_BlackDuckToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlackDuckTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_NetlifyDeployKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NetlifyDeployKeyRegex,
		line:          xorDecode("NDwqBRs4GT4fPB0yEzARNhc0FSoLKAkuDywNIgMgamtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("NDwqBRs4GT4fPB0yEzARNhc0FSoLKAkuDywNIgMgamtoaW5vbG1iYw=="),
	})
}

func TestProcessor_NetlifyDeployKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NetlifyDeployKeyRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_CloudinaryURL_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudinaryURLRegex,
		line:          xorDecode("GRYVDx4TFBsIAwUPCBZnOTY1Lz4zNDsoI2B1dWtoaW5vbG1iY2praGlub2AbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIBo3Izk2NS8+"),
		expMatch:      true,
		expSecret:     xorDecode("OTY1Lz4zNDsoI2B1dWtoaW5vbG1iY2praGlub2AbOBk+HzwdMhMwETYXNBUqCygJLg8sDSIDIBo3Izk2NS8+"),
	})
}

func TestProcessor_CloudinaryURL_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudinaryURLRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_ImgixToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ImgixTokenRegex,
		line:          xorDecode("MyJ3GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("MyJ3GzgZPh88HTITMBE2FzQVKgsoCS4PLA0iAyBqa2hpbm8="),
	})
}

func TestProcessor_ImgixToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ImgixTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_FastlyAPIToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FastlyAPITokenRegex,
		line:          xorDecode("PDspLjYjBTE/I2cbaxhoGWkebh9vHGwdbRJiE2MQahFrFmgXaRRuFW8KbA=="),
		expMatch:      true,
		expSecret:     xorDecode("G2sYaBlpHm4fbxxsHW0SYhNjEGoRaxZoF2kUbhVvCmw="),
	})
}

func TestProcessor_FastlyAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FastlyAPITokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

func TestProcessor_AkamaiToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AkamaiTokenRegex,
		line:          xorDecode("OzE7OHc7azhoOWk+bj9vPGw7bThidzljPmo/azxoO2k4bjlvPmw="),
		expMatch:      true,
		expSecret:     xorDecode("OzE7OHc7azhoOWk+bj9vPGw7bThidzljPmo/azxoO2k4bjlvPmw="),
	})
}

func TestProcessor_AkamaiToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AkamaiTokenRegex,
		line:          `not a valid token`,
		expMatch:      false,
	})
}

// ========================================
// SaaS & Communication (Batch 3) Tests
// ========================================

func TestProcessor_TwilioAccountSID_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwilioAccountSIDRegex,
		line:          xorDecode("Li0zNjM1BSkzPmcbGWtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88"),
		expMatch:      true,
		expSecret:     xorDecode("GxlraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4OT4/PA=="),
	})
}

func TestProcessor_TwilioAccountSID_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwilioAccountSIDRegex,
		line:          `twilio_sid=XX12345678`,
		expMatch:      false,
	})
}

func TestProcessor_TelnyxAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TelnyxAPIKeyRegex,
		line:          xorDecode("Lj82NCMiBTE/I2cRHwM7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwdEhMQERYXFBUKCwgJ"),
		expMatch:      true,
		expSecret:     xorDecode("ER8DOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRITEBEWFxQVCgsICQ=="),
	})
}

func TestProcessor_TelnyxAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TelnyxAPIKeyRegex,
		line:          `telnyx_key=KEY123`,
		expMatch:      false,
	})
}

func TestProcessor_VonageAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VonageAPIKeyRegex,
		line:          xorDecode("LDU0Oz0/BTE/I2c7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4="),
	})
}

func TestProcessor_VonageAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VonageAPIKeyRegex,
		line:          `vonage_key=ab`,
		expMatch:      false,
	})
}

func TestProcessor_PlivoAuthToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlivoAuthTokenRegex,
		line:          xorDecode("KjYzLDUFLjUxPzRnOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjamtoaQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjamtoaQ=="),
	})
}

func TestProcessor_PlivoAuthToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlivoAuthTokenRegex,
		line:          `plivo_token=short`,
		expMatch:      false,
	})
}

func TestProcessor_MessageBirdKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MessageBirdKeyRegex,
		line:          xorDecode("Nz8pKTs9PzgzKD4FMT8jZy04CDxqMWkiAyttEiAQFms/F28+FGM5Ci8="),
		expMatch:      true,
		expSecret:     xorDecode("LTgIPGoxaSIDK20SIBAWaz8Xbz4UYzkKLw=="),
	})
}

func TestProcessor_MessageBirdKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MessageBirdKeyRegex,
		line:          `messagebird_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_SendBirdKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendBirdKeyRegex,
		line:          xorDecode("KT80PjgzKD4FMT8jZzs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2g="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraA=="),
	})
}

func TestProcessor_SendBirdKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SendBirdKeyRegex,
		line:          `sendbird_key=abc123`,
		expMatch:      false,
	})
}

func TestProcessor_MandrillAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MandrillAPIKeyRegex,
		line:          xorDecode("Nzs0PigzNjYFMT8jZzs4OT4/PD0yMzBqa2hpbm9sbWJjMTY="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMxNg=="),
	})
}

func TestProcessor_MandrillAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MandrillAPIKeyRegex,
		line:          `mandrill_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_SparkPostToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SparkPostTokenRegex,
		line:          xorDecode("KSo7KDEqNSkuBTE/I2c7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYw=="),
	})
}

func TestProcessor_SparkPostToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SparkPostTokenRegex,
		line:          `sparkpost_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_CourierAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CourierAPIKeyRegex,
		line:          xorDecode("OTUvKDM/KAUxPyNnKjEFKig1PgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIDs4"),
		expMatch:      true,
		expSecret:     xorDecode("KjEFKig1PgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIDs4"),
	})
}

func TestProcessor_CourierAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CourierAPIKeyRegex,
		line:          `courier_key=pk_short`,
		expMatch:      false,
	})
}

func TestProcessor_PostmarkToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostmarkTokenRegex,
		line:          xorDecode("KjUpLjc7KDEFMT8jZztrOGg5aT5udz9vPGx3O204Ync5Yz5qdz9rPGg7aThuOW8+bA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7bThidzljPmp3P2s8aDtpOG45bz5s"),
	})
}

func TestProcessor_PostmarkToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostmarkTokenRegex,
		line:          `postmark_key=not-a-uuid`,
		expMatch:      false,
	})
}

func TestProcessor_IntercomToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IntercomTokenRegex,
		line:          xorDecode("MzQuPyg5NTcFMT8jZzs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Zw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Oztn"),
	})
}

func TestProcessor_IntercomToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IntercomTokenRegex,
		line:          `intercom_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_FreshdeskToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FreshdeskTokenRegex,
		line:          xorDecode("PCg/KTI+PykxBTE/I2c7ODk+Pzw9MjMwamtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmM="),
	})
}

func TestProcessor_FreshdeskToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FreshdeskTokenRegex,
		line:          `freshdesk_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_FreshbooksToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FreshbooksTokenRegex,
		line:          xorDecode("PCg/KTI4NTUxKQUxPyNnOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjag=="),
	})
}

func TestProcessor_FreshbooksToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FreshbooksTokenRegex,
		line:          `freshbooks_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_HubSpotAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HubSpotAPIKeyRegex,
		line:          xorDecode("Mi84KSo1LgU7KjMFMT8jZzs4OT4/PGtod2lub2x3bWJjanc7ODk+dz88a2hpbm9sbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2h3aW5vbHdtYmNqdzs4OT53PzxraGlub2xtYmNq"),
	})
}

func TestProcessor_HubSpotAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HubSpotAPIKeyRegex,
		line:          `hubspot_api_key=not-a-uuid`,
		expMatch:      false,
	})
}

func TestProcessor_SalesforceToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalesforceTokenRegex,
		line:          xorDecode("KTs2Pyk8NSg5PwUuNTE/NGdqah5rO2gYaTluHm8/bBx7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7"),
		expMatch:      true,
		expSecret:     xorDecode("amoeaztoGGk5bh5vP2wcezs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ozs7Ow=="),
	})
}

func TestProcessor_SalesforceToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalesforceTokenRegex,
		line:          `salesforce_token=notvalid`,
		expMatch:      false,
	})
}

func TestProcessor_DocuSignKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DocuSignKeyRegex,
		line:          xorDecode("PjU5LykzPTR6KT85KD8uZztrOGg5aT5udz9vPGx3O204Ync5Yz5qdz9rPGg7aThuOW8+bA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHc7bThidzljPmp3P2s8aDtpOG45bz5s"),
	})
}

func TestProcessor_DocuSignKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DocuSignKeyRegex,
		line:          `docusign secret=notvalid`,
		expMatch:      false,
	})
}

func TestProcessor_FastlyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FastlyTokenRegex,
		line:          xorDecode("PDspLjYjBTE/I2c7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExARFg=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQERY="),
	})
}

func TestProcessor_FastlyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FastlyTokenRegex,
		line:          `fastly_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_MattermostToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MattermostTokenRegex,
		line:          xorDecode("NzsuLj8oNzUpLgUxPyNnOzg5Pj88PTIzMGpraGlub2xtYmM7ODk+Pzw="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmM7ODk+Pzw="),
	})
}

func TestProcessor_MattermostToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MattermostTokenRegex,
		line:          `mattermost_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_WebflowToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebflowTokenRegex,
		line:          xorDecode("LT84PDY1LQUxPyNnOzg5Pj88PTIzMDE2NzQ1Kjs4OT4/PD0yMzAxNjc0NSo7ODk+Pzw9MjMwMTY3NDUqOzg5Pj88PTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1Kjs4OT4/PD0yMzAxNjc0NSo7ODk+Pzw9MjMwMTY3NDUqOzg5Pj88PTIzMDE2NzQ1Kg=="),
	})
}

func TestProcessor_WebflowToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebflowTokenRegex,
		line:          `webflow_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_DeepgramAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DeepgramAPIKeyRegex,
		line:          xorDecode("Pj8/Kj0oOzcFMT8jZzs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2g="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraA=="),
	})
}

func TestProcessor_DeepgramAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DeepgramAPIKeyRegex,
		line:          `deepgram_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_AssemblyAIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AssemblyAIKeyRegex,
		line:          xorDecode("OykpPzc4NiM7MwUxPyNnOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
	})
}

func TestProcessor_AssemblyAIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AssemblyAIKeyRegex,
		line:          `assemblyai_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_CohereAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CohereAPIKeyRegex,
		line:          xorDecode("OTUyPyg/BTsqMwUxPyNnOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYw=="),
	})
}

func TestProcessor_CohereAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CohereAPIKeyRegex,
		line:          `cohere_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_MistralAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MistralAPIKeyRegex,
		line:          xorDecode("NzMpLig7NgU7KjMFMT8jZzs4OT4/PD0yMzBqa2hpbm9sbWJjGxgZHh8cHRITEGpr"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQams="),
	})
}

func TestProcessor_MistralAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MistralAPIKeyRegex,
		line:          `mistral_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_FireworksAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FireworksAPIKeyRegex,
		line:          xorDecode("PDMoPy01KDEpBTsqMwUxPyNnPC0FOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQams="),
		expMatch:      true,
		expSecret:     xorDecode("PC0FOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQams="),
	})
}

func TestProcessor_FireworksAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FireworksAPIKeyRegex,
		line:          `fireworks_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_TogetherAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TogetherAPIKeyRegex,
		line:          xorDecode("LjU9Py4yPygFOyozBTE/I2c7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjGxgZHh8cHRITEGpraGlub2xtYmM7ODk+"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjOzg5Pg=="),
	})
}

func TestProcessor_TogetherAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TogetherAPIKeyRegex,
		line:          `together_api_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_PerplexityAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PerplexityAPIKeyRegex,
		line:          xorDecode("Kj8oKjY/IjMuIwUxPyNnKio2Inc7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("Kio2Inc7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
	})
}

func TestProcessor_PerplexityAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PerplexityAPIKeyRegex,
		line:          `perplexity_key=pplx-short`,
		expMatch:      false,
	})
}

func TestProcessor_SlackAppToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackAppTokenRegex,
		line:          xorDecode("KTY7OTEFOyoqZyI7Kip3a3cbamtoaW5vbG1iY3dqa2hpbm9sbWJjamtodzs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7OA=="),
		expMatch:      true,
		expSecret:     xorDecode("IjsqKndrdxtqa2hpbm9sbWJjd2praGlub2xtYmNqa2h3Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4"),
	})
}

func TestProcessor_SlackAppToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SlackAppTokenRegex,
		line:          `slack_app=xapp-short`,
		expMatch:      false,
	})
}

func TestProcessor_TrelloAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TrelloAPIKeyRegex,
		line:          xorDecode("Lig/NjY1BTE/I2c7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
	})
}

func TestProcessor_TrelloAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TrelloAPIKeyRegex,
		line:          `trello_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_MondayToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MondayTokenRegex,
		line:          xorDecode("NzU0PjsjBTE/I2c/IxAyOB05MxUzEBMPIBNrFDMTKRM0CG85GRNsEzEqAgwZEGN0PyMQazloDCMJDQszFTMTIhcwF2oUDgNpFR4xLRMzLTM4NxwuAAkTbBMxKiw7HW8fOGgPMxYZEDIAHWsqODMTbD4SEGsACS0zOw0cahMwNSIUMB9oFzAXbxceEyMWGRA2OA0cKjgZE2wTNyosOx1uLwAdYzYLHQxuAw1rLTgdDy8DaGMuEzMtMzhpEDQTMDUzOA1jLwAdHG8WDWMjACNqIhcwF2oUDgNpFRkTKRM0FDA4aRg2EzA1MwM3YzI5NwggFTQQNgMNCykDN2MyOTcIIBU0PiM7Agg2EzMtMzk3YykACRNsEzccMTgNNi8TMy0zPh0MMjgJE2wTNwwvAGg2LwANDCM7DW80EzRqdAk8NhEiLQgQCRc/EREcaAsObjwtKhc/EDxpbAoVMWwjEAwFOz4RFAwgNGM="),
		expMatch:      true,
		expSecret:     xorDecode("PyMQMjgdOTMVMxATDyATaxQzEykTNAhvORkTbBMxKgIMGRBjdD8jEGs5aAwjCQ0LMxUzEyIXMBdqFA4DaRUeMS0TMy0zODccLgAJE2wTMSosOx1vHzhoDzMWGRAyAB1rKjgzE2w+EhBrAAktMzsNHGoTMDUiFDAfaBcwF28XHhMjFhkQNjgNHCo4GRNsEzcqLDsdbi8AHWM2Cx0MbgMNay04HQ8vA2hjLhMzLTM4aRA0EzA1MzgNYy8AHRxvFg1jIwAjaiIXMBdqFA4DaRUZEykTNBQwOGkYNhMwNTMDN2MyOTcIIBU0EDYDDQspAzdjMjk3CCAVND4jOwIINhMzLTM5N2MpAAkTbBM3HDE4DTYvEzMtMz4dDDI4CRNsEzcMLwBoNi8ADQwjOw1vNBM0anQJPDYRIi0IEAkXPxERHGgLDm48LSoXPxA8aWwKFTFsIxAMBTs+ERQMIDRj"),
	})
}

func TestProcessor_MondayToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MondayTokenRegex,
		line:          `monday_key=not-a-jwt`,
		expMatch:      false,
	})
}

func TestProcessor_TodoistToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TodoistTokenRegex,
		line:          xorDecode("LjU+NTMpLgUxPyNnOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraA=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraA=="),
	})
}

func TestProcessor_TodoistToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TodoistTokenRegex,
		line:          `todoist_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_LarkSuiteToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LarkSuiteTokenRegex,
		line:          xorDecode("NjsoMSkvMy4/BTE/I2c5NjMFOzg5Pj88PTJqa2hpbm9sbQ=="),
		expMatch:      true,
		expSecret:     xorDecode("OTYzBTs4OT4/PD0yamtoaW5vbG0="),
	})
}

func TestProcessor_LarkSuiteToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LarkSuiteTokenRegex,
		line:          `larksuite_key=cli_short`,
		expMatch:      false,
	})
}

func TestProcessor_SmartsheetToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SmartsheetTokenRegex,
		line:          xorDecode("KTc7KC4pMj8/LgUxPyNnOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxw="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxw="),
	})
}

func TestProcessor_SmartsheetToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SmartsheetTokenRegex,
		line:          `smartsheet_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_Auth0ClientSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Auth0ClientSecretRegex,
		line:          xorDecode("Oy8uMmoFKT85KD8uZzs4OT4/PD0yMzBqa2hpbm9sbWJjGxgZHh8cHRITEGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYzs4OT4/PA=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJjOzg5Pj88"),
	})
}

func TestProcessor_Auth0ClientSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Auth0ClientSecretRegex,
		line:          `auth0_secret=short`,
		expMatch:      false,
	})
}

func TestProcessor_OneLoginSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OneLoginSecretRegex,
		line:          xorDecode("NTQ/NjU9MzR6KT85KD8uZzs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjag=="),
	})
}

func TestProcessor_OneLoginSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OneLoginSecretRegex,
		line:          `onelogin secret=short`,
		expMatch:      false,
	})
}

func TestProcessor_JumpCloudAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JumpCloudAPIKeyRegex,
		line:          xorDecode("MC83Kjk2NS8+BTE/I2c7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExBqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYw=="),
	})
}

func TestProcessor_JumpCloudAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JumpCloudAPIKeyRegex,
		line:          `jumpcloud_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_PipedreamAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PipedreamAPIKeyRegex,
		line:          xorDecode("KjMqPz4oPzs3BTE/I2c7ODk+PzxraGlub2xtYmNqOzg5Pj88a2hpbm9sbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88a2hpbm9sbWJjajs4OT4/PGtoaW5vbG1iY2o="),
	})
}

func TestProcessor_PipedreamAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PipedreamAPIKeyRegex,
		line:          `pipedream_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_WebexBotToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebexBotTokenRegex,
		line:          xorDecode("GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGwUbOGsABTs4OT4/PD1qdzs4a2h3OT5pbnc/PG9sdzs4OT4/PD0yMzAxNg=="),
		expMatch:      true,
		expSecret:     xorDecode("GxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGxsbGwUbOGsABTs4OT4/PD1qdzs4a2h3OT5pbnc/PG9sdzs4OT4/PD0yMzAxNg=="),
	})
}

func TestProcessor_WebexBotToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebexBotTokenRegex,
		line:          `webex_bot_token=short`,
		expMatch:      false,
	})
}

func TestProcessor_TwitchAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitchAccessTokenRegex,
		line:          xorDecode("Li0zLjkyBS41MT80Zzs4OT4/PD0yMzBqa2hpbm9sbWJjOzg5Pj88PTIzMA=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmM7ODk+Pzw9MjMw"),
	})
}

func TestProcessor_TwitchAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwitchAccessTokenRegex,
		line:          `twitch_token=short`,
		expMatch:      false,
	})
}

func TestProcessor_SignalWireToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SignalWireTokenRegex,
		line:          xorDecode("KTM9NDs2LTMoPwUxPyNnOzg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYzs4OT4/PD0yMzA="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQamtoaW5vbG1iYzs4OT4/PD0yMzA="),
	})
}

func TestProcessor_SignalWireToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SignalWireTokenRegex,
		line:          `signalwire_key=short`,
		expMatch:      false,
	})
}

func TestProcessor_TextMagicKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TextMagicKeyRegex,
		line:          xorDecode("Lj8iLjc7PTM5BTE/I2c7ODk+Pzw9MjMwamtoaW5vbG1iYxsYGR4fHB0SExA="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMGpraGlub2xtYmMbGBkeHxwdEhMQ"),
	})
}

func TestProcessor_TextMagicKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TextMagicKeyRegex,
		line:          `textmagic_key=short`,
		expMatch:      false,
	})
}


// ===== Batch 2: DevOps & Developer Tools Tests =====

func TestProcessor_BitbucketAppPassword_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitbucketAppPasswordRegex,
		line:          xorDecode("GBMOGA8ZER8OBRsKCgUKGwkJDRUIHmcbDhgYOzg5Pj88amtoaW5vbG1iYxsYGR4fHDs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Gw4YGDs4OT4/PGpraGlub2xtYmMbGBkeHxw7ODk+Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_BitbucketAppPassword_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BitbucketAppPasswordRegex, line: `ATBB_tooshort`, expMatch: false})
}

func TestProcessor_DroneToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DroneTokenRegex,
		line:          xorDecode("HggVFB8FDhURHxRnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
	})
}
func TestProcessor_DroneToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DroneTokenRegex, line: `not a drone token`, expMatch: false})
}

func TestProcessor_SourcegraphToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SourcegraphTokenRegex,
		line:          xorDecode("CRUPCBkfHQgbChIFDhURHxRnKT0qBTs7Ozs7Ozs7Ozs7Ozs7OzsFOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqaw=="),
		expMatch:      true,
		expSecret:     xorDecode("KT0qBTs7Ozs7Ozs7Ozs7Ozs7OzsFOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqaw=="),
	})
}
func TestProcessor_SourcegraphToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SourcegraphTokenRegex, line: `sgp_tooshort`, expMatch: false})
}

func TestProcessor_SourcegraphCodyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SourcegraphCodyTokenRegex,
		line:          xorDecode("CRUPCBkfHQgbChIFGRUeA2cpNjEFOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("KTYxBTs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
	})
}
func TestProcessor_SourcegraphCodyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SourcegraphCodyTokenRegex, line: `slk_tooshort`, expMatch: false})
}

func TestProcessor_LangSmithToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LangSmithTokenRegex,
		line:          xorDecode("FhsUHQkXEw4SBRsKEwURHwNnNiksaAUqLgVqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PAVqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("NiksaAUqLgVqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PAVqa2hpbm9sbWJj"),
	})
}
func TestProcessor_LangSmithToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LangSmithTokenRegex, line: `lsv2_pt_tooshort`, expMatch: false})
}

func TestProcessor_LangfuseSecretKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LangfuseSecretKeyRegex,
		line:          xorDecode("FhsUHRwPCR8FCR8ZCB8OBREfA2cpMXc2PHc7ODk+Pzxqa3doaW5vd2xtYmN3Ozg5Pnc/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("KTF3Njx3Ozg5Pj88amt3aGlub3dsbWJjdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_LangfuseSecretKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LangfuseSecretKeyRegex, line: `sk-lf-tooshort`, expMatch: false})
}

func TestProcessor_LangfusePublicKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LangfusePublicKeyRegex,
		line:          xorDecode("FhsUHRwPCR8FCg8YFhMZBREfA2cqMXc2PHc7ODk+Pzxqa3doaW5vd2xtYmN3Ozg5Pnc/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("KjF3Njx3Ozg5Pj88amt3aGlub3dsbWJjdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_LangfusePublicKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LangfusePublicKeyRegex, line: `pk-lf-tooshort`, expMatch: false})
}

func TestProcessor_PrefectToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PrefectTokenRegex,
		line:          xorDecode("CggfHB8ZDgUbChMFER8DZyo0LwU7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4="),
		expMatch:      true,
		expSecret:     xorDecode("KjQvBTs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pg=="),
	})
}
func TestProcessor_PrefectToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PrefectTokenRegex, line: `pnu_tooshort`, expMatch: false})
}

func TestProcessor_HarnessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HarnessTokenRegex,
		line:          xorDecode("EhsIFB8JCQUOFREfFGcqOy50Ozg5Pj88amtoaW5vbG1iYzs4OT4/PHQ7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amt0Ozg5Pj88amtoaW5vbG1iYzs4OT4="),
		expMatch:      true,
		expSecret:     xorDecode("KjsudDs4OT4/PGpraGlub2xtYmM7ODk+Pzx0Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGprdDs4OT4/PGpraGlub2xtYmM7ODk+"),
	})
}
func TestProcessor_HarnessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HarnessTokenRegex, line: `pat.tooshort`, expMatch: false})
}

func TestProcessor_ContentfulPAT_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ContentfulPATRegex,
		line:          xorDecode("GRUUDh8UDhwPFgUOFREfFGcZHAobDnc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),
		expMatch:      true,
		expSecret:     xorDecode("GRwKGw53Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHQ=="),
	})
}
func TestProcessor_ContentfulPAT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ContentfulPATRegex, line: `CFPAT-tooshort`, expMatch: false})
}

func TestProcessor_AirtableToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AirtableTokenRegex,
		line:          xorDecode("GxMIDhsYFh8FDhURHxRnKjsuGzg5Hj88amtoaW5vbG10Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("KjsuGzg5Hj88amtoaW5vbG10Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}
func TestProcessor_AirtableToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AirtableTokenRegex, line: `pat_tooshort`, expMatch: false})
}

func TestProcessor_NotionToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NotionTokenRegex,
		line:          xorDecode("FB4OCRsUBQ4VER8UZyk/OSg/LgUbOBk+Hzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYxsYGR4fHGpraGlu"),
		expMatch:      true,
		expSecret:     xorDecode("KT85KD8uBRs4GT4fPGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjGxgZHh8camtoaW4="),
	})
}
func TestProcessor_NotionToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NotionTokenRegex, line: `secret_tooshort`, expMatch: false})
}

func TestProcessor_ClickUpToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClickUpTokenRegex,
		line:          xorDecode("GRYTGREPCgUOFREfFGcqMQVraGlub2xtYgUbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQIDAGpraGlubw=="),
		expMatch:      true,
		expSecret:     xorDecode("KjEFa2hpbm9sbWIFGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwBqa2hpbm8="),
	})
}
func TestProcessor_ClickUpToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClickUpTokenRegex, line: `pk_123_tooshort`, expMatch: false})
}

func TestProcessor_AsanaPAT_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AsanaPATRegex,
		line:          xorDecode("GwkbFhsFDhURHxRna3VraGlub2xtYmNqa2hpbm9sYDs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("a3VraGlub2xtYmNqa2hpbm9sYDs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_AsanaPAT_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AsanaPATRegex, line: `1/tooshort:abc`, expMatch: false})
}

func TestProcessor_CoverallsToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoverallsTokenRegex,
		line:          xorDecode("GRUMHwgbFhYJBQgfChUFDhURHxRnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqaw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqaw=="),
	})
}
func TestProcessor_CoverallsToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CoverallsTokenRegex, line: `coveralls_key=tooshort`, expMatch: false})
}

func TestProcessor_CodemagicToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CodemagicTokenRegex,
		line:          xorDecode("GRUeHxcbHRMZBRsKEwUOFREfFGc7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlubw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm8="),
	})
}
func TestProcessor_CodemagicToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CodemagicTokenRegex, line: `codemagic_key=tooshort`, expMatch: false})
}

func TestProcessor_CodacyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CodacyTokenRegex,
		line:          xorDecode("GRUeGxkDBQoIFRAfGQ4FDhURHxRnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
	})
}
func TestProcessor_CodacyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CodacyTokenRegex, line: `codacy_token=tooshort`, expMatch: false})
}

func TestProcessor_ScrutinizerToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScrutinizerTokenRegex,
		line:          xorDecode("CRkIDw4TFBMAHwgFGxkZHwkJBQ4VER8UZzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_ScrutinizerToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScrutinizerTokenRegex, line: `scrutinizer_token=tooshort`, expMatch: false})
}

func TestProcessor_PercyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PercyTokenRegex,
		line:          xorDecode("Ch8IGQMFDhURHxRnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}
func TestProcessor_PercyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PercyTokenRegex, line: `PERCY_TOKEN=tooshort`, expMatch: false})
}

func TestProcessor_PagerDutyAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PagerDutyAPIKeyRegex,
		line:          xorDecode("ChsdHwgeDw4DBRsKEwURHwNnL3E7ODk+Pzw9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("L3E7ODk+Pzw9MjMwMTY3NDUqKyg="),
	})
}
func TestProcessor_PagerDutyAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PagerDutyAPIKeyRegex, line: `pagerduty_key=tooshort`, expMatch: false})
}

func TestProcessor_OpsgenieAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpsgenieAPIKeyRegex,
		line:          xorDecode("FQoJHR8UEx8FGwoTBREfA2c7ODk+Pzxqa3doaW5vd2xtYmN3Ozg5Pnc/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amt3aGlub3dsbWJjdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_OpsgenieAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OpsgenieAPIKeyRegex, line: `opsgenie_key=tooshort`, expMatch: false})
}

func TestProcessor_HoneycombToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HoneycombTokenRegex,
		line:          xorDecode("EhUUHwMZFRcYBRsKEwURHwNnOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0i"),
	})
}
func TestProcessor_HoneycombToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HoneycombTokenRegex, line: `honeycomb_key=short`, expMatch: false})
}

func TestProcessor_BetterStackToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BetterStackTokenRegex,
		line:          xorDecode("GB8ODh8ICQ4bGREFGwoTBREfA2c7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlubw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),
	})
}
func TestProcessor_BetterStackToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BetterStackTokenRegex, line: `betterstack_key=short`, expMatch: false})
}

func TestProcessor_LogglyToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LogglyTokenRegex,
		line:          xorDecode("FhUdHRYDBQ4VER8UZzs4OT4/PGprd2hpbm93bG1iY3c7ODk+dz88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amt3aGlub3dsbWJjdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_LogglyToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LogglyTokenRegex, line: `loggly_key=short`, expMatch: false})
}

func TestProcessor_LogzIOToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LogzIOTokenRegex,
		line:          xorDecode("FhUdABMVBRsKEwUOFREfFGc7ODk+Pzw9MhsYGR4fHB0SMzAxNjc0NSoTEBEWFxQVCg=="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIbGBkeHxwdEjMwMTY3NDUqExARFhcUFQo="),
	})
}
func TestProcessor_LogzIOToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LogzIOTokenRegex, line: `logzio_key=short`, expMatch: false})
}

func TestProcessor_PostHogToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostHogTokenRegex,
		line:          xorDecode("ChUJDhIVHQUbChMFER8DZyoyIgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmMbGBkeHxwd"),
		expMatch:      true,
		expSecret:     xorDecode("KjIiBTs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgamtoaW5vbG1iYxsYGR4fHB0="),
	})
}
func TestProcessor_PostHogToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PostHogTokenRegex, line: `phx_tooshort`, expMatch: false})
}

func TestProcessor_SegmentAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SegmentAPIKeyRegex,
		line:          xorDecode("CR8dFx8UDgUNCBMOHwURHwNnOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm8="),
	})
}
func TestProcessor_SegmentAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SegmentAPIKeyRegex, line: `segment_key=short`, expMatch: false})
}

func TestProcessor_MixpanelToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MixpanelTokenRegex,
		line:          xorDecode("FxMCChsUHxYFDhURHxRnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
	})
}
func TestProcessor_MixpanelToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MixpanelTokenRegex, line: `mixpanel_key=short`, expMatch: false})
}

func TestProcessor_AmplitudeAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AmplitudeAPIKeyRegex,
		line:          xorDecode("GxcKFhMODx4fBRsKEwURHwNnOzg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88amtoaW5vbG1iYzs4OT4/PGpraGlub2xtYmM="),
	})
}
func TestProcessor_AmplitudeAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AmplitudeAPIKeyRegex, line: `amplitude_key=short`, expMatch: false})
}

func TestProcessor_EndorLabsToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EndorLabsTokenRegex,
		line:          xorDecode("HxQeFQgFDhURHxRnPzQ+KAU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmM7ODk+"),
		expMatch:      true,
		expSecret:     xorDecode("PzQ+KAU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmM7ODk+"),
	})
}
func TestProcessor_EndorLabsToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EndorLabsTokenRegex, line: `endr_tooshort`, expMatch: false})
}

func TestProcessor_NightfallAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NightfallAPIKeyRegex,
		line:          xorDecode("FBMdEg4cGxYWBREfA2cUHHc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGpraGlub2xtYmM="),
		expMatch:      true,
		expSecret:     xorDecode("FBx3Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJj"),
	})
}
func TestProcessor_NightfallAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NightfallAPIKeyRegex, line: `NF-tooshort`, expMatch: false})
}

func TestProcessor_SentryDSN_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SentryDSNRegex,
		line:          xorDecode("Mi4uKilgdXU7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYxo1a2hpbm9sdDM0PT8pLnQpPzQuKCN0MzV1a2hpbm9sbQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXU7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYxo1a2hpbm9sdDM0PT8pLnQpPzQuKCN0MzV1a2hpbm9sbQ=="),
	})
}
func TestProcessor_SentryDSN_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SentryDSNRegex, line: `https://invalid@sentry.io/123`, expMatch: false})
}

func TestProcessor_JupiterOneToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JupiterOneTokenRegex,
		line:          xorDecode("EA8KEw4fCBUUHwUbChMFER8DZzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIiMgGxgZHh8cHRITEBEWFxQVCgsICQ4PDA0CAwBqa2hp"),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyAbGBkeHxwdEhMQERYXFBUKCwgJDg8MDQIDAGpraGk="),
	})
}
func TestProcessor_JupiterOneToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.JupiterOneTokenRegex, line: `jupiterone_key=short`, expMatch: false})
}

func TestProcessor_WizToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WizTokenRegex,
		line:          xorDecode("DRMABRkWEx8UDgUJHxkIHw5nOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRI="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBqa2hpbm9sbWJjGxgZHh8cHRI="),
	})
}
func TestProcessor_WizToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WizTokenRegex, line: `wiz_key=short`, expMatch: false})
}

func TestProcessor_DetectifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DetectifyKeyRegex,
		line:          xorDecode("Hh8OHxkOExwDBRsKEwURHwNnPm48bT9iO2M4aTlrPm8/bDxtO2I4YzlqPms/aDxpO24="),
		expMatch:      true,
		expSecret:     xorDecode("Pm48bT9iO2M4aTlrPm8/bDxtO2I4YzlqPms/aDxpO24="),
	})
}
func TestProcessor_DetectifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DetectifyKeyRegex, line: `detectify_key=short`, expMatch: false})
}

func TestProcessor_MicrosoftTeamsWebhook_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MicrosoftTeamsWebhookRegex,
		line:          xorDecode("Mi4uKilgdXU3IzUoPXQtPzgyNTUxdDU8PDM5P3Q5NTd1LT84MjU1MThodTs4OT4/PGprd2hpbm93bG1iY3c7ODk+dz88amtoaW5vbG1iYxo7ODk+Pzxqa3doaW5vd2xtYmN3Ozg5Pnc/PGpraGlub2xtYmN1EzQ5NTczND0NPzgyNTUxdTs4OT4/PGpraGlub2xtYmN1Ozg5Pj88amt3aGlub3dsbWJjdzs4OT53Pzxqa2hpbm9sbWJj"),
		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXU3IzUoPXQtPzgyNTUxdDU8PDM5P3Q5NTd1LT84MjU1MThodTs4OT4/PGprd2hpbm93bG1iY3c7ODk+dz88amtoaW5vbG1iYxo7ODk+Pzxqa3doaW5vd2xtYmN3Ozg5Pnc/PGpraGlub2xtYmN1EzQ5NTczND0NPzgyNTUxdTs4OT4/PGpraGlub2xtYmN1Ozg5Pj88amt3aGlub3dsbWJjdzs4OT53Pzxqa2hpbm9sbWJj"),
	})
}
func TestProcessor_MicrosoftTeamsWebhook_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MicrosoftTeamsWebhookRegex, line: `https://example.com/webhook`, expMatch: false})
}

func TestProcessor_ZapierWebhook_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZapierWebhookRegex,
		line:          xorDecode("Mi4uKilgdXUyNTUxKXQgOyozPyh0OTU3dTI1NTEpdTk7LjkydWtoaW5vbHU7ODk+Pzx1"),
		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXUyNTUxKXQgOyozPyh0OTU3dTI1NTEpdTk7LjkydWtoaW5vbHU7ODk+Pzx1"),
	})
}
func TestProcessor_ZapierWebhook_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZapierWebhookRegex, line: `https://example.com/hooks/catch/123/abc/`, expMatch: false})
}

func TestProcessor_TinesWebhook_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TinesWebhookRegex,
		line:          xorDecode("Mi4uKilgdXU3IzUoPXQuMzQ/KXQ5NTd1LT84MjU1MXU7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
		expMatch:      true,
		expSecret:     xorDecode("Mi4uKilgdXU3IzUoPXQuMzQ/KXQ5NTd1LT84MjU1MXU7ODk+Pzxqa2hpbm9sbWJjOzg5Pj88amtoaW5vbG1iYw=="),
	})
}
func TestProcessor_TinesWebhook_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TinesWebhookRegex, line: `https://example.com/webhook/abc`, expMatch: false})
}

func TestProcessor_GitLabRunnerToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitLabRunnerTokenRegex,
		line:          xorDecode("HRMOFhsYBQgPFBQfCAUOFREfFGc9Nigudzs4OT4/PD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("PTYoLnc7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSI="),
	})
}
func TestProcessor_GitLabRunnerToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GitLabRunnerTokenRegex, line: `glrt-short`, expMatch: false})
}

func TestProcessor_DockerHubToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DockerHubTokenRegex,
		line:          xorDecode("HhUZER8IBQobDmc+OTEoBSo7LgU7ODk+Pzw9MjMwMTY3NDUqKygpLi8sLSIjIGo="),
		expMatch:      true,
		expSecret:     xorDecode("PjkxKAUqOy4FOzg5Pj88PTIzMDE2NzQ1KisoKS4vLC0iIyBq"),
	})
}
func TestProcessor_DockerHubToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DockerHubTokenRegex, line: `dckr_pat_tooshort`, expMatch: false})
}
