package builtin_test

import (
	"testing"

	"github.com/afbase/secrets-searcher/pkg/builtin"
)

// Tests for the detectors in processor_regex_upstream.go.
// Fixtures are XOR-encoded like the ones in processor_test.go.

func TestProcessor_AbuseIPDBKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AbuseIPDBKeyRegex,
		line:          xorDecode("GxgPCR8TCh4Yemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5u"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4="),
	})
}
func TestProcessor_AbuseIPDBKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AbuseIPDBKeyRegex, line: `abuseipdb key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AbyssaleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AbyssaleKeyRegex,
		line:          xorDecode("GxgDCQkbFh96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_AbyssaleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AbyssaleKeyRegex, line: `abyssale key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AccuweatherKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AccuweatherKeyRegex,
		line:          xorDecode("GxkZDw0fGw4SHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCk="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCk="),
	})
}
func TestProcessor_AccuweatherKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AccuweatherKeyRegex, line: `accuweather key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AccuweatherKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AccuweatherKeyV2Regex,
		line:          xorDecode("GxkZDw0fGw4SHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_AccuweatherKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AccuweatherKeyV2Regex, line: `accuweather key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AdafruitIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AdafruitIOKeyRegex,
		line:          xorDecode("OzM1BTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY="),
		expMatch:      true,
		expSecret:     xorDecode("OzM1BTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY="),
	})
}
func TestProcessor_AdafruitIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AdafruitIOKeyRegex, line: `adafruitio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AdobeIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AdobeIOKeyRegex,
		line:          xorDecode("Gx4VGB96Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AdobeIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AdobeIOKeyRegex, line: `adobeio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AdzunaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AdzunaKeyRegex,
		line:          xorDecode("Gx4ADxQbemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AdzunaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AdzunaKeyRegex, line: `adzuna key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AeroworkflowKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AeroworkflowKeyRegex,
		line:          xorDecode("Gx8IFQ0VCBEcFhUNemd6eDtrOGg5aT5uP288bBttGGIZYx5q"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_AeroworkflowKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AeroworkflowKeyRegex, line: `aeroworkflow key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AhaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AhaKeyRegex,
		line:          xorDecode("GxIbemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_AhaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AhaKeyRegex, line: `aha key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AirshipKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AirshipKeyRegex,
		line:          xorDecode("GxMICRITCnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2Nw=="),
	})
}
func TestProcessor_AirshipKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AirshipKeyRegex, line: `airship key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AirVisualKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AirVisualKeyRegex,
		line:          xorDecode("GxMIDBMJDxsWemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_AirVisualKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AirVisualKeyRegex, line: `airvisual key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AlconostKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlconostKeyRegex,
		line:          xorDecode("GxYZFRQVCQ56Z3p4O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
	})
}
func TestProcessor_AlconostKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AlconostKeyRegex, line: `alconost key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AlegraKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlegraKeyRegex,
		line:          xorDecode("GxYfHQgbemd6eDtrOGg5aT5uP288bG1iY2o9MjMw"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzA="),
	})
}
func TestProcessor_AlegraKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AlegraKeyRegex, line: `alegra key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AletheiaAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AletheiaAPIKeyRegex,
		line:          xorDecode("GxYfDhIfExsbChN6Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_AletheiaAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AletheiaAPIKeyRegex, line: `aletheiaapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AlienVaultKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AlienVaultKeyRegex,
		line:          xorDecode("GxYTHxQMGw8WDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_AlienVaultKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AlienVaultKeyRegex, line: `alienvault key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AllsportsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AllsportsKeyRegex,
		line:          xorDecode("GxYWCQoVCA4Jemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_AllsportsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AllsportsKeyRegex, line: `allsports key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AmadeusSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AmadeusSecretRegex,
		line:          xorDecode("GxcbHh8PCXpneng7azhoOWk+bj9vPGwbbRhi"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYg=="),
	})
}
func TestProcessor_AmadeusSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AmadeusSecretRegex, line: `amadeus key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AmbeeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AmbeeKeyRegex,
		line:          xorDecode("GxcYHx96Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_AmbeeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AmbeeKeyRegex, line: `ambee key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AnypointKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AnypointKeyRegex,
		line:          xorDecode("GxQDChUTFA56Z3p4O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_AnypointKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AnypointKeyRegex, line: `anypoint key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AnypointOAuth2Secret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AnypointOAuth2SecretRegex,
		line:          xorDecode("GxQDChUTFA56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHDtrOGg5aT5uP28="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHDtrOGg5aT5uP28="),
	})
}
func TestProcessor_AnypointOAuth2Secret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AnypointOAuth2SecretRegex, line: `anypointoauth2 key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ApactaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ApactaKeyRegex,
		line:          xorDecode("GwobGQ4bemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_ApactaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ApactaKeyRegex, line: `apacta key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Api2CartKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Api2CartKeyRegex,
		line:          xorDecode("GwoTaBkbCA56Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_Api2CartKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Api2CartKeyRegex, line: `api2cart key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ApiflashKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ApiflashKeyRegex,
		line:          xorDecode("GwoTHBYbCRJ6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ApiflashKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ApiflashKeyRegex, line: `apiflash key = "REDACTED"`, expMatch: false})
}

func TestProcessor_APIFonicaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.APIFonicaKeyRegex,
		line:          xorDecode("GwoTHBUUExkbemd6eDtrOGg5aT5uP288d2xtYmN3aj0yM3cwMTY3dzQ1KisoKS4vLC0iIw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzx3bG1iY3dqPTIzdzAxNjd3NDUqKygpLi8sLSIj"),
	})
}
func TestProcessor_APIFonicaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.APIFonicaKeyRegex, line: `apifonica key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ApifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ApifyKeyRegex,
		line:          xorDecode("OyozPCMFOyozBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
		expMatch:      true,
		expSecret:     xorDecode("OyozPCMFOyozBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
	})
}
func TestProcessor_ApifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ApifyKeyRegex, line: `apify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ApilayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ApilayerKeyRegex,
		line:          xorDecode("GwoTFhsDHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ApilayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ApilayerKeyRegex, line: `apilayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_APIMaticKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.APIMaticKeyRegex,
		line:          xorDecode("GwoTFxsOExl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_APIMaticKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.APIMaticKeyRegex, line: `apimatic key = "REDACTED"`, expMatch: false})
}

func TestProcessor_APIMetricsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.APIMetricsKeyRegex,
		line:          xorDecode("GwoTFx8OCBMZCXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_APIMetricsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.APIMetricsKeyRegex, line: `apimetrics key = "REDACTED"`, expMatch: false})
}

func TestProcessor_APITemplateKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.APITemplateKeyRegex,
		line:          xorDecode("GwoTDh8XChYbDh96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywt"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywt"),
	})
}
func TestProcessor_APITemplateKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.APITemplateKeyRegex, line: `apitemplate key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AppcuesKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppcuesKeyRegex,
		line:          xorDecode("GwoKGQ8fCXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_AppcuesKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AppcuesKeyRegex, line: `appcues key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AppfollowKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppfollowKeyRegex,
		line:          xorDecode("GwoKHBUWFhUNemd6eD8jEGo/AhszFTMQEQxrCzMWGRAyOB05MxUzEBMPIBNrFDMQY3Q7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bHQbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJ"),
		expMatch:      true,
		expSecret:     xorDecode("PyMQaj8CGzMVMxARDGsLMxYZEDI4HTkzFTMQEw8gE2sUMxBjdDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsdBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAk="),
	})
}
func TestProcessor_AppfollowKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AppfollowKeyRegex, line: `appfollow key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AppointeddKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppointeddKeyRegex,
		line:          xorDecode("GwoKFRMUDh8eHnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMw"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMA=="),
	})
}
func TestProcessor_AppointeddKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AppointeddKeyRegex, line: `appointedd key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AppSynergyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AppSynergyKeyRegex,
		line:          xorDecode("GwoKCQMUHwgdA3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_AppSynergyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AppSynergyKeyRegex, line: `appsynergy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ApptivoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ApptivoKeyRegex,
		line:          xorDecode("GwoKDhMMFXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_ApptivoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ApptivoKeyRegex, line: `apptivo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ArtifactoryAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ArtifactoryAPIKeyRegex,
		line:          xorDecode("GxEZKjtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPg=="),
		expMatch:      true,
		expSecret:     xorDecode("GxEZKjtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPg=="),
	})
}
func TestProcessor_ArtifactoryAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ArtifactoryAPIKeyRegex, line: `artifactory key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ArtifactoryReferenceToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ArtifactoryReferenceTokenRegex,
		line:          xorDecode("OTcMNz4dLi87azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg=="),
		expMatch:      true,
		expSecret:     xorDecode("OTcMNz4dLi87azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg=="),
	})
}
func TestProcessor_ArtifactoryReferenceToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ArtifactoryReferenceTokenRegex, line: `artifactoryreferencetoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ArtsyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ArtsyKeyRegex,
		line:          xorDecode("GwgOCQN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ArtsyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ArtsyKeyRegex, line: `artsy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AteraKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AteraKeyRegex,
		line:          xorDecode("Gw4fCBt6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AteraKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AteraKeyRegex, line: `atera key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BitbucketDataCenterToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitbucketDataCenterTokenRegex,
		line:          xorDecode("GBgeGXc7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0idA=="),
		expMatch:      true,
		expSecret:     xorDecode("GBgeGXc7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
	})
}
func TestProcessor_BitbucketDataCenterToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BitbucketDataCenterTokenRegex, line: `atlassiandatacenter key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AuddKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AuddKeyRegex,
		line:          xorDecode("Gw8eHnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AuddKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AuddKeyRegex, line: `audd key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Auth0ManagementAPIToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Auth0ManagementAPITokenRegex,
		line:          xorDecode("Gw8OEmp6Z3p4PyM7azhoOWk="),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk="),
	})
}
func TestProcessor_Auth0ManagementAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Auth0ManagementAPITokenRegex, line: `auth0managementapitoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AutodeskSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AutodeskSecretRegex,
		line:          xorDecode("Gw8OFR4fCRF6Z3p4O2s4aDlpPm4/bzxsG20YYg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYg=="),
	})
}
func TestProcessor_AutodeskSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AutodeskSecretRegex, line: `autodesk key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AutokloseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AutokloseKeyRegex,
		line:          xorDecode("Gw8OFREWFQkfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_AutokloseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AutokloseKeyRegex, line: `autoklose key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AutoPilotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AutoPilotKeyRegex,
		line:          xorDecode("Gw8OFQoTFhUOemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_AutoPilotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AutoPilotKeyRegex, line: `autopilot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AvazaPersonalAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AvazaPersonalAccessTokenRegex,
		line:          xorDecode("GwwbABt6Z3p4a2hpbm9sd21iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sd21iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg="),
	})
}
func TestProcessor_AvazaPersonalAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AvazaPersonalAccessTokenRegex, line: `avazapersonalaccesstoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AviationStackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AviationStackKeyRegex,
		line:          xorDecode("GwwTGw4TFRQJDhsZEXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AviationStackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AviationStackKeyRegex, line: `aviationstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AWSAppSyncAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSAppSyncAPIKeyRegex,
		line:          xorDecode("PjtodztrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("PjtodztrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUq"),
	})
}
func TestProcessor_AWSAppSyncAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AWSAppSyncAPIKeyRegex, line: `aws key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AxonautKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AxonautKeyRegex,
		line:          xorDecode("GwIVFBsPDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AxonautKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AxonautKeyRegex, line: `axonaut key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AylienKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AylienKeyRegex,
		line:          xorDecode("GwMWEx8Uemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_AylienKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AylienKeyRegex, line: `aylien key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AyrshareKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AyrshareKeyRegex,
		line:          xorDecode("GwMICRIbCB96Z3p4a2hpbm9sG213GGIZYx5qHxx3HRITEBEWFxR3FQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG213GGIZYx5qHxx3HRITEBEWFxR3FQoLCAkODww="),
	})
}
func TestProcessor_AyrshareKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AyrshareKeyRegex, line: `ayrshare key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AzureEntraRefreshToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureEntraRefreshTokenRegex,
		line:          xorDecode("a3QbOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQp0Gz0LCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsI"),
		expMatch:      true,
		expSecret:     xorDecode("a3QbOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQp0Gz0LCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsI"),
	})
}
func TestProcessor_AzureEntraRefreshToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AzureEntraRefreshTokenRegex, line: `azure_entra key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AzureEntraSecretV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureEntraSecretV2Regex,
		line:          xorDecode("dTlpPm4LJD9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC11"),
		expMatch:      true,
		expSecret:     xorDecode("OWk+bgskP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLQ=="),
	})
}
func TestProcessor_AzureEntraSecretV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AzureEntraSecretV2Regex, line: `azure_entra key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AzureDirectManagementKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AzureDirectManagementKeyRegex,
		line:          xorDecode("GwAPCB96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cZ2c="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cZ2c="),
	})
}
func TestProcessor_AzureDirectManagementKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AzureDirectManagementKeyRegex, line: `azuredirectmanagementkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BannerbearKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BannerbearKeyRegex,
		line:          xorDecode("GBsUFB8IGB8bCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cLi4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHC4u"),
	})
}
func TestProcessor_BannerbearKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BannerbearKeyRegex, line: `bannerbear key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BannerbearKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BannerbearKeyV2Regex,
		line:          xorDecode("ODgFKigFO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1i"),
		expMatch:      true,
		expSecret:     xorDecode("ODgFKigFO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1i"),
	})
}
func TestProcessor_BannerbearKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BannerbearKeyV2Regex, line: `bannerbear key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BaremetricsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BaremetricsKeyRegex,
		line:          xorDecode("GBsIHxcfDggTGQl6Z3p4KTEFO2s4aDlpPm4/bzxsG20YYhlj"),
		expMatch:      true,
		expSecret:     xorDecode("KTEFO2s4aDlpPm4/bzxsG20YYhlj"),
	})
}
func TestProcessor_BaremetricsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BaremetricsKeyRegex, line: `baremetrics key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BeamerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BeamerKeyRegex,
		line:          xorDecode("GB8bFx8Iemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SE2c="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITZw=="),
	})
}
func TestProcessor_BeamerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BeamerKeyRegex, line: `beamer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BeeboleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BeeboleKeyRegex,
		line:          xorDecode("GB8fGBUWH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azho"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_BeeboleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BeeboleKeyRegex, line: `beebole key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BesnappyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BesnappyKeyRegex,
		line:          xorDecode("GB8JFBsKCgN6Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_BesnappyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BesnappyKeyRegex, line: `besnappy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BesttimeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BesttimeKeyRegex,
		line:          xorDecode("GB8JDg4TFx96Z3p4KigzBTtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("KigzBTtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_BesttimeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BesttimeKeyRegex, line: `besttime key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BillomatKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BillomatKeyRegex,
		line:          xorDecode("GBMWFhUXGw56Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_BillomatKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BillomatKeyRegex, line: `billomat key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BitbarKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitbarKeyRegex,
		line:          xorDecode("GBMOGBsIemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_BitbarKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BitbarKeyRegex, line: `bitbar key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BitcoinAverageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitcoinAverageKeyRegex,
		line:          xorDecode("GBMOGRUTFBsMHwgbHR96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_BitcoinAverageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BitcoinAverageKeyRegex, line: `bitcoinaverage key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BitfinexSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitfinexSecretRegex,
		line:          xorDecode("GBMOHBMUHwJ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_BitfinexSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BitfinexSecretRegex, line: `bitfinex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BitmexSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BitmexSecretRegex,
		line:          xorDecode("GBMOFx8Cemd6eHo7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERY="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_BitmexSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BitmexSecretRegex, line: `bitmex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BlazemeterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlazemeterKeyRegex,
		line:          xorDecode("GBYbAB8XHw4fCHpneng7azhoOWk+bnc/bzxsd21iY2p3PTIzMHcxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_BlazemeterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BlazemeterKeyRegex, line: `blazemeter key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BlitAppKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlitAppKeyRegex,
		line:          xorDecode("GBYTDhsKCnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywt"),
	})
}
func TestProcessor_BlitAppKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BlitAppKeyRegex, line: `blitapp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BlockNativeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BlockNativeKeyRegex,
		line:          xorDecode("GBYVGREUGw4TDB96Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_BlockNativeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BlockNativeKeyRegex, line: `blocknative key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BombBombKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BombBombKeyRegex,
		line:          xorDecode("GBUXGBgVFxh6Z3p4PyMiPyMi"),
		expMatch:      true,
		expSecret:     xorDecode("PyMiPyMi"),
	})
}
func TestProcessor_BombBombKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BombBombKeyRegex, line: `bombbomb key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BoostNoteKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BoostNoteKeyRegex,
		line:          xorDecode("GBUVCQ4UFQ4femd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_BoostNoteKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BoostNoteKeyRegex, line: `boostnote key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BorgbaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BorgbaseKeyRegex,
		line:          xorDecode("GBUIHRgbCR96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9Mg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9Mg=="),
	})
}
func TestProcessor_BorgbaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BorgbaseKeyRegex, line: `borgbase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BoxKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BoxKeyRegex,
		line:          xorDecode("GBUCGRUXemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_BoxKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BoxKeyRegex, line: `box key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BraintreePaymentsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BraintreePaymentsKeyRegex,
		line:          xorDecode("GAgbExQOCB8femd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_BraintreePaymentsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BraintreePaymentsKeyRegex, line: `braintreepayments key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BrainTrustAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrainTrustAPIKeyRegex,
		line:          xorDecode("KTF3O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
		expMatch:      true,
		expSecret:     xorDecode("KTF3O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_BrainTrustAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BrainTrustAPIKeyRegex, line: `braintrust key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BrandfetchKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrandfetchKeyRegex,
		line:          xorDecode("GAgbFB4cHw4ZEnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_BrandfetchKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BrandfetchKeyRegex, line: `brandfetch key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BrandfetchKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrandfetchKeyV2Regex,
		line:          xorDecode("GAgbFB4cHw4ZEnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdZw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHWc="),
	})
}
func TestProcessor_BrandfetchKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BrandfetchKeyV2Regex, line: `brandfetch key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BrowshotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BrowshotKeyRegex,
		line:          xorDecode("GAgVDQkSFQ56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNg=="),
	})
}
func TestProcessor_BrowshotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BrowshotKeyRegex, line: `browshot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BuddyNSKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BuddyNSKeyRegex,
		line:          xorDecode("GA8eHgMUCXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azho"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_BuddyNSKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BuddyNSKeyRegex, line: `buddyns key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BudibaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BudibaseKeyRegex,
		line:          xorDecode("GA8eExgbCR96Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2p3O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2p3O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1i"),
	})
}
func TestProcessor_BudibaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BudibaseKeyRegex, line: `budibase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BugherdKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BugherdKeyRegex,
		line:          xorDecode("GA8dEh8IHnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNg=="),
	})
}
func TestProcessor_BugherdKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BugherdKeyRegex, line: `bugherd key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BulbulKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BulbulKeyRegex,
		line:          xorDecode("GA8WGA8Wemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_BulbulKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BulbulKeyRegex, line: `bulbul key = "REDACTED"`, expMatch: false})
}

func TestProcessor_BulksmsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.BulksmsKeyRegex,
		line:          xorDecode("GA8WEQkXCXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2Nw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc="),
	})
}
func TestProcessor_BulksmsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.BulksmsKeyRegex, line: `bulksms key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CaflouKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CaflouKeyRegex,
		line:          xorDecode("PyMQMjgdOTMVMxATDyATaxQzEGM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzw="),
		expMatch:      true,
		expSecret:     xorDecode("PyMQMjgdOTMVMxATDyATaxQzEGM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzw="),
	})
}
func TestProcessor_CaflouKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CaflouKeyRegex, line: `caflou key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CalendarificKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CalendarificKeyRegex,
		line:          xorDecode("GRsWHxQeGwgTHBMZemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_CalendarificKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CalendarificKeyRegex, line: `calendarific key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CalorieNinjaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CalorieNinjaKeyRegex,
		line:          xorDecode("GRsWFQgTHxQTFBAbemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_CalorieNinjaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CalorieNinjaKeyRegex, line: `calorieninja key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CampaynKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CampaynKeyRegex,
		line:          xorDecode("GRsXChsDFHpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_CampaynKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CampaynKeyRegex, line: `campayn key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CannyIoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CannyIoKeyRegex,
		line:          xorDecode("GRsUFAN6Z3p4O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_CannyIoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CannyIoKeyRegex, line: `cannyio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CapsuleCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CapsuleCRMKeyRegex,
		line:          xorDecode("GRsKCQ8WHxkIF3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtr"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_CapsuleCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CapsuleCRMKeyRegex, line: `capsulecrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CaptainDataKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CaptainDataKeyRegex,
		line:          xorDecode("GRsKDhsTFB4bDht6Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_CaptainDataKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CaptainDataKeyRegex, line: `captaindata key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CarbonInterfaceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CarbonInterfaceKeyRegex,
		line:          xorDecode("GRsIGBUUExQOHwgcGxkfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmof"),
	})
}
func TestProcessor_CarbonInterfaceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CarbonInterfaceKeyRegex, line: `carboninterface key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CashboardKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CashboardKeyRegex,
		line:          xorDecode("GRsJEhgVGwgeemd6eGtoaXdub2x3G20Yd2IZYw=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpd25vbHcbbRh3Yhlj"),
	})
}
func TestProcessor_CashboardKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CashboardKeyRegex, line: `cashboard key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CaspioKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CaspioKeyRegex,
		line:          xorDecode("GRsJChMVemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWI="),
	})
}
func TestProcessor_CaspioKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CaspioKeyRegex, line: `caspio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CentralStationCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CentralStationCRMKeyRegex,
		line:          xorDecode("GR8UDggbFgkOGw4TFRR6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCku"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_CentralStationCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CentralStationCRMKeyRegex, line: `centralstationcrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CexIOSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CexIOSecretRegex,
		line:          xorDecode("GR8CExV6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_CexIOSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CexIOSecretRegex, line: `cexio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ChartmogulKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChartmogulKeyRegex,
		line:          xorDecode("GRIbCA4XFR0PFnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ChartmogulKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ChartmogulKeyRegex, line: `chartmogul key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ChatbotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChatbotKeyRegex,
		line:          xorDecode("GRIbDhgVDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ChatbotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ChatbotKeyRegex, line: `chatbot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ChatfuleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChatfuleKeyRegex,
		line:          xorDecode("GRIbDhwPHxZ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg="),
	})
}
func TestProcessor_ChatfuleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ChatfuleKeyRegex, line: `chatfule key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ChecIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChecIOKeyRegex,
		line:          xorDecode("GRIfGRMVemd6eCoxBTtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uPw=="),
		expMatch:      true,
		expSecret:     xorDecode("KjEFO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/"),
	})
}
func TestProcessor_ChecIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ChecIOKeyRegex, line: `checio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ChecklyHQKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ChecklyHQKeyRegex,
		line:          xorDecode("GRIfGREWAxILemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ChecklyHQKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ChecklyHQKeyRegex, line: `checklyhq key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CheckoutKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CheckoutKeyRegex,
		line:          xorDecode("GRIfGREVDw56Z3p4KTEFO2s4aDlpPm53P288bHcbbRhidxljHmp3Hxw7azhoOWk+bj9v"),
		expMatch:      true,
		expSecret:     xorDecode("KTEFO2s4aDlpPm53P288bHcbbRhidxljHmp3Hxw7azhoOWk+bj9v"),
	})
}
func TestProcessor_CheckoutKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CheckoutKeyRegex, line: `checkout key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CheckvistKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CheckvistKeyRegex,
		line:          xorDecode("GRIfGREMEwkOemd6eDtrOGg5aT5uP288bBtt"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20="),
	})
}
func TestProcessor_CheckvistKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CheckvistKeyRegex, line: `checkvist key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CiceroKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CiceroKeyRegex,
		line:          xorDecode("GRMZHwgVemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_CiceroKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CiceroKeyRegex, line: `cicero key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClarifaiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClarifaiKeyRegex,
		line:          xorDecode("GRYbCBMcGxN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ClarifaiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClarifaiKeyRegex, line: `clarifai key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClickHelpKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClickHelpKeyRegex,
		line:          xorDecode("GRYTGRESHxYKemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9Mg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_ClickHelpKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClickHelpKeyRegex, line: `clickhelp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClickSendsmsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClickSendsmsKeyRegex,
		line:          xorDecode("GRYTGREJHxQeCRcJemd6eGtoaW5vbBttdxhiGWN3HmofHHcdEhMQdxEWFxQVCgsICQ4PDA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG213GGIZY3ceah8cdx0SExB3ERYXFBUKCwgJDg8M"),
	})
}
func TestProcessor_ClickSendsmsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClickSendsmsKeyRegex, line: `clicksendsms key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CliengoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CliengoKeyRegex,
		line:          xorDecode("GRYTHxQdFXpneng7azhoOWk+bnc/bzxsd21iY2p3O2s4aHc5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_CliengoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CliengoKeyRegex, line: `cliengo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClientaryKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClientaryKeyRegex,
		line:          xorDecode("CBUUExR6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_ClientaryKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClientaryKeyRegex, line: `clientary key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClinchpadKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClinchpadKeyRegex,
		line:          xorDecode("GRYTFBkSChseemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ClinchpadKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClinchpadKeyRegex, line: `clinchpad key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClockifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClockifyKeyRegex,
		line:          xorDecode("GRYVGRETHAN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_ClockifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClockifyKeyRegex, line: `clockify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClockworkSMSToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClockworkSMSTokenRegex,
		line:          xorDecode("GRYVGRENFQgRemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9Mg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_ClockworkSMSToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClockworkSMSTokenRegex, line: `clockworksms key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudConvertKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudConvertKeyRegex,
		line:          xorDecode("GRYVDx4ZFRQMHwgOemd6eD8jO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0Ij8jNSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRIiExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQiPyM1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEiITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTI="),
	})
}
func TestProcessor_CloudConvertKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudConvertKeyRegex, line: `cloudconvert key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudElementsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudElementsKeyRegex,
		line:          xorDecode("GRYVDx4fFh8XHxQOCXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAd"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_CloudElementsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudElementsKeyRegex, line: `cloudelements key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudflareAPITokenV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudflareAPITokenV2Regex,
		line:          xorDecode("OTw7LgVrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjO2s4aDlpPm4="),
		expMatch:      true,
		expSecret:     xorDecode("OTw7LgVrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjO2s4aDlpPm4="),
	})
}
func TestProcessor_CloudflareAPITokenV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudflareAPITokenV2Regex, line: `cloudflareapitoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudflareGlobalAPIKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudflareGlobalAPIKeyV2Regex,
		line:          xorDecode("OTwxBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("OTwxBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI7azhoOWk+bg=="),
	})
}
func TestProcessor_CloudflareGlobalAPIKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudflareGlobalAPIKeyV2Regex, line: `cloudflareglobalapikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudImageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudImageKeyRegex,
		line:          xorDecode("GRYVDx4TFxsdH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_CloudImageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudImageKeyRegex, line: `cloudimage key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudmersiveKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudmersiveKeyRegex,
		line:          xorDecode("GRYVDx4XHwgJEwwfemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_CloudmersiveKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudmersiveKeyRegex, line: `cloudmersive key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloudplanKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloudplanKeyRegex,
		line:          xorDecode("GRYVDx4KFhsUemd6eGtoaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8M"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_CloudplanKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloudplanKeyRegex, line: `cloudplan key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CloverlyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CloverlyKeyRegex,
		line:          xorDecode("GRYVDB8IFgN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_CloverlyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CloverlyKeyRegex, line: `cloverly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClozeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClozeKeyRegex,
		line:          xorDecode("GRYVAB96Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_ClozeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClozeKeyRegex, line: `cloze key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ClustDocKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ClustDocKeyRegex,
		line:          xorDecode("GRYPCQ4eFRl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_ClustDocKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ClustDocKeyRegex, line: `clustdoc key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CodaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CodaKeyRegex,
		line:          xorDecode("GRUeG3pneng7azhoOWk+bnc/bzxsd21iY2p3PTIzMHcxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_CodaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CodaKeyRegex, line: `coda key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CodequiryKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CodequiryKeyRegex,
		line:          xorDecode("GRUeHwsPEwgDemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_CodequiryKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CodequiryKeyRegex, line: `codequiry key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CoinAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinAPIKeyRegex,
		line:          xorDecode("GRUTFBsKE3pnenhraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsICQ4PDA0CAwA="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMA"),
	})
}
func TestProcessor_CoinAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CoinAPIKeyRegex, line: `coinapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CoinlayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinlayerKeyRegex,
		line:          xorDecode("GRUTFBYbAx8Iemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_CoinlayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CoinlayerKeyRegex, line: `coinlayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CoinlibKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CoinlibKeyRegex,
		line:          xorDecode("GRUTFBYTGHpneng7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_CoinlibKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CoinlibKeyRegex, line: `coinlib key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Collect2Key_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Collect2KeyRegex,
		line:          xorDecode("GRUWFh8ZDmh6Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_Collect2Key_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Collect2KeyRegex, line: `collect2 key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ColumnKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ColumnKeyRegex,
		line:          xorDecode("GRUWDxcUemd6eC4/KS4FO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAx"),
		expMatch:      true,
		expSecret:     xorDecode("Lj8pLgU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE="),
	})
}
func TestProcessor_ColumnKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ColumnKeyRegex, line: `column key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CommerceJSKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CommerceJSKeyRegex,
		line:          xorDecode("GRUXFx8IGR8QCXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxs"),
	})
}
func TestProcessor_CommerceJSKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CommerceJSKeyRegex, line: `commercejs key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CommoditiesKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CommoditiesKeyRegex,
		line:          xorDecode("GRUXFxUeEw4THwl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_CommoditiesKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CommoditiesKeyRegex, line: `commodities key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CompanyHubKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CompanyHubKeyRegex,
		line:          xorDecode("GRUXChsUAxIPGHpneng7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_CompanyHubKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CompanyHubKeyRegex, line: `companyhub key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ConversionToolsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConversionToolsKeyRegex,
		line:          xorDecode("GRUUDB8ICRMVFA4VFRYJemd6eD8jO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKw=="),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSor"),
	})
}
func TestProcessor_ConversionToolsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ConversionToolsKeyRegex, line: `conversiontools key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ConvertAPISecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConvertAPISecretRegex,
		line:          xorDecode("GRUUDB8IDhsKE3pnengpPzkoPy4FO2s4aDlpPm4/bzxsG20YYg=="),
		expMatch:      true,
		expSecret:     xorDecode("KT85KD8uBTtrOGg5aT5uP288bBttGGI="),
	})
}
func TestProcessor_ConvertAPISecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ConvertAPISecretRegex, line: `convertapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ConvierKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ConvierKeyRegex,
		line:          xorDecode("GRUUDBMfCHpnenhraCY5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0S"),
		expMatch:      true,
		expSecret:     xorDecode("a2gmOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEg=="),
	})
}
func TestProcessor_ConvierKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ConvierKeyRegex, line: `convier key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CountryLayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CountryLayerKeyRegex,
		line:          xorDecode("GRUPFA4IAxYbAx8Iemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_CountryLayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CountryLayerKeyRegex, line: `countrylayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CraftMyPDFKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CraftMyPDFKeyRegex,
		line:          xorDecode("GQgbHA4XAwoeHHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCk="),
	})
}
func TestProcessor_CraftMyPDFKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CraftMyPDFKeyRegex, line: `craftmypdf key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CrowdinKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CrowdinKeyRegex,
		line:          xorDecode("GQgVDR4TFHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWM="),
	})
}
func TestProcessor_CrowdinKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CrowdinKeyRegex, line: `crowdin key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CryptoCompareKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CryptoCompareKeyRegex,
		line:          xorDecode("GQgDCg4VGRUXChsIH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_CryptoCompareKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CryptoCompareKeyRegex, line: `cryptocompare key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CurrencyCloudKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CurrencyCloudKeyRegex,
		line:          xorDecode("GQ8ICB8UGQMZFhUPHnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_CurrencyCloudKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CurrencyCloudKeyRegex, line: `currencycloud key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CurrencyfreaksKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CurrencyfreaksKeyRegex,
		line:          xorDecode("GQ8ICB8UGQMcCB8bEQl6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_CurrencyfreaksKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CurrencyfreaksKeyRegex, line: `currencyfreaks key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CurrencylayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CurrencylayerKeyRegex,
		line:          xorDecode("GQ8ICB8UGQMWGwMfCHpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_CurrencylayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CurrencylayerKeyRegex, line: `currencylayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CurrencyScoopKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CurrencyScoopKeyRegex,
		line:          xorDecode("GQ8ICB8UGQMJGRUVCnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_CurrencyScoopKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CurrencyScoopKeyRegex, line: `currencyscoop key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CurrentsAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CurrentsAPIKeyRegex,
		line:          xorDecode("GQ8ICB8UDgkbChN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_CurrentsAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CurrentsAPIKeyRegex, line: `currentsapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_CustomerGuruKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.CustomerGuruKeyRegex,
		line:          xorDecode("HQ8ID3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0"),
	})
}
func TestProcessor_CustomerGuruKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.CustomerGuruKeyRegex, line: `customerguru key = "REDACTED"`, expMatch: false})
}

func TestProcessor_D7NetworkKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.D7NetworkKeyRegex,
		line:          xorDecode("Hm0UHw4NFQgRemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9Zw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD1n"),
	})
}
func TestProcessor_D7NetworkKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.D7NetworkKeyRegex, line: `d7network key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DandelionKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DandelionKeyRegex,
		line:          xorDecode("HhsUHh8WExUUemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_DandelionKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DandelionKeyRegex, line: `dandelion key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DareboostKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DareboostKeyRegex,
		line:          xorDecode("HhsIHxgVFQkOemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_DareboostKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DareboostKeyRegex, line: `dareboost key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DataboxKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DataboxKeyRegex,
		line:          xorDecode("HhsOGxgVAnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAx"),
	})
}
func TestProcessor_DataboxKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DataboxKeyRegex, line: `databox key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DataGovKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DataGovKeyRegex,
		line:          xorDecode("HhsOG3QdFQx6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_DataGovKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DataGovKeyRegex, line: `datagov key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DebounceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DebounceKeyRegex,
		line:          xorDecode("Hh8YFQ8UGR96Z3p4O2s4aDlpPm4/bzxsGw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsGw=="),
	})
}
func TestProcessor_DebounceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DebounceKeyRegex, line: `debounce key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DeepAIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DeepAIKeyRegex,
		line:          xorDecode("Hh8fChsTemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_DeepAIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DeepAIKeyRegex, line: `deepai key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DelightedKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DelightedKeyRegex,
		line:          xorDecode("Hh8WEx0SDh8eemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_DelightedKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DelightedKeyRegex, line: `delighted key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DemioSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DemioSecretRegex,
		line:          xorDecode("Hh8XExV6Z3p4O2s4aDlpPm4/bw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bw=="),
	})
}
func TestProcessor_DemioSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DemioSecretRegex, line: `demio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DenoDeployToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DenoDeployTokenRegex,
		line:          xorDecode("Pj4qBSsoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Pj4qBSsoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aQ=="),
	})
}
func TestProcessor_DenoDeployToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DenoDeployTokenRegex, line: `deno key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DeputyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DeputyKeyRegex,
		line:          xorDecode("Hh8KDw4Demd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_DeputyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DeputyKeyRegex, line: `deputy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DetectLanguageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DetectLanguageKeyRegex,
		line:          xorDecode("Hh8OHxkOFhsUHQ8bHR96Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_DetectLanguageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DetectLanguageKeyRegex, line: `detectlanguage key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DfuseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DfuseKeyRegex,
		line:          xorDecode("LT84BTtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("LT84BTtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_DfuseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DfuseKeyRegex, line: `dfuse key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DiffbotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DiffbotKeyRegex,
		line:          xorDecode("HhMcHBgVDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_DiffbotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DiffbotKeyRegex, line: `diffbot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DiggernautKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DiggernautKeyRegex,
		line:          xorDecode("HhMdHR8IFBsPDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azho"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_DiggernautKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DiggernautKeyRegex, line: `diggernaut key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DisqusKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DisqusKeyRegex,
		line:          xorDecode("HhMJCw8Jemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_DisqusKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DisqusKeyRegex, line: `disqus key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DittoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DittoKeyRegex,
		line:          xorDecode("HhMODhV6Z3p4O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8sdC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8sdC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA="),
	})
}
func TestProcessor_DittoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DittoKeyRegex, line: `ditto key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DnscheckKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DnscheckKeyRegex,
		line:          xorDecode("HhQJGRIfGRF6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_DnscheckKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DnscheckKeyRegex, line: `dnscheck key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DockerAuthConfig_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DockerAuthConfigRegex,
		line:          xorDecode("IXg7Ly4yKXhgIXg7azhoOWl4YCF4Gw8OEnhgeHpnenh4eBsPDhJ4YHh6Z3p4eHgbDw4SeGB4emd6eHh4Gw8OEnhgeHpnenh4eBsPDhJ4YHh6Z3p4eHgbDw4SeGB4emd6eHgnJyc="),
		expMatch:      true,
		expSecret:     xorDecode("IXg7Ly4yKXhgIXg7azhoOWl4YCF4Gw8OEnhgeHpnenh4eBsPDhJ4YHh6Z3p4eHgbDw4SeGB4emd6eHh4Gw8OEnhgeHpnenh4eBsPDhJ4YHh6Z3p4eHgbDw4SeGB4emd6eHgnJyc="),
	})
}
func TestProcessor_DockerAuthConfig_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DockerAuthConfigRegex, line: `docker key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DocparserKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DocparserKeyRegex,
		line:          xorDecode("HhUZChsICR8Iemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_DocparserKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DocparserKeyRegex, line: `docparser key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DocumoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DocumoKeyRegex,
		line:          xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoIj8jKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7ayI4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRIT"),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoIj8jKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7ayI4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRIT"),
	})
}
func TestProcessor_DocumoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DocumoKeyRegex, line: `documo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DovicoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DovicoKeyRegex,
		line:          xorDecode("HhUMExkVemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sdC0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyx0LQ=="),
	})
}
func TestProcessor_DovicoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DovicoKeyRegex, line: `dovico key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DronaHQKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DronaHQKeyRegex,
		line:          xorDecode("HggVFBsSC3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWI="),
	})
}
func TestProcessor_DronaHQKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DronaHQKeyRegex, line: `dronahq key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DuffelToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DuffelTokenRegex,
		line:          xorDecode("Pi88PD82BS4/KS4FO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Pi88PD82BS4/KS4FO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_DuffelToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DuffelTokenRegex, line: `duffeltoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DuoSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DuoSecretRegex,
		line:          xorDecode("Hg8Vemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_DuoSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DuoSecretRegex, line: `duo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DuplyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DuplyKeyRegex,
		line:          xorDecode("Hg8KFgN6Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_DuplyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DuplyKeyRegex, line: `duply key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DynalistKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DynalistKeyRegex,
		line:          xorDecode("HgMUGxYTCQ56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg="),
	})
}
func TestProcessor_DynalistKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DynalistKeyRegex, line: `dynalist key = "REDACTED"`, expMatch: false})
}

func TestProcessor_DyspatchKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.DyspatchKeyRegex,
		line:          xorDecode("HgMJChsOGRJ6Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhljHmofHA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhljHmofHA=="),
	})
}
func TestProcessor_DyspatchKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.DyspatchKeyRegex, line: `dyspatch key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EagleEyeNetworksKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EagleEyeNetworksKeyRegex,
		line:          xorDecode("HxsdFh8fAx8UHw4NFQgRCXpneng7azhoOWk+bj9vPGwbbRg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20Y"),
	})
}
func TestProcessor_EagleEyeNetworksKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EagleEyeNetworksKeyRegex, line: `eagleeyenetworks key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EasyInsightKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EasyInsightKeyRegex,
		line:          xorDecode("HxsJAxMUCRMdEg56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_EasyInsightKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EasyInsightKeyRegex, line: `easyinsight key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EcoStruxureITKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EcoStruxureITKeyRegex,
		line:          xorDecode("HxkVCQ4IDwIPCB8TDnpnengbEWs7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFA=="),
		expMatch:      true,
		expSecret:     xorDecode("GxFrO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQ="),
	})
}
func TestProcessor_EcoStruxureITKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EcoStruxureITKeyRegex, line: `ecostruxureit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EdamamKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EdamamKeyRegex,
		line:          xorDecode("Hx4bFxsXemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_EdamamKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EdamamKeyRegex, line: `edamam key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EdenAIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EdenAIKeyRegex,
		line:          xorDecode("Hx4fFBsTemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLiIvLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aCI5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExAR"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuIi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoIjlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBE="),
	})
}
func TestProcessor_EdenAIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EdenAIKeyRegex, line: `edenai key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EightxEightKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EightxEightKeyRegex,
		line:          xorDecode("YgJiemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_EightxEightKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EightxEightKeyRegex, line: `eightxeight key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ElasticEmailKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ElasticEmailKeyRegex,
		line:          xorDecode("HxYbCQ4TGXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kiso"),
	})
}
func TestProcessor_ElasticEmailKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ElasticEmailKeyRegex, line: `elasticemail key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EnablexKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EnablexKeyRegex,
		line:          xorDecode("HxQbGBYfAnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_EnablexKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EnablexKeyRegex, line: `enablex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EndorLabsAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EndorLabsAPIKeyRegex,
		line:          xorDecode("PzQ+KHE7azhoOWk+bj9vPGwbbRhi"),
		expMatch:      true,
		expSecret:     xorDecode("PzQ+KHE7azhoOWk+bj9vPGwbbRhi"),
	})
}
func TestProcessor_EndorLabsAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EndorLabsAPIKeyRegex, line: `endorlabs key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EnigmaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EnigmaKeyRegex,
		line:          xorDecode("HxQTHRcbemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_EnigmaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EnigmaKeyRegex, line: `enigma key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EnvoyAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EnvoyAPIKeyRegex,
		line:          xorDecode("HxQMFQN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_EnvoyAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EnvoyAPIKeyRegex, line: `envoyapikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EraserKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EraserKeyRegex,
		line:          xorDecode("HwgbCR8Iemd6eDtrOGg5aT5uP288bBttGGIZYx5q"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_EraserKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EraserKeyRegex, line: `eraser key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EthplorerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EthplorerKeyRegex,
		line:          xorDecode("Hw4SChYVCB8Iemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHA=="),
	})
}
func TestProcessor_EthplorerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EthplorerKeyRegex, line: `ethplorer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_EverhourKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.EverhourKeyRegex,
		line:          xorDecode("HwwfCBIVDwh6Z3p4O2s4aHc5aT5udz9vPGxtYndjajtrOGh3OWk+bj9vPGw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aHc5aT5udz9vPGxtYndjajtrOGh3OWk+bj9vPGw="),
	})
}
func TestProcessor_EverhourKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.EverhourKeyRegex, line: `everhour key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ExchangeRateAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ExchangeRateAPIKeyRegex,
		line:          xorDecode("HwIZEhsUHR8IGw4femd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5u"),
	})
}
func TestProcessor_ExchangeRateAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ExchangeRateAPIKeyRegex, line: `exchangerateapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ExchangeRatesAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ExchangeRatesAPIKeyRegex,
		line:          xorDecode("HwIZEhsUHR8IGw4fCXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ExchangeRatesAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ExchangeRatesAPIKeyRegex, line: `exchangeratesapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ExportSDKKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ExportSDKKeyRegex,
		line:          xorDecode("HwIKFQgOCR4Remd6eDtrOGg5BWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDkFaT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5"),
	})
}
func TestProcessor_ExportSDKKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ExportSDKKeyRegex, line: `exportsdk key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ExtractorAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ExtractorAPIKeyRegex,
		line:          xorDecode("HwIOCBsZDhUIGwoTemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_ExtractorAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ExtractorAPIKeyRegex, line: `extractorapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FacePlusPlusSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FacePlusPlusSecretRegex,
		line:          xorDecode("HBsZHwoWDwkKFg8Jemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_FacePlusPlusSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FacePlusPlusSecretRegex, line: `faceplusplus key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FastForexKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FastForexKeyRegex,
		line:          xorDecode("HBsJDhwVCB8Cemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_FastForexKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FastForexKeyRegex, line: `fastforex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FeedierKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FeedierKeyRegex,
		line:          xorDecode("HB8fHhMfCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_FeedierKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FeedierKeyRegex, line: `feedier key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FetchrssKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FetchrssKeyRegex,
		line:          xorDecode("HB8OGRIICQl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_FetchrssKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FetchrssKeyRegex, line: `fetchrss key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FiberyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FiberyKeyRegex,
		line:          xorDecode("HBMYHwgDemd6eDtrOGg5aT5udD9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm50P288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzw="),
	})
}
func TestProcessor_FiberyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FiberyKeyRegex, line: `fibery key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FigmaPATV3_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FigmaPATV3Regex,
		line:          xorDecode("PDM9KgU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0idA=="),
		expMatch:      true,
		expSecret:     xorDecode("PDM9KgU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
	})
}
func TestProcessor_FigmaPATV3_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FigmaPATV3Regex, line: `figmapersonalaccesstoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FileIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FileIOKeyRegex,
		line:          xorDecode("HBMWHxMVemd6eGtoaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8MDQIDAGtoaQ=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hp"),
	})
}
func TestProcessor_FileIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FileIOKeyRegex, line: `fileio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FinageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FinageKeyRegex,
		line:          xorDecode("GwoTBREfA2toaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8M"),
		expMatch:      true,
		expSecret:     xorDecode("GwoTBREfA2toaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8M"),
	})
}
func TestProcessor_FinageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FinageKeyRegex, line: `finage key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FinancialModelingPrepKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FinancialModelingPrepKeyRegex,
		line:          xorDecode("HBMUGxQZExsWFxUeHxYTFB0KCB8Kemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_FinancialModelingPrepKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FinancialModelingPrepKeyRegex, line: `financialmodelingprep key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FindlKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FindlKeyRegex,
		line:          xorDecode("HBMUHhZ6Z3p4O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_FindlKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FindlKeyRegex, line: `findl key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FixerIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FixerIOKeyRegex,
		line:          xorDecode("HBMCHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_FixerIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FixerIOKeyRegex, line: `fixerio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlatIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlatIOKeyRegex,
		line:          xorDecode("HBYbDhMVemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMw"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzA="),
	})
}
func TestProcessor_FlatIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlatIOKeyRegex, line: `flatio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FleetbaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FleetbaseKeyRegex,
		line:          xorDecode("PDY4BTYzLD8FO2s4aDlpPm4/bzxsG20YYhljHmo="),
		expMatch:      true,
		expSecret:     xorDecode("PDY4BTYzLD8FO2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_FleetbaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FleetbaseKeyRegex, line: `fleetbase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlexportKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlexportKeyRegex,
		line:          xorDecode("KTI2LjcFO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("KTI2LjcFO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_FlexportKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlexportKeyRegex, line: `flexport key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlickrKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlickrKeyRegex,
		line:          xorDecode("HBYTGREIemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_FlickrKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlickrKeyRegex, line: `flickr key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlightAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlightAPIKeyRegex,
		line:          xorDecode("HBYTHRIOGwoTemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0"),
	})
}
func TestProcessor_FlightAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlightAPIKeyRegex, line: `flightapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlightLabsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlightLabsKeyRegex,
		line:          xorDecode("PyMQaj8CGzMVMxARDGsLMxYZEDI4HTkzFTMQCQ8gE2sUMxBjdD8jO2s4aDlpdD5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0"),
		expMatch:      true,
		expSecret:     xorDecode("PyMQaj8CGzMVMxARDGsLMxYZEDI4HTkzFTMQCQ8gE2sUMxBjdD8jO2s4aDlpdD5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0"),
	})
}
func TestProcessor_FlightLabsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlightLabsKeyRegex, line: `flightlabs key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlightstatsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlightstatsKeyRegex,
		line:          xorDecode("HBYTHRIOCQ4bDgl6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_FlightstatsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlightstatsKeyRegex, line: `flightstats key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FloatKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FloatKeyRegex,
		line:          xorDecode("HBYVGw56Z3p4O2s4aDlpPm4/bzxsbWJjah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDAGc="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDAGc="),
	})
}
func TestProcessor_FloatKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FloatKeyRegex, line: `float key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FlowFluKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FlowFluKeyRegex,
		line:          xorDecode("HBYVDRwWD3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBU="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQV"),
	})
}
func TestProcessor_FlowFluKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FlowFluKeyRegex, line: `flowflu key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FmfwKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FmfwKeyRegex,
		line:          xorDecode("HBccDXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_FmfwKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FmfwKeyRegex, line: `fmfw key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FormcraftKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FormcraftKeyRegex,
		line:          xorDecode("HBUIFxkIGxwOemd6eDtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_FormcraftKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FormcraftKeyRegex, line: `formcraft key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FormsiteKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FormsiteKeyRegex,
		line:          xorDecode("HBUIFwkTDh96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_FormsiteKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FormsiteKeyRegex, line: `formsite key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FourSquareSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FourSquareSecretRegex,
		line:          xorDecode("HBUPCAkLDxsIH3pnenhraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsICQ4PDA0CAwBraGlub2wbbRhiGWM="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhlj"),
	})
}
func TestProcessor_FourSquareSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FourSquareSecretRegex, line: `foursquare key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FrontKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FrontKeyRegex,
		line:          xorDecode("HAgVFA56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuIi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuIi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_FrontKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FrontKeyRegex, line: `front key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FulcrumKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FulcrumKeyRegex,
		line:          xorDecode("HA8WGQgPF3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4="),
	})
}
func TestProcessor_FulcrumKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FulcrumKeyRegex, line: `fulcrum key = "REDACTED"`, expMatch: false})
}

func TestProcessor_FXMarketKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.FXMarketKeyRegex,
		line:          xorDecode("HAIXGwgRHw56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_FXMarketKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.FXMarketKeyRegex, line: `fxmarket key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeckoboardKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeckoboardKeyRegex,
		line:          xorDecode("HR8ZERUYFRsIHnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_GeckoboardKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeckoboardKeyRegex, line: `geckoboard key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeminiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeminiKeyRegex,
		line:          xorDecode("NzspLj8odztrOGg5aT5uP288bBttGGIZYx5q"),
		expMatch:      true,
		expSecret:     xorDecode("NzspLj8odztrOGg5aT5uP288bBttGGIZYx5q"),
	})
}
func TestProcessor_GeminiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeminiKeyRegex, line: `gemini key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GengoSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GengoSecretRegex,
		line:          xorDecode("HR8UHRV6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7a3o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_GengoSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GengoSecretRegex, line: `gengo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeoapifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeoapifyKeyRegex,
		line:          xorDecode("HR8VGwoTHAN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_GeoapifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeoapifyKeyRegex, line: `geoapify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeocodeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeocodeKeyRegex,
		line:          xorDecode("HR8VGRUeH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_GeocodeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeocodeKeyRegex, line: `geocode key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeocodifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeocodifyKeyRegex,
		line:          xorDecode("HR8VGRUeExwDemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_GeocodifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeocodifyKeyRegex, line: `geocodify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeocodioKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeocodioKeyRegex,
		line:          xorDecode("HR8VGRUeemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4"),
	})
}
func TestProcessor_GeocodioKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeocodioKeyRegex, line: `geocodio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GeoIpifiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GeoIpifiKeyRegex,
		line:          xorDecode("EwoTHBN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_GeoIpifiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GeoIpifiKeyRegex, line: `geoipifi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GetEmailKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetEmailKeyRegex,
		line:          xorDecode("HR8OHxcbExZ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_GetEmailKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GetEmailKeyRegex, line: `getemail key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GetEmailsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetEmailsKeyRegex,
		line:          xorDecode("HR8OHxcbExYJemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSo="),
	})
}
func TestProcessor_GetEmailsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GetEmailsKeyRegex, line: `getemails key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GetGeoAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetGeoAPIKeyRegex,
		line:          xorDecode("HR8OHR8VGwoTemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_GetGeoAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GetGeoAPIKeyRegex, line: `getgeoapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GetgistKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetgistKeyRegex,
		line:          xorDecode("HR8OHRMJDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk="),
	})
}
func TestProcessor_GetgistKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GetgistKeyRegex, line: `getgist key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GetSandboxKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GetSandboxKeyRegex,
		line:          xorDecode("HR8OCRsUHhgVAnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azho"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_GetSandboxKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GetSandboxKeyRegex, line: `getsandbox key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GitLabOAuthAppSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitLabOAuthAppSecretRegex,
		line:          xorDecode("PTY1Oyl3O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("PTY1Oyl3O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_GitLabOAuthAppSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GitLabOAuthAppSecretRegex, line: `gitlaboauth2 key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GitterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GitterKeyRegex,
		line:          xorDecode("HRMODh8Iemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_GitterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GitterKeyRegex, line: `gitter key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GlassnodeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GlassnodeKeyRegex,
		line:          xorDecode("HRYbCQkUFR4femd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAx"),
	})
}
func TestProcessor_GlassnodeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GlassnodeKeyRegex, line: `glassnode key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GoCanvasKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoCanvasKeyRegex,
		line:          xorDecode("HRUZGxQMGwl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHWd6"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHWc="),
	})
}
func TestProcessor_GoCanvasKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GoCanvasKeyRegex, line: `gocanvas key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GoCardlessKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoCardlessKeyRegex,
		line:          xorDecode("NjMsPwU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0ieg=="),
		expMatch:      true,
		expSecret:     xorDecode("NjMsPwU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
	})
}
func TestProcessor_GoCardlessKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GoCardlessKeyRegex, line: `gocardless key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GoodDayKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GoodDayKeyRegex,
		line:          xorDecode("HRUVHh4bA3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_GoodDayKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GoodDayKeyRegex, line: `goodday key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GraphhopperKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GraphhopperKeyRegex,
		line:          xorDecode("HQgbChISFQoKHwh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_GraphhopperKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GraphhopperKeyRegex, line: `graphhopper key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GroovehqKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GroovehqKeyRegex,
		line:          xorDecode("HQgVFQwfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_GroovehqKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GroovehqKeyRegex, line: `groovehq key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GTMetrixKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GTMetrixKeyRegex,
		line:          xorDecode("HQ4XHw4IEwJ6Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_GTMetrixKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GTMetrixKeyRegex, line: `gtmetrix key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GuardianapiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GuardianapiKeyRegex,
		line:          xorDecode("HQ8bCB4TGxR6Z3p4O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_GuardianapiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GuardianapiKeyRegex, line: `guardianapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GuruKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GuruKeyRegex,
		line:          xorDecode("HQ8ID3pneng7azhoOWk+bnc/bzxsd21iY2p3PTIzMHcxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_GuruKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GuruKeyRegex, line: `guru key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GyazoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GyazoKeyRegex,
		line:          xorDecode("HQMbABV6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_GyazoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GyazoKeyRegex, line: `gyazo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HappyscribeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HappyscribeKeyRegex,
		line:          xorDecode("EhsKCgMJGQgTGB96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_HappyscribeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HappyscribeKeyRegex, line: `happyscribe key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HarvestKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HarvestKeyRegex,
		line:          xorDecode("EhsIDB8JDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygp"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKQ=="),
	})
}
func TestProcessor_HarvestKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HarvestKeyRegex, line: `harvest key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HashiCorpVaultBatchToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HashiCorpVaultBatchTokenRegex,
		line:          xorDecode("Miw4dDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUdQ=="),
		expMatch:      true,
		expSecret:     xorDecode("Miw4dDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcU"),
	})
}
func TestProcessor_HashiCorpVaultBatchToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HashiCorpVaultBatchTokenRegex, line: `hashicorpvault key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HasuraKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HasuraKeyRegex,
		line:          xorDecode("EhsJDwgbemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_HasuraKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HasuraKeyRegex, line: `hasura key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HelloSignKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HelloSignKeyRegex,
		line:          xorDecode("Eh8WFhUJEx0Uemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_HelloSignKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HelloSignKeyRegex, line: `hellosign key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HelpCrunchKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HelpCrunchKeyRegex,
		line:          xorDecode("Eh8WChkIDxQZEnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhlj"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYw=="),
	})
}
func TestProcessor_HelpCrunchKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HelpCrunchKeyRegex, line: `helpcrunch key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HelpscoutKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HelpscoutKeyRegex,
		line:          xorDecode("Eh8WCgkZFQ8Oemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_HelpscoutKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HelpscoutKeyRegex, line: `helpscout key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HerokuAPIKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HerokuAPIKeyV2Regex,
		line:          xorDecode("EggRD3cbGztrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("EggRD3cbGztrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_HerokuAPIKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HerokuAPIKeyV2Regex, line: `heroku key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HiveKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HiveKeyRegex,
		line:          xorDecode("EhMMH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_HiveKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HiveKeyRegex, line: `hive key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HiveageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HiveageKeyRegex,
		line:          xorDecode("EhMMHxsdH3pneng7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_HiveageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HiveageKeyRegex, line: `hiveage key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HolidayAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HolidayAPIKeyRegex,
		line:          xorDecode("EhUWEx4bAxsKE3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_HolidayAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HolidayAPIKeyRegex, line: `holidayapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HolisticKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HolisticKeyRegex,
		line:          xorDecode("EhUWEwkOExl6Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_HolisticKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HolisticKeyRegex, line: `holistic key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HostKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HostKeyRegex,
		line:          xorDecode("EhUJDnQTFXpneng7azhoOWk+bj9vPGxtYg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWI="),
	})
}
func TestProcessor_HostKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HostKeyRegex, line: `host key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Html2PdfKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Html2PdfKeyRegex,
		line:          xorDecode("Eg4XFmgKHhx6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_Html2PdfKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Html2PdfKeyRegex, line: `html2pdf key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HubSpotPrivateAppToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HubSpotPrivateAppTokenRegex,
		line:          xorDecode("Kjsudz8va3c7azhoOWk+bnc/bzxsdxttGGJ3GWMeancfHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("Kjsudz8va3c7azhoOWk+bnc/bzxsdxttGGJ3GWMeancfHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_HubSpotPrivateAppToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HubSpotPrivateAppTokenRegex, line: `hubspot_apikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HumanityKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HumanityKeyRegex,
		line:          xorDecode("Eg8XGxQTDgN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_HumanityKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HumanityKeyRegex, line: `humanity key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HumioAPIToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HumioAPITokenRegex,
		line:          xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yJDMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlp"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yJDMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlp"),
	})
}
func TestProcessor_HumioAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HumioAPITokenRegex, line: `humioapitoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HybiscusKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HybiscusKeyRegex,
		line:          xorDecode("EgMYEwkZDwl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_HybiscusKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HybiscusKeyRegex, line: `hybiscus key = "REDACTED"`, expMatch: false})
}

func TestProcessor_HypertrackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.HypertrackKeyRegex,
		line:          xorDecode("EgMKHwgOCBsZEXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsI"),
	})
}
func TestProcessor_HypertrackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.HypertrackKeyRegex, line: `hypertrack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IbmCloudUserKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IbmCloudUserKeyRegex,
		line:          xorDecode("ExgXemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0S"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_IbmCloudUserKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IbmCloudUserKeyRegex, line: `ibmclouduserkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IconFinderKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IconFinderKeyRegex,
		line:          xorDecode("ExkVFBwTFB4fCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtr"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_IconFinderKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IconFinderKeyRegex, line: `iconfinder key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IexapisKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IexapisKeyRegex,
		line:          xorDecode("Ex8CGwoTCXpnengpMQU7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("KTEFO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_IexapisKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IexapisKeyRegex, line: `iexapis key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IexcloudKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IexcloudKeyRegex,
		line:          xorDecode("Ex8CGRYVDx56Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiM="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiM="),
	})
}
func TestProcessor_IexcloudKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IexcloudKeyRegex, line: `iexcloud key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ImagekitKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ImagekitKeyRegex,
		line:          xorDecode("ExcbHR8REw56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_ImagekitKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ImagekitKeyRegex, line: `imagekit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ImaggaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ImaggaKeyRegex,
		line:          xorDecode("ExcbHR0bemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9v"),
	})
}
func TestProcessor_ImaggaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ImaggaKeyRegex, line: `imagga key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ImpalaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ImpalaKeyRegex,
		line:          xorDecode("ExcKGxYbemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEA=="),
	})
}
func TestProcessor_ImpalaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ImpalaKeyRegex, line: `impala key = "REDACTED"`, expMatch: false})
}

func TestProcessor_InfisicalKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InfisicalKeyRegex,
		line:          xorDecode("KS50O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNqdDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("KS50O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNqdDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_InfisicalKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.InfisicalKeyRegex, line: `infisical key = "REDACTED"`, expMatch: false})
}

func TestProcessor_InsightlyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InsightlyKeyRegex,
		line:          xorDecode("ExQJEx0SDhYDemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_InsightlyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.InsightlyKeyRegex, line: `insightly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_InstabotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InstabotKeyRegex,
		line:          xorDecode("ExQJDhsYFQ56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_InstabotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.InstabotKeyRegex, line: `instabot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_InstamojoSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InstamojoSecretRegex,
		line:          xorDecode("ExQJDhsXFRAVemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azho"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg="),
	})
}
func TestProcessor_InstamojoSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.InstamojoSecretRegex, line: `instamojo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IntersellerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IntersellerKeyRegex,
		line:          xorDecode("ExQOHwgJHxYWHwh6Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_IntersellerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IntersellerKeyRegex, line: `interseller key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Intra42Key_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Intra42KeyRegex,
		line:          xorDecode("KXcpbi5oLz53O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("KXcpbi5oLz53O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_Intra42Key_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Intra42KeyRegex, line: `intra42 key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IntrinioKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IntrinioKeyRegex,
		line:          xorDecode("ExQOCBMUExV6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_IntrinioKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IntrinioKeyRegex, line: `intrinio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_InvoiceOceanKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.InvoiceOceanKeyRegex,
		line:          xorDecode("ExQMFRMZHxUZHxsUemd6eDtrOGg5aT5uP288bBttGGIZYx5q"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_InvoiceOceanKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.InvoiceOceanKeyRegex, line: `invoiceocean key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Ip2locationKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Ip2locationKeyRegex,
		line:          xorDecode("EwpoFhUZGw4TFRR6Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_Ip2locationKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Ip2locationKeyRegex, line: `ip2location key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IpapiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IpapiKeyRegex,
		line:          xorDecode("EwobChN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_IpapiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IpapiKeyRegex, line: `ipapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IPGeolocationKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IPGeolocationKeyRegex,
		line:          xorDecode("EwodHxUWFRkbDhMVFHpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_IPGeolocationKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IPGeolocationKeyRegex, line: `ipgeolocation key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IPInfoDBKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IPInfoDBKeyRegex,
		line:          xorDecode("EwoTFBwVHhh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_IPInfoDBKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IPInfoDBKeyRegex, line: `ipinfodb key = "REDACTED"`, expMatch: false})
}

func TestProcessor_IPQualityKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.IPQualityKeyRegex,
		line:          xorDecode("EwoLDxsWEw4Demd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_IPQualityKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.IPQualityKeyRegex, line: `ipquality key = "REDACTED"`, expMatch: false})
}

func TestProcessor_JotformKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JotformKeyRegex,
		line:          xorDecode("EBUOHBUIF3pneng7azhoOWk+bj9vPGwbbWJjaj0yMzAxNjc0NSorKCkuLw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
	})
}
func TestProcessor_JotformKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.JotformKeyRegex, line: `jotform key = "REDACTED"`, expMatch: false})
}

func TestProcessor_JuroKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.JuroKeyRegex,
		line:          xorDecode("EA8IFXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_JuroKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.JuroKeyRegex, line: `juro key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KanbanKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KanbanKeyRegex,
		line:          xorDecode("ERsUGBsUemd6eGtoaW5vbBttGGIZYw=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhlj"),
	})
}
func TestProcessor_KanbanKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KanbanKeyRegex, line: `kanban key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KarmaCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KarmaCRMKeyRegex,
		line:          xorDecode("ERsIFxsZCBd6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_KarmaCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KarmaCRMKeyRegex, line: `karmacrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KeenIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KeenIOKeyRegex,
		line:          xorDecode("ER8fFHpnenhraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsICQ4PDA0CAwBraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsI"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCA=="),
	})
}
func TestProcessor_KeenIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KeenIOKeyRegex, line: `keenio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KickboxKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KickboxKeyRegex,
		line:          xorDecode("ERMZERgVAnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5u"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bg=="),
	})
}
func TestProcessor_KickboxKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KickboxKeyRegex, line: `kickbox key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KlipfolioKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KlipfolioKeyRegex,
		line:          xorDecode("ERYTChwVFhMVemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_KlipfolioKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KlipfolioKeyRegex, line: `klipfolio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KnapsackProKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KnapsackProKeyRegex,
		line:          xorDecode("ERQbCgkbGREKCBV6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_KnapsackProKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KnapsackProKeyRegex, line: `knapsackpro key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KongKonnectKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KongKonnectKeyRegex,
		line:          xorDecode("MSo7LgU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYX"),
		expMatch:      true,
		expSecret:     xorDecode("MSo7LgU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYX"),
	})
}
func TestProcessor_KongKonnectKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KongKonnectKeyRegex, line: `kong key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KontentKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KontentKeyRegex,
		line:          xorDecode("ERUUDh8UDnpneng/IztrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NCI/IzUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SIhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw="),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQiPyM1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEiITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8c"),
	})
}
func TestProcessor_KontentKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KontentKeyRegex, line: `kontent key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KrakenSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KrakenSecretRegex,
		line:          xorDecode("EQgbER8Uemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yeg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTI="),
	})
}
func TestProcessor_KrakenSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KrakenSecretRegex, line: `kraken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KuCoinSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KuCoinSecretRegex,
		line:          xorDecode("EQ8ZFRMUemd6eDtrOGg5aT5udz9vPGx3bWJjanc7azhodzlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_KuCoinSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KuCoinSecretRegex, line: `kucoin key = "REDACTED"`, expMatch: false})
}

func TestProcessor_KylasKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.KylasKeyRegex,
		line:          xorDecode("EQMWGwl6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_KylasKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.KylasKeyRegex, line: `kylas key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LambdaCloudKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LambdaCloudKeyRegex,
		line:          xorDecode("KT85KD8uBTsFazhoOWk+bj9vPGxtbmJjajtrOGg5aT5uP288bG1iY2p0Hxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQp3"),
		expMatch:      true,
		expSecret:     xorDecode("KT85KD8uBTsFazhoOWk+bj9vPGxtbmJjajtrOGg5aT5uP288bG1iY2p0Hxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQo="),
	})
}
func TestProcessor_LambdaCloudKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LambdaCloudKeyRegex, line: `lambdacloud key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LanguageLayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LanguageLayerKeyRegex,
		line:          xorDecode("FhsUHQ8bHR8WGwMfCHpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_LanguageLayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LanguageLayerKeyRegex, line: `languagelayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LeadfeederKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LeadfeederKeyRegex,
		line:          xorDecode("Fh8bHhwfHx4fCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAd"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_LeadfeederKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LeadfeederKeyRegex, line: `leadfeeder key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LemlistKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LemlistKeyRegex,
		line:          xorDecode("Fh8XFhMJDnpneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_LemlistKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LemlistKeyRegex, line: `lemlist key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LendflowKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LendflowKeyRegex,
		line:          xorDecode("Fh8UHhwWFQ16Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkudC8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD10MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAl3Dg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSJ3IyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhidxljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDHcNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkudy8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIncjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuL3csLSIjIB0SdxMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkudC8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD10MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAl3Dg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSJ3IyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhidxljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDHcNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkudy8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIncjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuL3csLSIjIB0SdxMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGI="),
	})
}
func TestProcessor_LendflowKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LendflowKeyRegex, line: `lendflow key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LessAnnoyingCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LessAnnoyingCRMKeyRegex,
		line:          xorDecode("Fh8JCRsUFBUDExQdemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4P"),
	})
}
func TestProcessor_LessAnnoyingCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LessAnnoyingCRMKeyRegex, line: `lessannoyingcrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LexigramKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LexigramKeyRegex,
		line:          xorDecode("Fh8CEx0IGxd6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCw=="),
	})
}
func TestProcessor_LexigramKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LexigramKeyRegex, line: `lexigram key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LineMessagingKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LineMessagingKeyRegex,
		line:          xorDecode("FhMUH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBE="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExAR"),
	})
}
func TestProcessor_LineMessagingKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LineMessagingKeyRegex, line: `linemessaging key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LineNotifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LineNotifyKeyRegex,
		line:          xorDecode("FhMUHxQVDhMcA3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAd"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_LineNotifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LineNotifyKeyRegex, line: `linenotify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LinkPreviewKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LinkPreviewKeyRegex,
		line:          xorDecode("FhMUEQoIHwwTHw16Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_LinkPreviewKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LinkPreviewKeyRegex, line: `linkpreview key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LiveAgentKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LiveAgentKeyRegex,
		line:          xorDecode("FhMMHxsdHxQOemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_LiveAgentKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LiveAgentKeyRegex, line: `liveagent key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LoadmillKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LoadmillKeyRegex,
		line:          xorDecode("FhUbHhcTFhZ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_LoadmillKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LoadmillKeyRegex, line: `loadmill key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LobKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LobKeyRegex,
		line:          xorDecode("NjMsPwU7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOA=="),
		expMatch:      true,
		expSecret:     xorDecode("NjMsPwU7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOA=="),
	})
}
func TestProcessor_LobKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LobKeyRegex, line: `lob key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LocationIQKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LocationIQKeyRegex,
		line:          xorDecode("FhUZGw4TFRQTC3pnengqMXQ7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("KjF0O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_LocationIQKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LocationIQKeyRegex, line: `locationiq key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LoginradiusKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LoginradiusKeyRegex,
		line:          xorDecode("FhUdExQIGx4TDwl6Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_LoginradiusKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LoginradiusKeyRegex, line: `loginradius key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LokaliseToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LokaliseTokenRegex,
		line:          xorDecode("FhURGxYTCR96Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_LokaliseToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LokaliseTokenRegex, line: `lokalisetoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LoyverseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LoyverseKeyRegex,
		line:          xorDecode("FhUDDB8ICR96Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_LoyverseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LoyverseKeyRegex, line: `loyverse key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LunchMoneyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LunchMoneyKeyRegex,
		line:          xorDecode("Fg8UGRIXFRQfA3pneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s="),
	})
}
func TestProcessor_LunchMoneyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LunchMoneyKeyRegex, line: `lunchmoney key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LunoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LunoKeyRegex,
		line:          xorDecode("Fg8UFXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAd"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_LunoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LunoKeyRegex, line: `luno key = "REDACTED"`, expMatch: false})
}

func TestProcessor_M3oKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.M3oKeyRegex,
		line:          xorDecode("F2kVemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_M3oKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.M3oKeyRegex, line: `m3o key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MadKuduKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MadKuduKeyRegex,
		line:          xorDecode("FxseEQ8eD3pneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_MadKuduKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MadKuduKeyRegex, line: `madkudu key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MagicBellKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MagicBellKeyRegex,
		line:          xorDecode("FxsdExkYHxYWemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_MagicBellKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MagicBellKeyRegex, line: `magicbell key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MagneticKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MagneticKeyRegex,
		line:          xorDecode("FxsdFB8OExl6Z3p4O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_MagneticKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MagneticKeyRegex, line: `magnetic key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MailboxlayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailboxlayerKeyRegex,
		line:          xorDecode("FxsTFhgVAhYbAx8Iemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_MailboxlayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MailboxlayerKeyRegex, line: `mailboxlayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MailJetBasicAuthKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailJetBasicAuthKeyRegex,
		line:          xorDecode("FxsTFhAfDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjNn"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzZw=="),
	})
}
func TestProcessor_MailJetBasicAuthKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MailJetBasicAuthKeyRegex, line: `mailjetbasicauth key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MailJetSMSKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailJetSMSKeyRegex,
		line:          xorDecode("FxsTFhAfDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_MailJetSMSKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MailJetSMSKeyRegex, line: `mailjetsms key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MailmodoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailmodoKeyRegex,
		line:          xorDecode("FxsTFhcVHhV6Z3p4a2hpbm9sG3dtGGIZYx5qdx8cHRITEBF3FhcUFQoLCA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG3dtGGIZYx5qdx8cHRITEBF3FhcUFQoLCA=="),
	})
}
func TestProcessor_MailmodoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MailmodoKeyRegex, line: `mailmodo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MailsacKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MailsacKeyRegex,
		line:          xorDecode("FxsTFgkbGXpnengxBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
		expMatch:      true,
		expSecret:     xorDecode("MQU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4="),
	})
}
func TestProcessor_MailsacKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MailsacKeyRegex, line: `mailsac key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ManifestKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ManifestKeyRegex,
		line:          xorDecode("FxsUExwfCQ56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ManifestKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ManifestKeyRegex, line: `manifest key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MapquestKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MapquestKeyRegex,
		line:          xorDecode("FxsKCw8fCQ56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_MapquestKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MapquestKeyRegex, line: `mapquest key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MarketstackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MarketstackKeyRegex,
		line:          xorDecode("FxsIER8OCQ4bGRF6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_MarketstackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MarketstackKeyRegex, line: `marketstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MavenlinkKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MavenlinkKeyRegex,
		line:          xorDecode("FxsMHxQWExQRemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_MavenlinkKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MavenlinkKeyRegex, line: `mavenlink key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MaxMindLicenseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MaxMindLicenseKeyRegex,
		line:          xorDecode("FxsCFxMUHnpneng7azhoOWk+bj9vPGwbbRhi"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYg=="),
	})
}
func TestProcessor_MaxMindLicenseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MaxMindLicenseKeyRegex, line: `maxmindlicense key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MaxMindLicenseKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MaxMindLicenseKeyV2Regex,
		line:          xorDecode("O2s4aDlpBT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpBTc3MQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpBT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpBTc3MQ=="),
	})
}
func TestProcessor_MaxMindLicenseKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MaxMindLicenseKeyV2Regex, line: `maxmindlicense key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MeaningCloudKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MeaningCloudKeyRegex,
		line:          xorDecode("Fx8bFBMUHRkWFQ8eemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_MeaningCloudKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MeaningCloudKeyRegex, line: `meaningcloud key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MeistertaskKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MeistertaskKeyRegex,
		line:          xorDecode("Fx8TCQ4fCA4bCRF6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_MeistertaskKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MeistertaskKeyRegex, line: `meistertask key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MerakiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MerakiKeyRegex,
		line:          xorDecode("Fx8IGxETemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_MerakiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MerakiKeyRegex, line: `meraki key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MesiboKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MesiboKeyRegex,
		line:          xorDecode("Fx8JExgVemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_MesiboKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MesiboKeyRegex, line: `mesibo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MetaAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MetaAPIKeyRegex,
		line:          xorDecode("Fx8OGxsKE3pneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_MetaAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MetaAPIKeyRegex, line: `metaapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MetabaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MetabaseKeyRegex,
		line:          xorDecode("Fx8OGxgbCR96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_MetabaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MetabaseKeyRegex, line: `metabase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MetriloKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MetriloKeyRegex,
		line:          xorDecode("Fx8OCBMWFXpneng7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_MetriloKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MetriloKeyRegex, line: `metrilo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MindmeisterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MindmeisterKeyRegex,
		line:          xorDecode("FxMUHhcfEwkOHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_MindmeisterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MindmeisterKeyRegex, line: `mindmeister key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MiroKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MiroKeyRegex,
		line:          xorDecode("FxMIFXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAx"),
	})
}
func TestProcessor_MiroKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MiroKeyRegex, line: `miro key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MiteKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MiteKeyRegex,
		line:          xorDecode("FxMOH3pneng7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_MiteKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MiteKeyRegex, line: `mite key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MixmaxKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MixmaxKeyRegex,
		line:          xorDecode("FxMCFxsCemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_MixmaxKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MixmaxKeyRegex, line: `mixmax key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ModerationKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ModerationKeyRegex,
		line:          xorDecode("FxUeHwgbDhMVFHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS50LywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMXQ2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5u"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkudC8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDF0Njc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bg=="),
	})
}
func TestProcessor_ModerationKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ModerationKeyRegex, line: `moderation key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MonkeyLearnKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MonkeyLearnKeyRegex,
		line:          xorDecode("FxUUER8DFh8bCBR6Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_MonkeyLearnKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MonkeyLearnKeyRegex, line: `monkeylearn key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MoonclerkKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MoonclerkKeyRegex,
		line:          xorDecode("FxUVFBkWHwgRemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_MoonclerkKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MoonclerkKeyRegex, line: `moonclerk key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MuxSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MuxSecretRegex,
		line:          xorDecode("Fw8Cemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG3o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwb"),
	})
}
func TestProcessor_MuxSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MuxSecretRegex, line: `mux key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MyfreshworksKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MyfreshworksKeyRegex,
		line:          xorDecode("HAgfCRINFQgRCXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8c"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHA=="),
	})
}
func TestProcessor_MyfreshworksKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MyfreshworksKeyRegex, line: `myfreshworks key = "REDACTED"`, expMatch: false})
}

func TestProcessor_MyIntervalsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.MyIntervalsKeyRegex,
		line:          xorDecode("FwMTFA4fCAwbFgl6Z3p4O2s4aDlpPm4/bzw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzw="),
	})
}
func TestProcessor_MyIntervalsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.MyIntervalsKeyRegex, line: `myintervals key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NasdaqDataLinkKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NasdaqDataLinkKeyRegex,
		line:          xorDecode("FBsJHhsLemd6eDtrOGg5aT5uP288bBttGGIZYx5q"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_NasdaqDataLinkKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NasdaqDataLinkKeyRegex, line: `nasdaqdatalink key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NethuntKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NethuntKeyRegex,
		line:          xorDecode("FB8OEg8UDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_NethuntKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NethuntKeyRegex, line: `nethunt key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NetsuiteSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NetsuiteSecretRegex,
		line:          xorDecode("FB8OCQ8TDh96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_NetsuiteSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NetsuiteSecretRegex, line: `netsuite key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NeutrinoAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NeutrinoAPIKeyRegex,
		line:          xorDecode("FB8PDggTFBUbChN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_NeutrinoAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NeutrinoAPIKeyRegex, line: `neutrinoapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewRelicBrowserKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicBrowserKeyV2Regex,
		line:          xorDecode("FAgYCHc7azhoOWk+bj9vPGxtYmNqO2s4"),
		expMatch:      true,
		expSecret:     xorDecode("FAgYCHc7azhoOWk+bj9vPGxtYmNqO2s4"),
	})
}
func TestProcessor_NewRelicBrowserKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewRelicBrowserKeyV2Regex, line: `newrelicbrowserkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewRelicInsightsInsertKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicInsightsInsertKeyRegex,
		line:          xorDecode("FAgTE3c7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIz"),
		expMatch:      true,
		expSecret:     xorDecode("FAgTE3c7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIz"),
	})
}
func TestProcessor_NewRelicInsightsInsertKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewRelicInsightsInsertKeyRegex, line: `newrelicinsightsinsertkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewRelicInsightsQueryKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicInsightsQueryKeyRegex,
		line:          xorDecode("FAgTC3c7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIz"),
		expMatch:      true,
		expSecret:     xorDecode("FAgTC3c7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIz"),
	})
}
func TestProcessor_NewRelicInsightsQueryKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewRelicInsightsQueryKeyRegex, line: `newrelicinsightsquerykey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewRelicLicenseKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicLicenseKeyV2Regex,
		line:          xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2ocHBwcFAgbFg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2ocHBwcFAgbFg=="),
	})
}
func TestProcessor_NewRelicLicenseKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewRelicLicenseKeyV2Regex, line: `newreliclicensekey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewRelicMobileAppToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicMobileAppTokenRegex,
		line:          xorDecode("Gxs7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5udxQIFxs="),
		expMatch:      true,
		expSecret:     xorDecode("Gxs7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5udxQIFxs="),
	})
}
func TestProcessor_NewRelicMobileAppToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewRelicMobileAppTokenRegex, line: `newrelicmobileapptoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewRelicUserKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewRelicUserKeyRegex,
		line:          xorDecode("FAgbEXdraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgs="),
		expMatch:      true,
		expSecret:     xorDecode("FAgbEXdraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgs="),
	})
}
func TestProcessor_NewRelicUserKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewRelicUserKeyRegex, line: `newrelicuserkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewsapiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewsapiKeyRegex,
		line:          xorDecode("FB8NCRsKE3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_NewsapiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewsapiKeyRegex, line: `newsapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NewscatcherKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NewscatcherKeyRegex,
		line:          xorDecode("FB8NCRkbDhkSHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_NewscatcherKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NewscatcherKeyRegex, line: `newscatcher key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NexmoAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NexmoAPIKeyRegex,
		line:          xorDecode("FB8CFxV6Z3p4O2s4aDlpPm4/bzxsG20YYg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYg=="),
	})
}
func TestProcessor_NexmoAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NexmoAPIKeyRegex, line: `nexmoapikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NftportKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NftportKeyRegex,
		line:          xorDecode("FBwOChUIDnpneng7azhoOWk+bnc/bzxsd21iY2p3PTIzMHcxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_NftportKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NftportKeyRegex, line: `nftport key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NicereplyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NicereplyKeyRegex,
		line:          xorDecode("FBMZHwgfChYDemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_NicereplyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NicereplyKeyRegex, line: `nicereply key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NimbleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NimbleKeyRegex,
		line:          xorDecode("FBMXGBYfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0"),
	})
}
func TestProcessor_NimbleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NimbleKeyRegex, line: `nimble key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NoticeableKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NoticeableKeyRegex,
		line:          xorDecode("FBUOExkfGxgWH3pneng7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_NoticeableKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NoticeableKeyRegex, line: `noticeable key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NozbeTeamsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NozbeTeamsKeyRegex,
		line:          xorDecode("FBUAGB96Z3p4O2s4aDlpPm4/bzxsG20YYgUZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljeg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYgUZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhlj"),
	})
}
func TestProcessor_NozbeTeamsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NozbeTeamsKeyRegex, line: `nozbeteams key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NumverifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NumverifyKeyRegex,
		line:          xorDecode("FA8XDB8IExwDemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_NumverifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NumverifyKeyRegex, line: `numverify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NutritionixKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NutritionixKeyRegex,
		line:          xorDecode("FA8OCBMOExUUEwJ6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_NutritionixKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NutritionixKeyRegex, line: `nutritionix key = "REDACTED"`, expMatch: false})
}

func TestProcessor_NylasKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.NylasKeyRegex,
		line:          xorDecode("FAMWGwl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0"),
	})
}
func TestProcessor_NylasKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.NylasKeyRegex, line: `nylas key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OandaKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OandaKeyRegex,
		line:          xorDecode("FRsUHht6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_OandaKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OandaKeyRegex, line: `oanda key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OctopusDeployToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OctopusDeployTokenRegex,
		line:          xorDecode("GwoTd2toaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJ"),
		expMatch:      true,
		expSecret:     xorDecode("GwoTd2toaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJ"),
	})
}
func TestProcessor_OctopusDeployToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OctopusDeployTokenRegex, line: `octopusdeploy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OnepageCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OnepageCRMKeyRegex,
		line:          xorDecode("FRQfChsdHxkIF3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_OnepageCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OnepageCRMKeyRegex, line: `onepagecrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OnfleetKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OnfleetKeyRegex,
		line:          xorDecode("FRQcFh8fDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_OnfleetKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OnfleetKeyRegex, line: `onfleet key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OOPSpamKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OOPSpamKeyRegex,
		line:          xorDecode("FRUKCQobF3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_OOPSpamKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OOPSpamKeyRegex, line: `oopspam key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OpenCageDataKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenCageDataKeyRegex,
		line:          xorDecode("FQofFBkbHR8eGw4bemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_OpenCageDataKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OpenCageDataKeyRegex, line: `opencagedata key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OpenRouterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenRouterKeyRegex,
		line:          xorDecode("KTF3NSh3LGt3O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("KTF3NSh3LGt3O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_OpenRouterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OpenRouterKeyRegex, line: `openrouter key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OpenuvKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenuvKeyRegex,
		line:          xorDecode("FQofFA8Memd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_OpenuvKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OpenuvKeyRegex, line: `openuv key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OpenVpnSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenVpnSecretRegex,
		line:          xorDecode("FQofFAwKFHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtr"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_OpenVpnSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OpenVpnSecretRegex, line: `openvpn key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OpenWeatherKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OpenWeatherKeyRegex,
		line:          xorDecode("FQofFA0fGw4SHwh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_OpenWeatherKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OpenWeatherKeyRegex, line: `openweather key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OverloopKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OverloopKeyRegex,
		line:          xorDecode("FQwfCBYVFQp6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQ="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQ="),
	})
}
func TestProcessor_OverloopKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OverloopKeyRegex, line: `overloop key = "REDACTED"`, expMatch: false})
}

func TestProcessor_OwlbotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.OwlbotKeyRegex,
		line:          xorDecode("FQ0WGBUOemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_OwlbotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.OwlbotKeyRegex, line: `owlbot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PagarmeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PagarmeKeyRegex,
		line:          xorDecode("OzEFNjMsPwU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ="),
		expMatch:      true,
		expSecret:     xorDecode("OzEFNjMsPwU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ="),
	})
}
func TestProcessor_PagarmeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PagarmeKeyRegex, line: `pagarme key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PandadocKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PandadocKeyRegex,
		line:          xorDecode("ChsUHhseFRl6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_PandadocKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PandadocKeyRegex, line: `pandadoc key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PandaScoreKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PandaScoreKeyRegex,
		line:          xorDecode("ChsUHhsJGRUIH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBV6"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQV"),
	})
}
func TestProcessor_PandaScoreKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PandaScoreKeyRegex, line: `pandascore key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PaperformKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaperformKeyRegex,
		line:          xorDecode("ChsKHwgcFQgXemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEg=="),
	})
}
func TestProcessor_PaperformKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PaperformKeyRegex, line: `paperform key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ParallelDotsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ParallelDotsKeyRegex,
		line:          xorDecode("ChsIGxYWHxYeFQ4Jemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_ParallelDotsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ParallelDotsKeyRegex, line: `paralleldots key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ParsehubKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ParsehubKeyRegex,
		line:          xorDecode("ChsICR8SDxh6Z3p4O2s4aDlpPm4/bzxs"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxs"),
	})
}
func TestProcessor_ParsehubKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ParsehubKeyRegex, line: `parsehub key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ParseurKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ParseurKeyRegex,
		line:          xorDecode("ChsICR8PCDt6Z3p4azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uPw=="),
		expMatch:      true,
		expSecret:     xorDecode("azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uPw=="),
	})
}
func TestProcessor_ParseurKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ParseurKeyRegex, line: `parseur key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PartnerstackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PartnerstackKeyRegex,
		line:          xorDecode("ChsIDhQfCAkOGxkRemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_PartnerstackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PartnerstackKeyRegex, line: `partnerstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PastebinKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PastebinKeyRegex,
		line:          xorDecode("ChsJDh8YExR6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_PastebinKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PastebinKeyRegex, line: `pastebin key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PaydirtappKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaydirtappKeyRegex,
		line:          xorDecode("ChsDHhMIDhsKCnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_PaydirtappKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PaydirtappKeyRegex, line: `paydirtapp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PaymoappKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaymoappKeyRegex,
		line:          xorDecode("ChsDFxUbCgp6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_PaymoappKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PaymoappKeyRegex, line: `paymoapp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PaymongoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PaymongoKeyRegex,
		line:          xorDecode("ChsDFxUUHRV6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_PaymongoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PaymongoKeyRegex, line: `paymongo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PayPalOAuthSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PayPalOAuthSecretRegex,
		line:          xorDecode("ChsDChsWemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0S"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_PayPalOAuthSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PayPalOAuthSecretRegex, line: `paypaloauth key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PdfLayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PdfLayerKeyRegex,
		line:          xorDecode("Ch4cFhsDHwh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_PdfLayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PdfLayerKeyRegex, line: `pdflayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PdfShiftKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PdfShiftKeyRegex,
		line:          xorDecode("Ch4cCRITHA56Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_PdfShiftKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PdfShiftKeyRegex, line: `pdfshift key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PepipostKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PepipostKeyRegex,
		line:          xorDecode("Ch8KEwoVCQ56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_PepipostKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PepipostKeyRegex, line: `pepipost key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PgAnalyzeReadKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PgAnalyzeReadKeyRegex,
		line:          xorDecode("Kj07KAU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE="),
		expMatch:      true,
		expSecret:     xorDecode("Kj07KAU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE="),
	})
}
func TestProcessor_PgAnalyzeReadKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PgAnalyzeReadKeyRegex, line: `pganalyzereadkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PhotoroomKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PhotoroomKeyRegex,
		line:          xorDecode("ChIVDhUIFRUXemd6eCkxBSooBTsFazhoOWk+bj9vPGwbbRhiGWMeah8cO2s4aDlpPm4/bzxsG20YYhljHg=="),
		expMatch:      true,
		expSecret:     xorDecode("KTEFKigFOwVrOGg5aT5uP288bBttGGIZYx5qHxw7azhoOWk+bj9vPGwbbRhiGWMe"),
	})
}
func TestProcessor_PhotoroomKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PhotoroomKeyRegex, line: `photoroom key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PhraseAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PhraseAccessTokenRegex,
		line:          xorDecode("ChIIGwkfemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_PhraseAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PhraseAccessTokenRegex, line: `phraseaccesstoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PineconeKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PineconeKeyV2Regex,
		line:          xorDecode("KjkpMQU7azhoOQVpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk="),
		expMatch:      true,
		expSecret:     xorDecode("KjkpMQU7azhoOQVpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk="),
	})
}
func TestProcessor_PineconeKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PineconeKeyV2Regex, line: `pinecone key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PivotalTrackerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PivotalTrackerKeyRegex,
		line:          xorDecode("ChMMFQ4bFnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_PivotalTrackerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PivotalTrackerKeyRegex, line: `pivotaltracker key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PixabayKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PixabayKeyRegex,
		line:          xorDecode("ChMCGxgbA3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_PixabayKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PixabayKeyRegex, line: `pixabay key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PlanviewLeanKitKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanviewLeanKitKeyRegex,
		line:          xorDecode("ChYbFAwTHw0WHxsUERMOemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_PlanviewLeanKitKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PlanviewLeanKitKeyRegex, line: `planviewleankit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PlanyoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PlanyoKeyRegex,
		line:          xorDecode("ChYbFAMVemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSo="),
	})
}
func TestProcessor_PlanyoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PlanyoKeyRegex, line: `planyo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PodioKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PodioKeyRegex,
		line:          xorDecode("ChUeExV6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_PodioKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PodioKeyRegex, line: `podio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PollsAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PollsAPIKeyRegex,
		line:          xorDecode("ChUWFgkbChN6Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCA=="),
	})
}
func TestProcessor_PollsAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PollsAPIKeyRegex, line: `pollsapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PoloniexSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PoloniexSecretRegex,
		line:          xorDecode("ChUWFRQTHwJ6Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_PoloniexSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PoloniexSecretRegex, line: `poloniex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PostageAppKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostageAppKeyRegex,
		line:          xorDecode("ChUJDhsdHxsKCnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_PostageAppKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PostageAppKeyRegex, line: `postageapp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PostbacksKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PostbacksKeyRegex,
		line:          xorDecode("ChUJDhgbGREJemd6eDtrOGg5aT5udz9vPGx3bWJjanc7azhodzlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_PostbacksKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PostbacksKeyRegex, line: `postbacks key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PowrbotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PowrbotKeyRegex,
		line:          xorDecode("ChUNCBgVDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_PowrbotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PowrbotKeyRegex, line: `powrbot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PrefectTokenV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PrefectTokenV2Regex,
		line:          xorDecode("KjQvBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
		expMatch:      true,
		expSecret:     xorDecode("KjQvBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
	})
}
func TestProcessor_PrefectTokenV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PrefectTokenV2Regex, line: `prefect key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PrivacyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PrivacyKeyRegex,
		line:          xorDecode("CggTDBsZA3pneng7azhoOWk+bnc/bzxsd21iY2p3PTIzMHcxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdz0yMzB3MTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_PrivacyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PrivacyKeyRegex, line: `privacy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ProdpadKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ProdpadKeyRegex,
		line:          xorDecode("CggVHgobHnpneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_ProdpadKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ProdpadKeyRegex, line: `prodpad key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ProspectCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ProspectCRMKeyRegex,
		line:          xorDecode("CggVCQofGQ56Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ProspectCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ProspectCRMKeyRegex, line: `prospectcrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ProtocolsIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ProtocolsIOKeyRegex,
		line:          xorDecode("CggVDhUZFRYJemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_ProtocolsIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ProtocolsIOKeyRegex, line: `protocolsio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ProxyCrawlKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ProxyCrawlKeyRegex,
		line:          xorDecode("CggVAgMZCBsNFnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8c"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHA=="),
	})
}
func TestProcessor_ProxyCrawlKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ProxyCrawlKeyRegex, line: `proxycrawl key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PureStakeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PureStakeKeyRegex,
		line:          xorDecode("Cg8IHwkOGxEfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_PureStakeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PureStakeKeyRegex, line: `purestake key = "REDACTED"`, expMatch: false})
}

func TestProcessor_PushBulletAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.PushBulletAPIKeyRegex,
		line:          xorDecode("Cg8JEhgPFhYfDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_PushBulletAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.PushBulletAPIKeyRegex, line: `pushbulletapikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_QaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.QaseKeyRegex,
		line:          xorDecode("CxsJH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_QaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.QaseKeyRegex, line: `qase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_QualarooKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.QualarooKeyRegex,
		line:          xorDecode("Cw8bFhsIFRV6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_QualarooKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.QualarooKeyRegex, line: `qualaroo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_QuboleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.QuboleKeyRegex,
		line:          xorDecode("Cw8YFRYfemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_QuboleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.QuboleKeyRegex, line: `qubole key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RampSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RampSecretRegex,
		line:          xorDecode("KDs3KgUpPzkFO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
		expMatch:      true,
		expSecret:     xorDecode("KDs3KgUpPzkFO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_RampSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RampSecretRegex, line: `ramp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RavenKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RavenKeyRegex,
		line:          xorDecode("CBsMHxR6Z3p4a2hpbm9sG20YYhljHmofHA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHA=="),
	})
}
func TestProcessor_RavenKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RavenKeyRegex, line: `raven key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RawgKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RawgKeyRegex,
		line:          xorDecode("CBsNHXpneng7azhoOWk+bj9vPGwbbWJjaj0yMzAxNjc0NSorKCkuLw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
	})
}
func TestProcessor_RawgKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RawgKeyRegex, line: `rawg key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ReachmailKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ReachmailKeyRegex,
		line:          xorDecode("CB8bGRIXGxMWemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_ReachmailKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ReachmailKeyRegex, line: `reachmail key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ReadMeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ReadMeKeyRegex,
		line:          xorDecode("KD43PwU7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("KD43PwU7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0i"),
	})
}
func TestProcessor_ReadMeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ReadMeKeyRegex, line: `readme key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ReallySimpleSystemsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ReallySimpleSystemsKeyRegex,
		line:          xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjciPyM0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20Y"),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjciPyM0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20Y"),
	})
}
func TestProcessor_ReallySimpleSystemsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ReallySimpleSystemsKeyRegex, line: `reallysimplesystems key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RebrandlyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RebrandlyKeyRegex,
		line:          xorDecode("CB8YCBsUHhYDemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_RebrandlyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RebrandlyKeyRegex, line: `rebrandly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RedHatPyxisKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RedHatPyxisKeyRegex,
		line:          xorDecode("CB8eEhsOemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_RedHatPyxisKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RedHatPyxisKeyRegex, line: `redhatpyxis key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RefinerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RefinerKeyRegex,
		line:          xorDecode("CB8cExQfCHpneng7azhoOWk+bnc/bzxsd21iY2p3O2s4aHc5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_RefinerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RefinerKeyRegex, line: `refiner key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RentmanKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RentmanKeyRegex,
		line:          xorDecode("CB8UDhcbFHpneng/IztrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygiPyMpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoIj8jKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLg=="),
	})
}
func TestProcessor_RentmanKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RentmanKeyRegex, line: `rentman key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RepairshoprKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RepairshoprKeyRegex,
		line:          xorDecode("CB8KGxMICRIVCgh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQV"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQV"),
	})
}
func TestProcessor_RepairshoprKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RepairshoprKeyRegex, line: `repairshopr key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ReplyIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ReplyIOKeyRegex,
		line:          xorDecode("CB8KFgMTFXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
	})
}
func TestProcessor_ReplyIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ReplyIOKeyRegex, line: `replyio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RequestFinanceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RequestFinanceKeyRegex,
		line:          xorDecode("CB8LDx8JDhwTFBsUGR96Z3p4a2hpbm9sG3dtGGIZYx5qdx8cHRITEBF3FhcUFQoLCA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG3dtGGIZYx5qdx8cHRITEBF3FhcUFQoLCA=="),
	})
}
func TestProcessor_RequestFinanceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RequestFinanceKeyRegex, line: `requestfinance key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ResendKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ResendKeyRegex,
		line:          xorDecode("KD8FO2s4aDlpPm4FP288bBttGGIZYx4fHD0yMzAxNzQ1Kiso"),
		expMatch:      true,
		expSecret:     xorDecode("KD8FO2s4aDlpPm4FP288bBttGGIZYx4fHD0yMzAxNzQ1Kiso"),
	})
}
func TestProcessor_ResendKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ResendKeyRegex, line: `resend key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RestpackHtmlToPdfAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RestpackHtmlToPdfAPIKeyRegex,
		line:          xorDecode("CB8JDgobGRF6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEW"),
	})
}
func TestProcessor_RestpackHtmlToPdfAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RestpackHtmlToPdfAPIKeyRegex, line: `restpackhtmltopdfapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RevKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RevKeyRegex,
		line:          xorDecode("CB8Memd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMWd6"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxZw=="),
	})
}
func TestProcessor_RevKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RevKeyRegex, line: `rev key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RevampCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RevampCRMKeyRegex,
		line:          xorDecode("CB8MGxcKemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_RevampCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RevampCRMKeyRegex, line: `revampcrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RingCentralKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RingCentralKeyRegex,
		line:          xorDecode("CBMUHRkfFA4IGxZ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHA=="),
	})
}
func TestProcessor_RingCentralKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RingCentralKeyRegex, line: `ringcentral key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RiteKitKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RiteKitKeyRegex,
		line:          xorDecode("CBMOHxETDnpneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGw="),
	})
}
func TestProcessor_RiteKitKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RiteKitKeyRegex, line: `ritekit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RoaringSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RoaringSecretRegex,
		line:          xorDecode("CBUbCBMUHXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNg=="),
	})
}
func TestProcessor_RoaringSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RoaringSecretRegex, line: `roaring key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RootlyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RootlyKeyRegex,
		line:          xorDecode("KDU1LjYjBTtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("KDU1LjYjBTtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_RootlyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RootlyKeyRegex, line: `rootly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_Route4meKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.Route4meKeyRegex,
		line:          xorDecode("CBUPDh9uFx96Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_Route4meKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.Route4meKeyRegex, line: `route4me key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RowndSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RowndSecretRegex,
		line:          xorDecode("CBUNFB56Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxs"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxs"),
	})
}
func TestProcessor_RowndSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RowndSecretRegex, line: `rownd key = "REDACTED"`, expMatch: false})
}

func TestProcessor_RunRunItKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.RunRunItKeyRegex,
		line:          xorDecode("CA8UCA8UEw56Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_RunRunItKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.RunRunItKeyRegex, line: `runrunit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SaladCloudAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SaladCloudAPIKeyRegex,
		line:          xorDecode("KTs2Oz4FOTY1Lz4FOwVrOGg5aT5u"),
		expMatch:      true,
		expSecret:     xorDecode("KTs2Oz4FOTY1Lz4FOwVrOGg5aT5u"),
	})
}
func TestProcessor_SaladCloudAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SaladCloudAPIKeyRegex, line: `saladcloudapikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SalescookieKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalescookieKeyRegex,
		line:          xorDecode("CRsWHwkZFRUREx96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SalescookieKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SalescookieKeyRegex, line: `salescookie key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SalesflareKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalesflareKeyRegex,
		line:          xorDecode("CRsWHwkcFhsIH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhM="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRIT"),
	})
}
func TestProcessor_SalesflareKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SalesflareKeyRegex, line: `salesflare key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SalesmateKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalesmateKeyRegex,
		line:          xorDecode("CRsWHwkXGw4femd6eDtrOGg5aT5udz9vPGx3bWJjanc7azhodzlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_SalesmateKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SalesmateKeyRegex, line: `salesmate key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SatismeterProjectkey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SatismeterProjectkeyRegex,
		line:          xorDecode("CRsOEwkXHw4fCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SatismeterProjectkey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SatismeterProjectkeyRegex, line: `satismeterprojectkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScalrKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScalrKeyRegex,
		line:          xorDecode("CRkbFgh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bA=="),
	})
}
func TestProcessor_ScalrKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScalrKeyRegex, line: `scalr key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScrapeowlKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScrapeowlKeyRegex,
		line:          xorDecode("CRkIGwofFQ0Wemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_ScrapeowlKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScrapeowlKeyRegex, line: `scrapeowl key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScraperAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScraperAPIKeyRegex,
		line:          xorDecode("CRkIGwofCBsKE3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ScraperAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScraperAPIKeyRegex, line: `scraperapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScraperBoxKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScraperBoxKeyRegex,
		line:          xorDecode("CRkIGwofCBgVAnpnenhraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsICQ4PDA=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_ScraperBoxKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScraperBoxKeyRegex, line: `scraperbox key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScrapeStackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScrapeStackKeyRegex,
		line:          xorDecode("CRkIGwofCQ4bGRF6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ScrapeStackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScrapeStackKeyRegex, line: `scrapestack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScrapflyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScrapflyKeyRegex,
		line:          xorDecode("CRkIGwocFgN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ScrapflyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScrapflyKeyRegex, line: `scrapfly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScrapingAntKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScrapingAntKeyRegex,
		line:          xorDecode("CRkIGwoTFB0bFA56Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_ScrapingAntKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScrapingAntKeyRegex, line: `scrapingant key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScrapingBeeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScrapingBeeKeyRegex,
		line:          xorDecode("CRkIGwoTFB0YHx96Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20="),
	})
}
func TestProcessor_ScrapingBeeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScrapingBeeKeyRegex, line: `scrapingbee key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScreenshotAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScreenshotAPIKeyRegex,
		line:          xorDecode("CRkIHx8UCRIVDhsKE3pnenhraGlub2wbd20YYhljHmp3HxwdEhMQEXcWFxQVCgsI"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG3dtGGIZYx5qdx8cHRITEBF3FhcUFQoLCA=="),
	})
}
func TestProcessor_ScreenshotAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScreenshotAPIKeyRegex, line: `screenshotapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ScreenshotLayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ScreenshotLayerKeyRegex,
		line:          xorDecode("CRkIHx8UCRIVDhYbAx8Iemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ScreenshotLayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ScreenshotLayerKeyRegex, line: `screenshotlayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SelectPDFKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SelectPDFKeyRegex,
		line:          xorDecode("CR8WHxkOCh4cemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_SelectPDFKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SelectPDFKeyRegex, line: `selectpdf key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SemaphoreKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SemaphoreKeyRegex,
		line:          xorDecode("CR8XGwoSFQgfemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_SemaphoreKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SemaphoreKeyRegex, line: `semaphore key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SerphouseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SerphouseKeyRegex,
		line:          xorDecode("CR8IChIVDwkfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_SerphouseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SerphouseKeyRegex, line: `serphouse key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SerpStackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SerpStackKeyRegex,
		line:          xorDecode("CR8ICgkOGxkRemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_SerpStackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SerpStackKeyRegex, line: `serpstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ServalSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ServalSecretRegex,
		line:          xorDecode("KSw2BSk/OSg/LgUqMQU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYX"),
		expMatch:      true,
		expSecret:     xorDecode("KSw2BSk/OSg/LgUqMQU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYX"),
	})
}
func TestProcessor_ServalSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ServalSecretRegex, line: `serval key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SheetyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SheetyKeyRegex,
		line:          xorDecode("CRIfHw4Demd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKyg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_SheetyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SheetyKeyRegex, line: `sheety key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SherpadeskKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SherpadeskKeyRegex,
		line:          xorDecode("CRIfCAobHh8JEXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_SherpadeskKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SherpadeskKeyRegex, line: `sherpadesk key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ShipdayKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShipdayKeyRegex,
		line:          xorDecode("CRITCh4bA3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NQ=="),
	})
}
func TestProcessor_ShipdayKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ShipdayKeyRegex, line: `shipday key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ShippoToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShippoTokenRegex,
		line:          xorDecode("KTIzKio1BTYzLD8FO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("KTIzKio1BTYzLD8FO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_ShippoToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ShippoTokenRegex, line: `shippo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ShortcutKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShortcutKeyRegex,
		line:          xorDecode("CRIVCA4ZDw56Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_ShortcutKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ShortcutKeyRegex, line: `shortcut key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ShotstackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShotstackKeyRegex,
		line:          xorDecode("CRIVDgkOGxkRemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_ShotstackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ShotstackKeyRegex, line: `shotstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ShutterstockSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShutterstockSecretRegex,
		line:          xorDecode("CRIPDg4fCAkOFRkRemd6eDtrOGg5aT5uP288bBttGGI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYg=="),
	})
}
func TestProcessor_ShutterstockSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ShutterstockSecretRegex, line: `shutterstock key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ShutterstockOAuthKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ShutterstockOAuthKeyRegex,
		line:          xorDecode("CRIPDg4fCAkOFRkRemd6eCxodTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGI="),
		expMatch:      true,
		expSecret:     xorDecode("LGh1O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYg=="),
	})
}
func TestProcessor_ShutterstockOAuthKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ShutterstockOAuthKeyRegex, line: `shutterstockoauth key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SignaturitKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SignaturitKeyRegex,
		line:          xorDecode("CRMdFBsODwgTDnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9Mg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTI="),
	})
}
func TestProcessor_SignaturitKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SignaturitKeyRegex, line: `signaturit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SignupgeniusKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SignupgeniusKeyRegex,
		line:          xorDecode("CRMdFA8KHR8UEw8Jemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SignupgeniusKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SignupgeniusKeyRegex, line: `signupgenius key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SigoptKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SigoptKeyRegex,
		line:          xorDecode("CRMdFQoOemd6eGtoaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8MDQIDAGtoaW5vbBttGGIZYw=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhlj"),
	})
}
func TestProcessor_SigoptKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SigoptKeyRegex, line: `sigopt key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SimFinKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SimFinKeyRegex,
		line:          xorDecode("CRMXHBMUemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SimFinKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SimFinKeyRegex, line: `simfin key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SimplesatKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SimplesatKeyRegex,
		line:          xorDecode("CRMXChYfCRsOemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_SimplesatKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SimplesatKeyRegex, line: `simplesat key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SimplyNotedKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SimplyNotedKeyRegex,
		line:          xorDecode("CRMXChYDFBUOHx56Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NA=="),
	})
}
func TestProcessor_SimplyNotedKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SimplyNotedKeyRegex, line: `simplynoted key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SimvolyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SimvolyKeyRegex,
		line:          xorDecode("CRMXDBUWA3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywt"),
	})
}
func TestProcessor_SimvolyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SimvolyKeyRegex, line: `simvoly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SinchMessageKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SinchMessageKeyRegex,
		line:          xorDecode("CRMUGRJ6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_SinchMessageKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SinchMessageKeyRegex, line: `sinchmessage key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SirvKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SirvKeyRegex,
		line:          xorDecode("CRMIDHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMw"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMA=="),
	})
}
func TestProcessor_SirvKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SirvKeyRegex, line: `sirv key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SiteleafKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SiteleafKeyRegex,
		line:          xorDecode("CRMOHxYfGxx6Z3p4O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
	})
}
func TestProcessor_SiteleafKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SiteleafKeyRegex, line: `siteleaf key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SkrappioKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SkrappioKeyRegex,
		line:          xorDecode("CREIGwoKemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_SkrappioKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SkrappioKeyRegex, line: `skrappio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SkyBiometrySecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SkyBiometrySecretRegex,
		line:          xorDecode("CREDGBMVFx8OCAN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NQ=="),
	})
}
func TestProcessor_SkyBiometrySecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SkyBiometrySecretRegex, line: `skybiometry key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SmartyStreetsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SmartyStreetsKeyRegex,
		line:          xorDecode("CRcbCA4DCQ4IHx8OCXpneng7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_SmartyStreetsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SmartyStreetsKeyRegex, line: `smartystreets key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SmoochSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SmoochSecretRegex,
		line:          xorDecode("CRcVFRkSemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0y"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTI="),
	})
}
func TestProcessor_SmoochSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SmoochSecretRegex, line: `smooch key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SolarWindsObservabilityKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SolarWindsObservabilityKeyRegex,
		line:          xorDecode("CRUWGwgNExQeCXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uPw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj8="),
	})
}
func TestProcessor_SolarWindsObservabilityKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SolarWindsObservabilityKeyRegex, line: `solarwindsobservability key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SonarCloudTokenV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SonarCloudTokenV2Regex,
		line:          xorDecode("KSs5NQU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQ=="),
		expMatch:      true,
		expSecret:     xorDecode("KSs5NQU7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQ=="),
	})
}
func TestProcessor_SonarCloudTokenV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SonarCloudTokenV2Regex, line: `sonarcloud key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SonarQubeTokenV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SonarQubeTokenV2Regex,
		line:          xorDecode("KSs7BWs4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj8="),
		expMatch:      true,
		expSecret:     xorDecode("KSs7BWs4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj8="),
	})
}
func TestProcessor_SonarQubeTokenV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SonarQubeTokenV2Regex, line: `sonarqube key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SpectralOpsToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SpectralOpsTokenRegex,
		line:          xorDecode("KSovdztrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("KSovdztrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
	})
}
func TestProcessor_SpectralOpsToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SpectralOpsTokenRegex, line: `spectralops key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SpeechTextAIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SpeechTextAIKeyRegex,
		line:          xorDecode("CQofHxkSDh8CDnpneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_SpeechTextAIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SpeechTextAIKeyRegex, line: `speechtextai key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SpoonacularKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SpoonacularKeyRegex,
		line:          xorDecode("CQoVFRQbGQ8WGwh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_SpoonacularKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SpoonacularKeyRegex, line: `spoonacular key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SportsmonkKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SportsmonkKeyRegex,
		line:          xorDecode("CQoVCA4JFxUUEXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_SportsmonkKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SportsmonkKeyRegex, line: `sportsmonk key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SpotifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SpotifyKeyRegex,
		line:          xorDecode("CQoVDhMcA3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1Kg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SpotifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SpotifyKeyRegex, line: `spotifykey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SquarespaceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SquarespaceKeyRegex,
		line:          xorDecode("CQsPGwgfCQobGR96Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_SquarespaceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SquarespaceKeyRegex, line: `squarespace key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SslMateKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SslMateKeyRegex,
		line:          xorDecode("CQkWFxsOH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_SslMateKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SslMateKeyRegex, line: `sslmate key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StatuscakeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StatuscakeKeyRegex,
		line:          xorDecode("CQ4bDg8JGRsRH3pneng7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_StatuscakeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StatuscakeKeyRegex, line: `statuscake key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StatuspalKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StatuspalKeyRegex,
		line:          xorDecode("CQ4bDg8JChsWemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_StatuspalKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StatuspalKeyRegex, line: `statuspal key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StockdataKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StockdataKeyRegex,
		line:          xorDecode("CQ4VGREeGw4bemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_StockdataKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StockdataKeyRegex, line: `stockdata key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StorecoveKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StorecoveKeyRegex,
		line:          xorDecode("CQ4VCB8ZFQwfemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_StorecoveKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StorecoveKeyRegex, line: `storecove key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StormboardKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StormboardKeyRegex,
		line:          xorDecode("CQ4VCBcYFRsIHnpneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5u"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_StormboardKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StormboardKeyRegex, line: `stormboard key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StormglassKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StormglassKeyRegex,
		line:          xorDecode("CQ4VCBcdFhsJCXpneng7azhoOWk+bj9vPGwbbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8sLSIj"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg5aT5uP288bBttYmNqPTIzMDE2NzQ1KisoKS4vLC0iIw=="),
	})
}
func TestProcessor_StormglassKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StormglassKeyRegex, line: `stormglass key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StorychiefKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StorychiefKeyRegex,
		line:          xorDecode("CQ4VCAMZEhMfHHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9v"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bw=="),
	})
}
func TestProcessor_StorychiefKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StorychiefKeyRegex, line: `storychief key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StravaSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StravaSecretRegex,
		line:          xorDecode("CQ4IGwwbemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_StravaSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StravaSecretRegex, line: `strava key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StreakKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StreakKeyRegex,
		line:          xorDecode("CQ4IHxsRemd6eDtrOGg5aT5uP288bBttYmNqO2s4aDlpPm4/bzxsG21i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o7azhoOWk+bj9vPGwbbWI="),
	})
}
func TestProcessor_StreakKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StreakKeyRegex, line: `streak key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StripoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripoKeyRegex,
		line:          xorDecode("CQ4IEwoVemd6eD8jEDI4HTkzFTMQEw8gE2sUMxBjdDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWl0Pm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFw=="),
		expMatch:      true,
		expSecret:     xorDecode("PyMQMjgdOTMVMxATDyATaxQzEGN0O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aXQ+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYX"),
	})
}
func TestProcessor_StripoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StripoKeyRegex, line: `stripo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SugesterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SugesterKeyRegex,
		line:          xorDecode("CQ8dHwkOHwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SugesterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SugesterKeyRegex, line: `sugester key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SuperNotesAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SuperNotesAPIKeyRegex,
		line:          xorDecode("CQ8KHwgUFQ4fCXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdeg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_SuperNotesAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SuperNotesAPIKeyRegex, line: `supernotesapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SurveyAnyplaceKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SurveyAnyplaceKeyRegex,
		line:          xorDecode("CQ8IDB8Demd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SurveyAnyplaceKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SurveyAnyplaceKeyRegex, line: `surveyanyplace key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SurveyBotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SurveyBotKeyRegex,
		line:          xorDecode("CQ8IDB8DGBUOemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhlj"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWM="),
	})
}
func TestProcessor_SurveyBotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SurveyBotKeyRegex, line: `surveybot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SurveySparrowKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SurveySparrowKeyRegex,
		line:          xorDecode("CQ8IDB8DCQobCAgVDXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMw"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMA=="),
	})
}
func TestProcessor_SurveySparrowKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SurveySparrowKeyRegex, line: `surveysparrow key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SurvicateKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SurvicateKeyRegex,
		line:          xorDecode("CQ8IDBMZGw4femd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_SurvicateKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SurvicateKeyRegex, line: `survicate key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SwiftypeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SwiftypeKeyRegex,
		line:          xorDecode("CQ0THA4DCh96Z3p4O2s4aDlpBT5uP288bHcbbRhiGWM="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpBT5uP288bHcbbRhiGWM="),
	})
}
func TestProcessor_SwiftypeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SwiftypeKeyRegex, line: `swiftype key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TableauPersonalAccessToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TableauPersonalAccessTokenRegex,
		line:          xorDecode("DhsYFh8bD3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cZ2dgPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHGdnYD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsI"),
	})
}
func TestProcessor_TableauPersonalAccessToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TableauPersonalAccessTokenRegex, line: `tableau key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TailscaleKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TailscaleKeyRegex,
		line:          xorDecode("LikxPyN3Ozg5Pj88d2wbbRhiGXdjHmofHD0="),
		expMatch:      true,
		expSecret:     xorDecode("LikxPyN3Ozg5Pj88d2wbbRhiGXdjHmofHD0="),
	})
}
func TestProcessor_TailscaleKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TailscaleKeyRegex, line: `tailscale key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TallyfyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TallyfyKeyRegex,
		line:          xorDecode("DhsWFgMcA3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS50LywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKdAsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoL"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkudC8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCnQLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCw=="),
	})
}
func TestProcessor_TallyfyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TallyfyKeyRegex, line: `tallyfy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TatumIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TatumIOKeyRegex,
		line:          xorDecode("DhsODxd6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_TatumIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TatumIOKeyRegex, line: `tatumio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TaxjarKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TaxjarKeyRegex,
		line:          xorDecode("DhsCEBsIemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_TaxjarKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TaxjarKeyRegex, line: `taxjar key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TeamgateToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TeamgateTokenRegex,
		line:          xorDecode("Dh8bFx0bDh96Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_TeamgateToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TeamgateTokenRegex, line: `teamgate key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TeamworkCRMKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TeamworkCRMKeyRegex,
		line:          xorDecode("Dh8bFw0VCBF6Z3p4LjE0dCxrBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/Z3o="),
		expMatch:      true,
		expSecret:     xorDecode("LjE0dCxrBTtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/Zw=="),
	})
}
func TestProcessor_TeamworkCRMKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TeamworkCRMKeyRegex, line: `teamworkcrm key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TechnicalAnalysisAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TechnicalAnalysisAPIKeyRegex,
		line:          xorDecode("Dh8ZEhQTGRsWGxQbFgMJEwkbChN6Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhlj"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhlj"),
	})
}
func TestProcessor_TechnicalAnalysisAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TechnicalAnalysisAPIKeyRegex, line: `technicalanalysisapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TefterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TefterKeyRegex,
		line:          xorDecode("Dh8cDh8Iemd6eDtrOGg5aT5uP288bBttGGIZYx5q"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_TefterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TefterKeyRegex, line: `tefter key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TeletypeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TeletypeKeyRegex,
		line:          xorDecode("Dh8WHw4DCh96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_TeletypeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TeletypeKeyRegex, line: `teletype key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TestingBotKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TestingBotKeyRegex,
		line:          xorDecode("Dh8JDhMUHRgVDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_TestingBotKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TestingBotKeyRegex, line: `testingbot key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TheOddsAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TheOddsAPIKeyRegex,
		line:          xorDecode("DhIfFR4eCRsKE3pneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_TheOddsAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TheOddsAPIKeyRegex, line: `theoddsapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ThinkificKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ThinkificKeyRegex,
		line:          xorDecode("DhITFBETHBMZemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_ThinkificKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ThinkificKeyRegex, line: `thinkific key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ThousandEyesKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ThousandEyesKeyRegex,
		line:          xorDecode("DhIVDwkbFB4fAx8Jemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ThousandEyesKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ThousandEyesKeyRegex, line: `thousandeyes key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TicketMasterKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TicketMasterKeyRegex,
		line:          xorDecode("DhMZER8OFxsJDh8Iemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_TicketMasterKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TicketMasterKeyRegex, line: `ticketmaster key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TickettailorKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TickettailorKeyRegex,
		line:          xorDecode("DhMZER8ODhsTFhUIemd6eCkxBWtoaW4Fb2xtYmNqBTtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("KTEFa2hpbgVvbG1iY2oFO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_TickettailorKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TickettailorKeyRegex, line: `tickettailor key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TiingoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TiingoKeyRegex,
		line:          xorDecode("DhMTFB0Vemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8sLSIjIDtrOGg="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aA=="),
	})
}
func TestProcessor_TiingoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TiingoKeyRegex, line: `tiingo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TimeCampKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TimeCampKeyRegex,
		line:          xorDecode("DhMXHxkbFwp6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSo="),
	})
}
func TestProcessor_TimeCampKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TimeCampKeyRegex, line: `timecamp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TimezoneapiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TimezoneapiKeyRegex,
		line:          xorDecode("DhMXHwAVFB8bChN6Z3p4Ozg5Pj88GxgZHh8cPTIzMDE2NzQ="),
		expMatch:      true,
		expSecret:     xorDecode("Ozg5Pj88GxgZHh8cPTIzMDE2NzQ="),
	})
}
func TestProcessor_TimezoneapiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TimezoneapiKeyRegex, line: `timezoneapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TLyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TLyKeyRegex,
		line:          xorDecode("DhYDemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_TLyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TLyKeyRegex, line: `tly key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TmetricKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TmetricKeyRegex,
		line:          xorDecode("DhcfDggTGXpnenhraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsICQ4PDA0CAwBraGlub2wbbRhiGWMeah8cHRITEBEWFxQVCgsI"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODwwNAgMAa2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCA=="),
	})
}
func TestProcessor_TmetricKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TmetricKeyRegex, line: `tmetric key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TogglTrackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TogglTrackKeyRegex,
		line:          xorDecode("DhUdHRZ6Z3p4O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG21iY2o9MjMwMTY3NDUqKygpLi8="),
	})
}
func TestProcessor_TogglTrackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TogglTrackKeyRegex, line: `toggltrack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TokeetKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TokeetKeyRegex,
		line:          xorDecode("DhURHx8Oemd6eDtrOGg5aT5udz9vPGx3bWJjanc7azhodzlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_TokeetKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TokeetKeyRegex, line: `tokeet key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TomorrowIOKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TomorrowIOKeyRegex,
		line:          xorDecode("DhUXFQgIFQ16Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_TomorrowIOKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TomorrowIOKeyRegex, line: `tomorrowio key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TradierKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TradierKeyRegex,
		line:          xorDecode("DggbHhMfCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNg=="),
	})
}
func TestProcessor_TradierKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TradierKeyRegex, line: `tradier key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TravelPayoutsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TravelPayoutsKeyRegex,
		line:          xorDecode("DggbDB8WChsDFQ8OCXpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_TravelPayoutsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TravelPayoutsKeyRegex, line: `travelpayouts key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TrufflehogEnterpriseSecret_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TrufflehogEnterpriseSecretRegex,
		line:          xorDecode("LjI1PXcpPzkoPy53O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
		expMatch:      true,
		expSecret:     xorDecode("LjI1PXcpPzkoPy53O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_TrufflehogEnterpriseSecret_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TrufflehogEnterpriseSecretRegex, line: `trufflehogenterprise key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TwistToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TwistTokenRegex,
		line:          xorDecode("Dg0TCQ56Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_TwistToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TwistTokenRegex, line: `twist key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TyntecKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TyntecKeyRegex,
		line:          xorDecode("DgMUDh8Zemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_TyntecKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TyntecKeyRegex, line: `tyntec key = "REDACTED"`, expMatch: false})
}

func TestProcessor_TypetalkKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.TypetalkKeyRegex,
		line:          xorDecode("DgMKHw4bFhF6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_TypetalkKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.TypetalkKeyRegex, line: `typetalk key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UbidotsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UbidotsKeyRegex,
		line:          xorDecode("GBgcHHc7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ="),
		expMatch:      true,
		expSecret:     xorDecode("GBgcHHc7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ="),
	})
}
func TestProcessor_UbidotsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UbidotsKeyRegex, line: `ubidots key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UclassifyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UclassifyKeyRegex,
		line:          xorDecode("DxkWGwkJExwDemd6eDtrOGg5aT5uP288bA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxs"),
	})
}
func TestProcessor_UclassifyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UclassifyKeyRegex, line: `uclassify key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UnifyIDKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UnifyIDKeyRegex,
		line:          xorDecode("DxQTHAN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRI="),
	})
}
func TestProcessor_UnifyIDKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UnifyIDKeyRegex, line: `unifyid key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UnpluggKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UnpluggKeyRegex,
		line:          xorDecode("DxQKFg96Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKA=="),
	})
}
func TestProcessor_UnpluggKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UnpluggKeyRegex, line: `unplugg key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UnsplashKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UnsplashKeyRegex,
		line:          xorDecode("DxQJChYbCRJ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHQ=="),
	})
}
func TestProcessor_UnsplashKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UnsplashKeyRegex, line: `unsplash key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UPCDatabaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UPCDatabaseKeyRegex,
		line:          xorDecode("DwoZHhsOGxgbCR96Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_UPCDatabaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UPCDatabaseKeyRegex, line: `upcdatabase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UpleadKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UpleadKeyRegex,
		line:          xorDecode("DwoWHxseemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_UpleadKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UpleadKeyRegex, line: `uplead key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UploadCareKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UploadCareKeyRegex,
		line:          xorDecode("DwoWFRseGRsIH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzA="),
	})
}
func TestProcessor_UploadCareKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UploadCareKeyRegex, line: `uploadcare key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UpwaveKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UpwaveKeyRegex,
		line:          xorDecode("DwoNGwwfemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_UpwaveKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UpwaveKeyRegex, line: `upwave key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UserKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UserKeyRegex,
		line:          xorDecode("DwkfCHQZFRd6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_UserKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UserKeyRegex, line: `user key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UserflowKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UserflowKeyRegex,
		line:          xorDecode("DwkfCBwWFQ16Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCk="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCk="),
	})
}
func TestProcessor_UserflowKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UserflowKeyRegex, line: `userflow key = "REDACTED"`, expMatch: false})
}

func TestProcessor_UserStackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.UserStackKeyRegex,
		line:          xorDecode("DwkfCAkOGxkRemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_UserStackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.UserStackKeyRegex, line: `userstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VagrantCloudPersonalToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VagrantCloudPersonalTokenRegex,
		line:          xorDecode("DBsdCBsUDnpneng7azhoOWk+bj9vPGwbbSI7LjY7KSxrIhhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx4="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20iOy42OyksayIYYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMe"),
	})
}
func TestProcessor_VagrantCloudPersonalToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VagrantCloudPersonalTokenRegex, line: `vagrantcloudpersonaltoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VatLayerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VatLayerKeyRegex,
		line:          xorDecode("DBsOFhsDHwh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_VatLayerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VatLayerKeyRegex, line: `vatlayer key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VboutKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VboutKeyRegex,
		line:          xorDecode("DBgVDw56Z3p4a2hpbm9sbWJjamtoaW5vbG1iY2praGlubw=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sbWJjamtoaW5vbG1iY2praGlubw=="),
	})
}
func TestProcessor_VboutKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VboutKeyRegex, line: `vbout key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VerifierKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VerifierKeyRegex,
		line:          xorDecode("DB8IExwTHwh6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0"),
	})
}
func TestProcessor_VerifierKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VerifierKeyRegex, line: `verifier key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VerimailKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VerimailKeyRegex,
		line:          xorDecode("DB8IExcbExZ6Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_VerimailKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VerimailKeyRegex, line: `verimail key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VeriphoneKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VeriphoneKeyRegex,
		line:          xorDecode("DB8IEwoSFRQfemd6eGtoaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8M"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_VeriphoneKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VeriphoneKeyRegex, line: `veriphone key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VersionEyeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VersionEyeKeyRegex,
		line:          xorDecode("DB8ICRMVFB8DH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_VersionEyeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VersionEyeKeyRegex, line: `versioneye key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ViewneoKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ViewneoKeyRegex,
		line:          xorDecode("DBMfDRQfFXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwiDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cIj0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MIg0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHCI9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s="),
	})
}
func TestProcessor_ViewneoKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ViewneoKeyRegex, line: `viewneo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VisualCrossingKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VisualCrossingKeyRegex,
		line:          xorDecode("DBMJDxsWGQgVCQkTFB16Z3p4a2hpbm9sG20YYhljHmofHB0SExARFhcUFQ=="),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQ=="),
	})
}
func TestProcessor_VisualCrossingKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VisualCrossingKeyRegex, line: `visualcrossing key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VoiceflowKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VoiceflowKeyRegex,
		line:          xorDecode("DBx0O2s4aDlpPm4/bzxsG20YYhljHmofHDtrdDhoOWk+bj9vPGwbbRhiGWM="),
		expMatch:      true,
		expSecret:     xorDecode("DBx0O2s4aDlpPm4/bzxsG20YYhljHmofHDtrdDhoOWk+bj9vPGwbbRhiGWM="),
	})
}
func TestProcessor_VoiceflowKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VoiceflowKeyRegex, line: `voiceflow key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VoicegainKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VoicegainKeyRegex,
		line:          xorDecode("DBUTGR8dGxMUemd6eD8jO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCI/IykuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYyIeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQID"),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoIj8jKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljIh5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgM="),
	})
}
func TestProcessor_VoicegainKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VoicegainKeyRegex, line: `voicegain key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VoodooSMSKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VoodooSMSKeyRegex,
		line:          xorDecode("DBUVHhUVCRcJemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEA=="),
	})
}
func TestProcessor_VoodooSMSKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VoodooSMSKeyRegex, line: `voodoosms key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VoucheryKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VoucheryKeyRegex,
		line:          xorDecode("DBUPGRIfCAN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_VoucheryKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VoucheryKeyRegex, line: `vouchery key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VpnapiKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VpnapiKeyRegex,
		line:          xorDecode("DAoUGwoTemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_VpnapiKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VpnapiKeyRegex, line: `vpnapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_VyteKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.VyteKeyRegex,
		line:          xorDecode("DAMOH3pneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA7azhoOWk+bj9vPGxtYg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMgO2s4aDlpPm4/bzxsbWI="),
	})
}
func TestProcessor_VyteKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.VyteKeyRegex, line: `vyte key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WalkScoreKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WalkScoreKeyRegex,
		line:          xorDecode("DRsWEQkZFQgfemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_WalkScoreKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WalkScoreKeyRegex, line: `walkscore key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WeatherBitKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WeatherBitKeyRegex,
		line:          xorDecode("DR8bDhIfCBgTDnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_WeatherBitKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WeatherBitKeyRegex, line: `weatherbit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WeatherStackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WeatherStackKeyRegex,
		line:          xorDecode("DR8bDhIfCAkOGxkRemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8s"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_WeatherStackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WeatherStackKeyRegex, line: `weatherstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WebScraperKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebScraperKeyRegex,
		line:          xorDecode("DR8YCRkIGwofCHpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_WebScraperKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WebScraperKeyRegex, line: `webscraper key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WebscrapingKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebscrapingKeyRegex,
		line:          xorDecode("DR8YCRkIGwoTFB16Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_WebscrapingKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WebscrapingKeyRegex, line: `webscraping key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WebsitepulseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WebsitepulseKeyRegex,
		line:          xorDecode("DR8YCRMOHwoPFgkfemd6eDtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o="),
	})
}
func TestProcessor_WebsitepulseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WebsitepulseKeyRegex, line: `websitepulse key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WeightsAndBiasesKeyV2_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WeightsAndBiasesKeyV2Regex,
		line:          xorDecode("LTs0PjgFLGsFO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxBTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20="),
		expMatch:      true,
		expSecret:     xorDecode("LTs0PjgFLGsFO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxBTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20="),
	})
}
func TestProcessor_WeightsAndBiasesKeyV2_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WeightsAndBiasesKeyV2Regex, line: `weightsandbiases key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WePayKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WePayKeyRegex,
		line:          xorDecode("DR8KGwN6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA="),
	})
}
func TestProcessor_WePayKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WePayKeyRegex, line: `wepay key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WhoxyKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WhoxyKeyRegex,
		line:          xorDecode("DRIVAgN6Z3p4O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywt"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywt"),
	})
}
func TestProcessor_WhoxyKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WhoxyKeyRegex, line: `whoxy key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WitKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WitKeyRegex,
		line:          xorDecode("DRMOdBsTemd6eGtoaW5vbBttGGIZYx5qHxwdEhMQERYXFBUKCwgJDg8M"),
		expMatch:      true,
		expSecret:     xorDecode("a2hpbm9sG20YYhljHmofHB0SExARFhcUFQoLCAkODww="),
	})
}
func TestProcessor_WitKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WitKeyRegex, line: `wit key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WorksnapsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WorksnapsKeyRegex,
		line:          xorDecode("DRUIEQkUGwoJemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_WorksnapsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WorksnapsKeyRegex, line: `worksnaps key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WorkstackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WorkstackKeyRegex,
		line:          xorDecode("DRUIEQkOGxkRemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAg=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0C"),
	})
}
func TestProcessor_WorkstackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WorkstackKeyRegex, line: `workstack key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WorldCoinIndexKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WorldCoinIndexKeyRegex,
		line:          xorDecode("DRUIFh4ZFRMUExQeHwJ6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCk="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCk="),
	})
}
func TestProcessor_WorldCoinIndexKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WorldCoinIndexKeyRegex, line: `worldcoinindex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WorldWeatherKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WorldWeatherKeyRegex,
		line:          xorDecode("DRUIFh4NHxsOEh8Iemd6eDtrOGg5aT5uP288bG1iY2o9MjMwMTY3NDUqKygpLi8="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLw=="),
	})
}
func TestProcessor_WorldWeatherKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WorldWeatherKeyRegex, line: `worldweather key = "REDACTED"`, expMatch: false})
}

func TestProcessor_WrikeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.WrikeKeyRegex,
		line:          xorDecode("DQgTER96Z3p4PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0="),
		expMatch:      true,
		expSecret:     xorDecode("PyM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0="),
	})
}
func TestProcessor_WrikeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.WrikeKeyRegex, line: `wrike key = "REDACTED"`, expMatch: false})
}

func TestProcessor_YandexKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.YandexKeyRegex,
		line:          xorDecode("AxsUHh8Cemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmof"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8="),
	})
}
func TestProcessor_YandexKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.YandexKeyRegex, line: `yandex key = "REDACTED"`, expMatch: false})
}

func TestProcessor_YelpKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.YelpKeyRegex,
		line:          xorDecode("Ax8WCnpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg="),
	})
}
func TestProcessor_YelpKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.YelpKeyRegex, line: `yelp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_YouNeedABudgetKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.YouNeedABudgetKeyRegex,
		line:          xorDecode("AxUPFB8fHhsYDx4dHw56Z3p4O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjag=="),
	})
}
func TestProcessor_YouNeedABudgetKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.YouNeedABudgetKeyRegex, line: `youneedabudget key = "REDACTED"`, expMatch: false})
}

func TestProcessor_YouSignKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.YouSignKeyRegex,
		line:          xorDecode("AxUPCRMdFHpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLA=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLyw="),
	})
}
func TestProcessor_YouSignKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.YouSignKeyRegex, line: `yousign key = "REDACTED"`, expMatch: false})
}

func TestProcessor_YoutubeAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.YoutubeAPIKeyRegex,
		line:          xorDecode("AxUPDg8YH3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywt"),
	})
}
func TestProcessor_YoutubeAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.YoutubeAPIKeyRegex, line: `youtubeapikey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZendeskAPIToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZendeskAPITokenRegex,
		line:          xorDecode("AB8UHh8JEXpneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIg=="),
	})
}
func TestProcessor_ZendeskAPIToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZendeskAPITokenRegex, line: `zendeskapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZenkitAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZenkitAPIKeyRegex,
		line:          xorDecode("AB8UERMOemd6eDtrOGg5aT5udz9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
	})
}
func TestProcessor_ZenkitAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZenkitAPIKeyRegex, line: `zenkitapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZenRowsKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZenRowsKeyRegex,
		line:          xorDecode("AB8UCBUNCXpneng7azhoOWk+bj9vPGxtYmNqO2s4aDlpPm4/bzxsbWJjajtrOGg5aT5u"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjajtrOGg5aT5uP288bG1iY2o7azhoOWk+bg=="),
	})
}
func TestProcessor_ZenRowsKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZenRowsKeyRegex, line: `zenrows key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZenscrapeKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZenscrapeKeyRegex,
		line:          xorDecode("AB8UCRkIGwofemd6eDtrOGg5aT5udz9vPGx3bWJjanc7azhodzlpPm4/bzxsbWJjag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_ZenscrapeKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZenscrapeKeyRegex, line: `zenscrape key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZenserpKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZenserpKeyRegex,
		line:          xorDecode("AB8UCR8ICnpneng7azhoOWk+bj9vPGxtYmNqPTIzMDE2NzQ1KisoKS4vLC0iIyA="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsbWJjaj0yMzAxNjc0NSorKCkuLywtIiMg"),
	})
}
func TestProcessor_ZenserpKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZenserpKeyRegex, line: `zenserp key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZeplinKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZeplinKeyRegex,
		line:          xorDecode("AB8KFhMUemd6eDtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0i"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSI="),
	})
}
func TestProcessor_ZeplinKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZeplinKeyRegex, line: `zeplin key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZeroTierKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZeroTierKeyRegex,
		line:          xorDecode("AB8IFQ4THwh6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ZeroTierKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZeroTierKeyRegex, line: `zerotier key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZipCodeAPIKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZipCodeAPIKeyRegex,
		line:          xorDecode("ABMKGRUeHxsKE3pneng7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtr"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCkuLywtIiMgHRITEBEWFxQVCgsICQ4PDA0CAwA7aw=="),
	})
}
func TestProcessor_ZipCodeAPIKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZipCodeAPIKeyRegex, line: `zipcodeapi key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZipcodebaseKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZipcodebaseKeyRegex,
		line:          xorDecode("ABMKGRUeHxgbCR96Z3p4O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm53P288bHdtYmNqdztrOGh3OWk+bj9vPGxtYmNq"),
	})
}
func TestProcessor_ZipcodebaseKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZipcodebaseKeyRegex, line: `zipcodebase key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZonkaFeedbackKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZonkaFeedbackKeyRegex,
		line:          xorDecode("ABUUERt6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSorKCku"),
	})
}
func TestProcessor_ZonkaFeedbackKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZonkaFeedbackKeyRegex, line: `zonkafeedback key = "REDACTED"`, expMatch: false})
}

func TestProcessor_ZulipChatKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.ZulipChatKeyRegex,
		line:          xorDecode("AA8WEwp6Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_ZulipChatKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.ZulipChatKeyRegex, line: `zulipchat key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AWSExtendedAccessKeyID_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSExtendedAccessKeyIDRegex,
		line:          xorDecode("G2kOa2hpbm9sG20YYhljHmofHB0="),
		expMatch:      true,
		expSecret:     xorDecode("G2kOa2hpbm9sG20YYhljHmofHB0="),
	})
}
func TestProcessor_AWSExtendedAccessKeyID_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AWSExtendedAccessKeyIDRegex, line: `awsextendedaccesskeyid key = "REDACTED"`, expMatch: false})
}

func TestProcessor_AWSCredFileInfo_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.AWSCredFileInfoRegex,
		line:          xorDecode("Gw0JBRsZGR8JCQURHwMFEx56Z3p4ZyI7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmo="),
	})
}
func TestProcessor_AWSCredFileInfo_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.AWSCredFileInfoRegex, line: `awscredfileinfo key = "REDACTED"`, expMatch: false})
}

func TestProcessor_StripeRestrictedKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.StripeRestrictedKeyRegex,
		line:          xorDecode("KDEFLj8pLgU7azhoOWk+bj9vPGwbbRhiGWMeag=="),
		expMatch:      true,
		expSecret:     xorDecode("KDEFLj8pLgU7azhoOWk+bj9vPGwbbRhiGWMeag=="),
	})
}
func TestProcessor_StripeRestrictedKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.StripeRestrictedKeyRegex, line: `striperestrictedkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SalesforceRefreshToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalesforceRefreshTokenRegex,
		line:          xorDecode("bxsfCmJsaztrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhlj"),
		expMatch:      true,
		expSecret:     xorDecode("bxsfCmJsaztrOGg5aT5uP288bBttGGIZYx5qHxw9MjMwMTY3NDUqKygpLi8sLSIjIB0SExARFhcUFQoLCAkODwwNAgMAO2s4aDlpPm4/bzxsG20YYhlj"),
	})
}
func TestProcessor_SalesforceRefreshToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SalesforceRefreshTokenRegex, line: `salesforcerefreshtoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SalesforceConsumerKey_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SalesforceConsumerKeyRegex,
		line:          xorDecode("aRcMHWM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYw=="),
		expMatch:      true,
		expSecret:     xorDecode("aRcMHWM7azhoOWk+bj9vPGwbbRhiGWMeah8cPTIzMDE2NzQ1KisoKS4vLC0iIyAdEhMQERYXFBUKCwgJDg8MDQIDADtrOGg5aT5uP288bBttGGIZYw=="),
	})
}
func TestProcessor_SalesforceConsumerKey_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SalesforceConsumerKeyRegex, line: `salesforceconsumerkey key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SignableToken_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SignableTokenRegex,
		line:          xorDecode("CRMdFBsYFh96Z3p4O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
		expMatch:      true,
		expSecret:     xorDecode("O2s4aDlpPm4/bzxsG20YYhljHmofHD0yMzAxNjc0NSo="),
	})
}
func TestProcessor_SignableToken_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SignableTokenRegex, line: `signabletoken key = "REDACTED"`, expMatch: false})
}

func TestProcessor_SQLServerConnString_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.SQLServerConnStringRegex,
		line:          xorDecode("CT8oLD8oZy45KmA+OHQzNC4/KDQ7NnZrbmlpYR47Ljs4Oyk/ZzsqKmEPKT8oehM+ZyksOWEKOykpLTUoPmcAImJrMQsqFjdoYzth"),
		expMatch:      true,
		expSecret:     xorDecode("ACJiazELKhY3aGM7"),
	})
}
func TestProcessor_SQLServerConnString_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.SQLServerConnStringRegex, line: `sqlserverconnstring key = "REDACTED"`, expMatch: false})
}

func TestProcessor_LDAPOpenDSObject_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.LDAPOpenDSObjectRegex,
		line:          xorDecode("CT8uejV6Z3o+dBUqPzQeCRU4MD85LnJ4Fh4bCmB1dT45dDk1KCp0NjU5OzZ4dnp4KSw5dzgzND54dnp4ACJiazELKhY3aGM7eHZ6a3M="),
		expMatch:      true,
		expSecret:     xorDecode("ACJiazELKhY3aGM7"),
	})
}
func TestProcessor_LDAPOpenDSObject_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.LDAPOpenDSObjectRegex, line: `ldapopendsobject key = "REDACTED"`, expMatch: false})
}

func TestProcessor_GCPApplicationDefaultCredentials_Valid(t *testing.T) {
	runProcessorTest(t, processorTest{
		coreProcessor: builtin.GCPApplicationDefaultCredentialsRegex,
		line:          xorDecode("IXg5NjM/NC4FMz54YHp4a2hpbnQ7KiopdD01NT02Py8pPyg5NTQuPzQudDk1N3h2eng5NjM/NC4FKT85KD8ueGB6eD53HBZjbwtrYyttFws3HCo+bTISHmoOI3h2engoPzwoPykyBS41MT80eGB6eGt1dWo7ODk+Pzw9eHZ6eC4jKj94YHp4Oy8uMjUoMyA/PgUvKT8oeCc="),
		expMatch:      true,
		expSecret:     xorDecode("IXg5NjM/NC4FMz54YHp4a2hpbnQ7KiopdD01NT02Py8pPyg5NTQuPzQudDk1N3h2eng5NjM/NC4FKT85KD8ueGB6eD53HBZjbwtrYyttFws3HCo+bTISHmoOI3h2engoPzwoPykyBS41MT80eGB6eGt1dWo7ODk+Pzw9eHZ6eC4jKj94YHp4Oy8uMjUoMyA/PgUvKT8oeCc="),
	})
}
func TestProcessor_GCPApplicationDefaultCredentials_Invalid(t *testing.T) {
	runProcessorTest(t, processorTest{coreProcessor: builtin.GCPApplicationDefaultCredentialsRegex, line: `gcpapplicationdefaultcredentials key = "REDACTED"`, expMatch: false})
}
