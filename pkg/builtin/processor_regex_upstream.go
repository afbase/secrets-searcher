package builtin

import (
	"github.com/afbase/secrets-searcher/pkg/app/config"
	"github.com/afbase/secrets-searcher/pkg/search"
)

// Regex processor definitions ported from the detectors in trufflehog
// (https://github.com/trufflesecurity/trufflehog) and the signatures in shhgit
// (https://github.com/eth0izzle/shhgit) that were not already covered by
// regexProcessorDefinitions.
//
// Upstream trufflehog confirms most of these by calling the vendor API. This
// tool does not, so the keyword-prefixed patterns are best-effort.
func upstreamRegexProcessorDefinitions() (result []*config.ProcessorConfig) {
	return []*config.ProcessorConfig{
		// AbuseIPDBKey (trufflehog abuseipdb)
		{
			Name:      AbuseIPDBKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:abuseipdb).{0,40}?\b([a-z0-9]{80})\b`,
			},
		},

		// AbyssaleKey (trufflehog abyssale)
		{
			Name:      AbyssaleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:abyssale).{0,40}?\b([a-z0-9A-Z]{40})\b`,
			},
		},

		// AccuweatherKey (trufflehog accuweather/v1)
		{
			Name:      AccuweatherKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:accuweather).{0,40}?([a-z0-9A-Z\%]{35})\b`,
			},
		},

		// AccuweatherKeyV2 (trufflehog accuweather/v2)
		{
			Name:      AccuweatherKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:accuweather).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// AdafruitIOKey (trufflehog adafruitio)
		{
			Name:      AdafruitIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(aio\_[a-zA-Z0-9]{28})\b`,
			},
		},

		// AdobeIOKey (trufflehog adobeio)
		{
			Name:      AdobeIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:adobe).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// AdzunaKey (trufflehog adzuna)
		{
			Name:      AdzunaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:adzuna).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// AeroworkflowKey (trufflehog aeroworkflow)
		{
			Name:      AeroworkflowKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:aeroworkflow).{0,40}?\b([a-zA-Z0-9^!?#:*;]{20})`,
			},
		},

		// AhaKey (trufflehog aha)
		{
			Name:      AhaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:aha).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// AirshipKey (trufflehog airship)
		{
			Name:      AirshipKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:airship).{0,40}?\b([0-9a-zA-Z]{91})\b`,
			},
		},

		// AirVisualKey (trufflehog airvisual)
		{
			Name:      AirVisualKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:airvisual).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// AlconostKey (trufflehog alconost)
		{
			Name:      AlconostKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:alconost).{0,40}?\b([0-9Aa-z]{32})\b`,
			},
		},

		// AlegraKey (trufflehog alegra)
		{
			Name:      AlegraKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:alegra).{0,40}?\b([a-z0-9-]{20})\b`,
			},
		},

		// AletheiaAPIKey (trufflehog aletheiaapi)
		{
			Name:      AletheiaAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:aletheiaapi).{0,40}?\b([A-Z0-9]{32})\b`,
			},
		},

		// AlienVaultKey (trufflehog alienvault)
		{
			Name:      AlienVaultKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:alienvault).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// AllsportsKey (trufflehog allsports)
		{
			Name:      AllsportsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:allsports).{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// AmadeusSecret (trufflehog amadeus)
		{
			Name:      AmadeusSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:amadeus).{0,40}?\b([0-9A-Za-z]{16})\b`,
			},
		},

		// AmbeeKey (trufflehog ambee)
		{
			Name:      AmbeeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ambee).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// AnypointKey (trufflehog anypoint)
		{
			Name:      AnypointKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:anypoint).{0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// AnypointOAuth2Secret (trufflehog anypointoauth2)
		{
			Name:      AnypointOAuth2SecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:anypoint).{0,40}?\b([0-9a-fA-F]{32})\b`,
			},
		},

		// ApactaKey (trufflehog apacta)
		{
			Name:      ApactaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apacta).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// Api2CartKey (trufflehog api2cart)
		{
			Name:      Api2CartKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:api2cart).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// ApiflashKey (trufflehog apiflash)
		{
			Name:      ApiflashKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apiflash).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// APIFonicaKey (trufflehog apifonica)
		{
			Name:      APIFonicaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apifonica).{0,40}?\b([0-9a-z]{11}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// ApifyKey (trufflehog apify)
		{
			Name:      ApifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(apify\_api\_[a-zA-Z-0-9]{36})\b`,
			},
		},

		// ApilayerKey (trufflehog apilayer)
		{
			Name:      ApilayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apilayer).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// APIMaticKey (trufflehog apimatic)
		{
			Name:      APIMaticKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apimatic).{0,40}?\b([a-zA-Z0-9_-]{64})\b`,
			},
		},

		// APIMetricsKey (trufflehog apimetrics)
		{
			Name:      APIMetricsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apimetrics).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// APITemplateKey (trufflehog apitemplate)
		{
			Name:      APITemplateKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apitemplate).{0,40}?\b([0-9a-zA-Z]{39})\b`,
			},
		},

		// AppcuesKey (trufflehog appcues)
		{
			Name:      AppcuesKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:appcues).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// AppfollowKey (trufflehog appfollow)
		{
			Name:      AppfollowKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:appfollow).{0,40}?\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9\.[0-9A-Za-z]{74}\.[0-9A-Z-a-z\-_]{43})\b`,
			},
		},

		// AppointeddKey (trufflehog appointedd)
		{
			Name:      AppointeddKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:appointedd).{0,40}?\b([a-zA-Z0-9=+]{88})`,
			},
		},

		// AppSynergyKey (trufflehog appsynergy)
		{
			Name:      AppSynergyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:appsynergy).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// ApptivoKey (trufflehog apptivo)
		{
			Name:      ApptivoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:apptivo).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// ArtifactoryAPIKey (trufflehog artifactory)
		{
			Name:      ArtifactoryAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(AKCp[a-zA-Z0-9]{69})\b`,
			},
		},

		// ArtifactoryReferenceToken (trufflehog artifactoryreferencetoken)
		{
			Name:      ArtifactoryReferenceTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(cmVmdGtu[A-Za-z0-9]{56})\b`,
			},
		},

		// ArtsyKey (trufflehog artsy)
		{
			Name:      ArtsyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:artsy).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// AteraKey (trufflehog atera)
		{
			Name:      AteraKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:atera).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// BitbucketDataCenterToken (trufflehog atlassiandatacenter/bitbucketdatacenter)
		{
			Name:      BitbucketDataCenterTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(BBDC-[A-Za-z0-9+/@_-]{40,50})(?:[^A-Za-z0-9+/@_-]|$)`,
			},
		},

		// AuddKey (trufflehog audd)
		{
			Name:      AuddKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:audd).{0,40}?\b([a-z0-9-]{32})\b`,
			},
		},

		// Auth0ManagementAPIToken (trufflehog auth0managementapitoken)
		{
			Name:      Auth0ManagementAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:auth0).{0,40}?\b(ey[a-zA-Z0-9._-]+)\b`,
			},
		},

		// AutodeskSecret (trufflehog autodesk)
		{
			Name:      AutodeskSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:autodesk).{0,40}?\b([0-9A-Za-z]{16})\b`,
			},
		},

		// AutokloseKey (trufflehog autoklose)
		{
			Name:      AutokloseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:autoklose).{0,40}?\b([a-zA-Z0-9-]{32})\b`,
			},
		},

		// AutoPilotKey (trufflehog autopilot)
		{
			Name:      AutoPilotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:autopilot).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// AvazaPersonalAccessToken (trufflehog avazapersonalaccesstoken)
		{
			Name:      AvazaPersonalAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:avaza).{0,40}?\b([0-9]+-[0-9a-f]{40})\b`,
			},
		},

		// AviationStackKey (trufflehog aviationstack)
		{
			Name:      AviationStackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:aviationstack).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// AWSAppSyncAPIKey (trufflehog aws/appsync)
		{
			Name:      AWSAppSyncAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(da2-[a-z0-9]{26})\b`,
			},
		},

		// AxonautKey (trufflehog axonaut)
		{
			Name:      AxonautKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:axonaut).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// AylienKey (trufflehog aylien)
		{
			Name:      AylienKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:aylien).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// AyrshareKey (trufflehog ayrshare)
		{
			Name:      AyrshareKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ayrshare).{0,40}?\b([A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8}-[A-Z0-9]{8})\b`,
			},
		},

		// AzureEntraRefreshToken (trufflehog azure_entra/refreshtoken)
		{
			Name:      AzureEntraRefreshTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b[01]\.A[\w-]{50,}(?:\.\d)?\.Ag[\w-]{250,}(?:\.A[\w-]{200,})?`,
			},
		},

		// AzureEntraSecretV2 (trufflehog azure_entra/serviceprincipal/v2)
		{
			Name:      AzureEntraSecretV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?:[^a-zA-Z0-9_~.-]|^)([a-zA-Z0-9_~.-]{3}\dQ~[a-zA-Z0-9_~.-]{31,34})(?:[^a-zA-Z0-9_~.-]|$)`,
			},
		},

		// AzureDirectManagementKey (trufflehog azuredirectmanagementkey)
		{
			Name:      AzureDirectManagementKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:azure|\.management\.azure-api\.net).{0,40}?([a-zA-Z0-9+\/]{83,85}[a-zA-Z0-9]==)`,
			},
		},

		// BannerbearKey (trufflehog bannerbear/v1)
		{
			Name:      BannerbearKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bannerbear).{0,40}?\b([0-9a-zA-Z]{22}tt)\b`,
			},
		},

		// BannerbearKeyV2 (trufflehog bannerbear/v2)
		{
			Name:      BannerbearKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(bb_(?:pr|ma)_[a-f0-9]{30})\b`,
			},
		},

		// BaremetricsKey (trufflehog baremetrics)
		{
			Name:      BaremetricsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:baremetrics).{0,40}?\b((?:sk|lk)_[a-zA-Z0-9]{18,25})\b`,
			},
		},

		// BeamerKey (trufflehog beamer)
		{
			Name:      BeamerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:beamer).{0,40}?\b([a-zA-Z0-9_+/]{45}=)`,
			},
		},

		// BeeboleKey (trufflehog beebole)
		{
			Name:      BeeboleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:beebole).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// BesnappyKey (trufflehog besnappy)
		{
			Name:      BesnappyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:besnappy).{0,40}?\b([a-f0-9]{64})\b`,
			},
		},

		// BesttimeKey (trufflehog besttime)
		{
			Name:      BesttimeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:besttime).{0,40}?\b(pri_[a-f0-9]{32})\b`,
			},
		},

		// BillomatKey (trufflehog billomat)
		{
			Name:      BillomatKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:billomat).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// BitbarKey (trufflehog bitbar)
		{
			Name:      BitbarKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bitbar).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// BitcoinAverageKey (trufflehog bitcoinaverage)
		{
			Name:      BitcoinAverageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bitcoinaverage).{0,40}?\b([a-zA-Z0-9]{43})\b`,
			},
		},

		// BitfinexSecret (trufflehog bitfinex)
		{
			Name:      BitfinexSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bitfinex).{0,40}?\b([A-Za-z0-9_-]{43})\b`,
			},
		},

		// BitmexSecret (trufflehog bitmex)
		{
			Name:      BitmexSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bitmex).{0,40}?(?:^|[ \r\n])([0-9a-zA-Z\-\_]{48})(?:[ \r\n]|$)`,
			},
		},

		// BlazemeterKey (trufflehog blazemeter)
		{
			Name:      BlazemeterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:blazemeter|runscope).{0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// BlitAppKey (trufflehog blitapp)
		{
			Name:      BlitAppKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:blitapp).{0,40}?\b([a-zA-Z0-9_-]{39})\b`,
			},
		},

		// BlockNativeKey (trufflehog blocknative)
		{
			Name:      BlockNativeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:blocknative).{0,40}?\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// BombBombKey (trufflehog bombbomb)
		{
			Name:      BombBombKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bombbomb).{0,40}?\b(ey[0-9a-zA-Z]{0,140}.ey[0-9a-zA-Z-\/_]{0,419}.[0-9a-zA-Z-\/_]{0,171})\b`,
			},
		},

		// BoostNoteKey (trufflehog boostnote)
		{
			Name:      BoostNoteKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:boostnote).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// BorgbaseKey (trufflehog borgbase)
		{
			Name:      BorgbaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:borgbase).{0,40}?\b([a-zA-Z0-9/_.-]{148,152})\b`,
			},
		},

		// BoxKey (trufflehog box)
		{
			Name:      BoxKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:box[_.-]?(?:com|api|access|token|key|dev)|\bbox\b).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// BraintreePaymentsKey (trufflehog braintreepayments)
		{
			Name:      BraintreePaymentsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:braintree).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// BrainTrustAPIKey (trufflehog braintrust)
		{
			Name:      BrainTrustAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk-[A-Za-z0-9]{48})\b`,
			},
		},

		// BrandfetchKey (trufflehog brandfetch/v1)
		{
			Name:      BrandfetchKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:brandfetch).{0,40}?\b([0-9A-Za-z]{40})\b`,
			},
		},

		// BrandfetchKeyV2 (trufflehog brandfetch/v2)
		{
			Name:      BrandfetchKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:brandfetch).{0,40}?([a-zA-Z0-9=+/\-_!@#$%^&*()]{43}=)`,
			},
		},

		// BrowshotKey (trufflehog browshot)
		{
			Name:      BrowshotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:browshot).{0,40}?\b([a-zA-Z-0-9]{28})\b`,
			},
		},

		// BuddyNSKey (trufflehog buddyns)
		{
			Name:      BuddyNSKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:buddyns).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// BudibaseKey (trufflehog budibase)
		{
			Name:      BudibaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:budibase).{0,40}?\b([a-f0-9]{32}-[a-f0-9]{78,80})\b`,
			},
		},

		// BugherdKey (trufflehog bugherd)
		{
			Name:      BugherdKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bugherd).{0,40}?\b([0-9a-z]{22})\b`,
			},
		},

		// BulbulKey (trufflehog bulbul)
		{
			Name:      BulbulKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bulbul).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// BulksmsKey (trufflehog bulksms)
		{
			Name:      BulksmsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:bulksms).{0,40}?\b([a-zA-Z0-9!@#$%^&*()]{29})\b`,
			},
		},

		// CaflouKey (trufflehog caflou)
		{
			Name:      CaflouKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(eyJhbGciOiJIUzI1NiJ9[a-zA-Z0-9._-]{135})\b`,
			},
		},

		// CalendarificKey (trufflehog calendarific)
		{
			Name:      CalendarificKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:calendarific).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// CalorieNinjaKey (trufflehog calorieninja)
		{
			Name:      CalorieNinjaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:calorieninja).{0,40}?\b([0-9A-Za-z]{40})\b`,
			},
		},

		// CampaynKey (trufflehog campayn)
		{
			Name:      CampaynKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:campayn).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// CannyIoKey (trufflehog cannyio)
		{
			Name:      CannyIoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:canny).{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// CapsuleCRMKey (trufflehog capsulecrm)
		{
			Name:      CapsuleCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:capsulecrm).{0,40}?\b([a-zA-Z0-9-._+=]{64})\b`,
			},
		},

		// CaptainDataKey (trufflehog captaindata/v1)
		{
			Name:      CaptainDataKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:captaindata).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// CarbonInterfaceKey (trufflehog carboninterface)
		{
			Name:      CarbonInterfaceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:carboninterface).{0,40}?\b([a-zA-Z0-9]{21})\b`,
			},
		},

		// CashboardKey (trufflehog cashboard)
		{
			Name:      CashboardKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cashboard).{0,40}?\b([0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3}-[0-9A-Z]{3})\b`,
			},
		},

		// CaspioKey (trufflehog caspio)
		{
			Name:      CaspioKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:caspio).{0,40}?\b([a-z0-9]{50})\b`,
			},
		},

		// CentralStationCRMKey (trufflehog centralstationcrm)
		{
			Name:      CentralStationCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:centralstation).{0,40}?\b([a-z0-9]{30})\b`,
			},
		},

		// CexIOSecret (trufflehog cexio)
		{
			Name:      CexIOSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cexio|cex\.io).{0,40}?\b([0-9A-Za-z]{24,27})\b`,
			},
		},

		// ChartmogulKey (trufflehog chartmogul)
		{
			Name:      ChartmogulKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:chartmogul).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ChatbotKey (trufflehog chatbot)
		{
			Name:      ChatbotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:chatbot).{0,40}?\b([a-zA-Z0-9_]{32})\b`,
			},
		},

		// ChatfuleKey (trufflehog chatfule)
		{
			Name:      ChatfuleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:chatfuel).{0,40}?\b([a-zA-Z0-9]{128})\b`,
			},
		},

		// ChecIOKey (trufflehog checio)
		{
			Name:      ChecIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:checio).{0,40}?\b(pk_[a-z0-9]{45})\b`,
			},
		},

		// ChecklyHQKey (trufflehog checklyhq)
		{
			Name:      ChecklyHQKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:checklyhq).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// CheckoutKey (trufflehog checkout)
		{
			Name:      CheckoutKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:checkout).{0,40}?\b((?:sk_|sk_test_)[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})\b`,
			},
		},

		// CheckvistKey (trufflehog checkvist)
		{
			Name:      CheckvistKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:checkvist).{0,40}?\b([0-9a-zA-Z]{14})\b`,
			},
		},

		// CiceroKey (trufflehog cicero)
		{
			Name:      CiceroKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cicero).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// ClarifaiKey (trufflehog clarifai)
		{
			Name:      ClarifaiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clarifai).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// ClickHelpKey (trufflehog clickhelp)
		{
			Name:      ClickHelpKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clickhelp).{0,40}?\b([0-9A-Za-z]{24})\b`,
			},
		},

		// ClickSendsmsKey (trufflehog clicksendsms)
		{
			Name:      ClickSendsmsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clicksendsms).{0,40}?\b([0-9A-Z]{8}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{4}-[0-9A-Z]{12})\b`,
			},
		},

		// CliengoKey (trufflehog cliengo)
		{
			Name:      CliengoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cliengo).{0,40}?\b([0-9a-f]{8}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{4}\-[0-9a-f]{12})\b`,
			},
		},

		// ClientaryKey (trufflehog clientary)
		{
			Name:      ClientaryKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ronin|clientary).{0,40}?\b([0-9a-zA-Z]{24,26})\b`,
			},
		},

		// ClinchpadKey (trufflehog clinchpad)
		{
			Name:      ClinchpadKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clinchpad).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ClockifyKey (trufflehog clockify)
		{
			Name:      ClockifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clockify).{0,40}?\b([a-zA-Z0-9]{48})\b`,
			},
		},

		// ClockworkSMSToken (trufflehog clockworksms)
		{
			Name:      ClockworkSMSTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clockwork|textanywhere).{0,40}?\b([0-9a-zA-Z]{24})\b`,
			},
		},

		// CloudConvertKey (trufflehog cloudconvert)
		{
			Name:      CloudConvertKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloudconvert).{0,40}?\b(ey[0-9a-zA-Z]{30,34}.ey[0-9a-zA-Z-\/_]{200,500}.[0-9a-zA-Z-\/_]{600,700})\b`,
			},
		},

		// CloudElementsKey (trufflehog cloudelements)
		{
			Name:      CloudElementsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloudelements).{0,40}?\b([a-zA-Z0-9]{43})\b`,
			},
		},

		// CloudflareAPITokenV2 (trufflehog cloudflareapitoken/v2)
		{
			Name:      CloudflareAPITokenV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(cf[ua]t_[a-zA-Z0-9]{40}[a-f0-9]{8})\b`,
			},
		},

		// CloudflareGlobalAPIKeyV2 (trufflehog cloudflareglobalapikey/v2)
		{
			Name:      CloudflareGlobalAPIKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(cfk_[a-zA-Z0-9]{40}[a-f0-9]{8})\b`,
			},
		},

		// CloudImageKey (trufflehog cloudimage)
		{
			Name:      CloudImageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloudimage).{0,40}?\b([a-z0-9_]{30})\b`,
			},
		},

		// CloudmersiveKey (trufflehog cloudmersive)
		{
			Name:      CloudmersiveKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloudmersive).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// CloudplanKey (trufflehog cloudplan)
		{
			Name:      CloudplanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloudplan).{0,40}?\b([A-Z0-9-]{32})\b`,
			},
		},

		// CloverlyKey (trufflehog cloverly)
		{
			Name:      CloverlyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloverly).{0,40}?\b([a-z0-9:_]{28})\b`,
			},
		},

		// ClozeKey (trufflehog cloze)
		{
			Name:      ClozeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cloze).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// ClustDocKey (trufflehog clustdoc)
		{
			Name:      ClustDocKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:clustdoc).{0,40}?\b([0-9a-zA-Z]{60})\b`,
			},
		},

		// CodaKey (trufflehog coda)
		{
			Name:      CodaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:coda).{0,40}?\b([0-9a-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// CodequiryKey (trufflehog codequiry)
		{
			Name:      CodequiryKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:codequiry).{0,40}?\b([a-zA-Z-0-9]{64})\b`,
			},
		},

		// CoinAPIKey (trufflehog coinapi)
		{
			Name:      CoinAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:coinapi).{0,40}?\b([A-Z0-9-]{36})\b`,
			},
		},

		// CoinlayerKey (trufflehog coinlayer)
		{
			Name:      CoinlayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:coinlayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// CoinlibKey (trufflehog coinlib)
		{
			Name:      CoinlibKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:coinlib).{0,40}?\b([a-z0-9]{16})\b`,
			},
		},

		// Collect2Key (trufflehog collect2)
		{
			Name:      Collect2KeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:collect2).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// ColumnKey (trufflehog column)
		{
			Name:      ColumnKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:column).{0,40}?\b((?:test|live)_[a-zA-Z0-9]{27})\b`,
			},
		},

		// CommerceJSKey (trufflehog commercejs)
		{
			Name:      CommerceJSKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:commercejs).{0,40}?\b([a-z0-9_]{48})\b`,
			},
		},

		// CommoditiesKey (trufflehog commodities)
		{
			Name:      CommoditiesKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:commodities).{0,40}?\b([a-zA-Z0-9]{60})\b`,
			},
		},

		// CompanyHubKey (trufflehog companyhub)
		{
			Name:      CompanyHubKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:companyhub).{0,40}?\b([0-9a-zA-Z]{20})\b`,
			},
		},

		// ConversionToolsKey (trufflehog conversiontools)
		{
			Name:      ConversionToolsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:conversiontools).{0,40}?\b(ey[a-zA-Z0-9_.]{157,165})\b`,
			},
		},

		// ConvertAPISecret (trufflehog convertapi)
		{
			Name:      ConvertAPISecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:convertapi).{0,40}?\b(secret_[0-9a-zA-Z]{16})\b`,
			},
		},

		// ConvierKey (trufflehog convier)
		{
			Name:      ConvierKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:convier).{0,40}?\b([0-9]{2}\|[a-zA-Z0-9]{40})\b`,
			},
		},

		// CountryLayerKey (trufflehog countrylayer)
		{
			Name:      CountryLayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:countrylayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// CraftMyPDFKey (trufflehog craftmypdf)
		{
			Name:      CraftMyPDFKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:craftmypdf).{0,40}?\b([0-9a-zA-Z]{35})\b`,
			},
		},

		// CrowdinKey (trufflehog crowdin)
		{
			Name:      CrowdinKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:crowdin).{0,40}?\b([0-9A-Za-z]{80})\b`,
			},
		},

		// CryptoCompareKey (trufflehog cryptocompare)
		{
			Name:      CryptoCompareKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:cryptocompare).{0,40}?\b([a-z-0-9]{64})\b`,
			},
		},

		// CurrencyCloudKey (trufflehog currencycloud)
		{
			Name:      CurrencyCloudKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:currencycloud).{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// CurrencyfreaksKey (trufflehog currencyfreaks)
		{
			Name:      CurrencyfreaksKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:currencyfreaks).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// CurrencylayerKey (trufflehog currencylayer)
		{
			Name:      CurrencylayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:currencylayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// CurrencyScoopKey (trufflehog currencyscoop)
		{
			Name:      CurrencyScoopKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:currencyscoop).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// CurrentsAPIKey (trufflehog currentsapi)
		{
			Name:      CurrentsAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:currentsapi).{0,40}?([a-zA-Z0-9_-]{48})`,
			},
		},

		// CustomerGuruKey (trufflehog customerguru)
		{
			Name:      CustomerGuruKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:guru).{0,40}?\b([a-z0-9A-Z]{30})\b`,
			},
		},

		// D7NetworkKey (trufflehog d7network)
		{
			Name:      D7NetworkKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:d7network).{0,40}?\b([a-zA-Z0-9\W\S]{23}\=)`,
			},
		},

		// DandelionKey (trufflehog dandelion)
		{
			Name:      DandelionKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dandelion).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// DareboostKey (trufflehog dareboost)
		{
			Name:      DareboostKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dareboost).{0,40}?\b([0-9a-zA-Z]{60})\b`,
			},
		},

		// DataboxKey (trufflehog databox)
		{
			Name:      DataboxKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:databox).{0,40}?\b([0-9a-z]{21})\b`,
			},
		},

		// DataGovKey (trufflehog datagov)
		{
			Name:      DataGovKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:data\.gov).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// DebounceKey (trufflehog debounce)
		{
			Name:      DebounceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:debounce).{0,40}?\b([a-zA-Z0-9]{13})\b`,
			},
		},

		// DeepAIKey (trufflehog deepai)
		{
			Name:      DeepAIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:deepai).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// DelightedKey (trufflehog delighted)
		{
			Name:      DelightedKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:delighted).{0,40}?\b([a-z0-9A-Z]{32})\b`,
			},
		},

		// DemioSecret (trufflehog demio)
		{
			Name:      DemioSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:demio).{0,40}?\b([a-z0-9A-Z]{10,20})\b`,
			},
		},

		// DenoDeployToken (trufflehog deno)
		{
			Name:      DenoDeployTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(dd[pw]_[a-zA-Z0-9]{36})\b`,
			},
		},

		// DeputyKey (trufflehog deputy)
		{
			Name:      DeputyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:deputy).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// DetectLanguageKey (trufflehog detectlanguage)
		{
			Name:      DetectLanguageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:detectlanguage).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// DfuseKey (trufflehog dfuse)
		{
			Name:      DfuseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(web\_[0-9a-z]{32})\b`,
			},
		},

		// DiffbotKey (trufflehog diffbot)
		{
			Name:      DiffbotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:diffbot).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// DiggernautKey (trufflehog diggernaut)
		{
			Name:      DiggernautKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:diggernaut).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// DisqusKey (trufflehog disqus)
		{
			Name:      DisqusKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:disqus).{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// DittoKey (trufflehog ditto)
		{
			Name:      DittoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ditto).{0,40}?\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12}\.[a-z0-9]{40})\b`,
			},
		},

		// DnscheckKey (trufflehog dnscheck)
		{
			Name:      DnscheckKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dnscheck).{0,40}?\b([a-z0-9A-Z]{32})\b`,
			},
		},

		// DockerAuthConfig (trufflehog docker)
		{
			Name:      DockerAuthConfigRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `{(?:\s|\\+[nrt])*\\*"auths\\*"(?:\s|\\+t)*:(?:\s|\\+t)*{(?:\s|\\+[nrt])*\\*"(?i:https?:\/\/)?[a-z0-9\-.:\/]+\\*"(?:\s|\\+t)*:(?:\s|\\+t)*{(?:(?:\s|\\+[nrt])*\\*"(?i:auth|email|username|password)\\*"\s*:\s*\\*".*?\\*"\s*,?)+?(?:\s|\\+[nrt])*}(?:\s|\\+[nrt])*}(?:\s|\\+[nrt])*}`,
			},
		},

		// DocparserKey (trufflehog docparser)
		{
			Name:      DocparserKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:docparser).{0,40}?\b([a-f0-9]{40})\b`,
			},
		},

		// DocumoKey (trufflehog documo)
		{
			Name:      DocumoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9]{154}.[a-zA-Z0-9_-]{43})\b`,
			},
		},

		// DovicoKey (trufflehog dovico)
		{
			Name:      DovicoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dovico).{0,40}?\b([0-9a-z]{32}\.[0-9a-z]{1,}\b)`,
			},
		},

		// DronaHQKey (trufflehog dronahq)
		{
			Name:      DronaHQKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dronahq).{0,40}?\b([a-z0-9]{50})\b`,
			},
		},

		// DuffelToken (trufflehog duffeltoken)
		{
			Name:      DuffelTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(duffel_(?:test|live)_[A-Za-z0-9_-]{43})(?:$|[^A-Za-z0-9_-])`,
			},
		},

		// DuoSecret (trufflehog duo)
		{
			Name:      DuoSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:duo).{0,40}?\b([A-Za-z0-9]{40})\b`,
			},
		},

		// DuplyKey (trufflehog duply)
		{
			Name:      DuplyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:duply).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// DynalistKey (trufflehog dynalist)
		{
			Name:      DynalistKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dynalist).{0,40}?\b([a-zA-Z0-9-_]{128})\b`,
			},
		},

		// DyspatchKey (trufflehog dyspatch)
		{
			Name:      DyspatchKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:dyspatch).{0,40}?\b([A-Z0-9]{52})\b`,
			},
		},

		// EagleEyeNetworksKey (trufflehog eagleeyenetworks)
		{
			Name:      EagleEyeNetworksKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:eagleeyenetworks).{0,40}?\b([a-zA-Z0-9]{15})\b`,
			},
		},

		// EasyInsightKey (trufflehog easyinsight)
		{
			Name:      EasyInsightKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:easyinsight|easy-insight).{0,40}?\b([0-9a-zA-Z]{20})\b`,
			},
		},

		// EcoStruxureITKey (trufflehog ecostruxureit)
		{
			Name:      EcoStruxureITKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ecostruxureit).{0,40}?\b(AK1[0-9a-zA-Z\/]{50,55})\b`,
			},
		},

		// EdamamKey (trufflehog edamam)
		{
			Name:      EdamamKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:edamam).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// EdenAIKey (trufflehog edenai)
		{
			Name:      EdenAIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:edenai).{0,40}?\b([a-zA-Z0-9]{36}.[a-zA-Z0-9]{92}.[a-zA-Z0-9_]{43})\b`,
			},
		},

		// EightxEightKey (trufflehog eightxeight)
		{
			Name:      EightxEightKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:8x8).{0,40}?\b([a-zA-Z0-9]{43})\b`,
			},
		},

		// ElasticEmailKey (trufflehog elasticemail)
		{
			Name:      ElasticEmailKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:elastic).{0,40}?\b([A-Za-z0-9_-]{96})\b`,
			},
		},

		// EnablexKey (trufflehog enablex)
		{
			Name:      EnablexKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:enablex).{0,40}?\b([a-zA-Z0-9]{36})\b`,
			},
		},

		// EndorLabsAPIKey (trufflehog endorlabs)
		{
			Name:      EndorLabsAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(endr\+[a-zA-Z0-9-]{16})\b`,
			},
		},

		// EnigmaKey (trufflehog enigma)
		{
			Name:      EnigmaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:enigma).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// EnvoyAPIKey (trufflehog envoyapikey)
		{
			Name:      EnvoyAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:envoy).{0,40}?\b([a-zA-Z0-9]{220})\b`,
			},
		},

		// EraserKey (trufflehog eraser)
		{
			Name:      EraserKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:eraser).{0,40}?\b([0-9a-zA-Z]{20})\b`,
			},
		},

		// EthplorerKey (trufflehog ethplorer)
		{
			Name:      EthplorerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ethplorer).{0,40}?\b([a-z0-9A-Z-]{22})\b`,
			},
		},

		// EverhourKey (trufflehog everhour)
		{
			Name:      EverhourKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:everhour).{0,40}?\b([0-9Aa-f]{4}-[0-9a-f]{4}-[0-9a-f]{6}-[0-9a-f]{6}-[0-9a-f]{8})\b`,
			},
		},

		// ExchangeRateAPIKey (trufflehog exchangerateapi)
		{
			Name:      ExchangeRateAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:exchangerate|exchange-rate).{0,40}?\b([a-f0-9]{24})\b`,
			},
		},

		// ExchangeRatesAPIKey (trufflehog exchangeratesapi)
		{
			Name:      ExchangeRatesAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:exchangerates).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ExportSDKKey (trufflehog exportsdk)
		{
			Name:      ExportSDKKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:exportsdk).{0,40}?\b([0-9a-z]{5,15}_[0-9a-z-]{36})\b`,
			},
		},

		// ExtractorAPIKey (trufflehog extractorapi)
		{
			Name:      ExtractorAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:extractorapi).{0,40}?\b([a-zA-Z-0-9]{40})\b`,
			},
		},

		// FacePlusPlusSecret (trufflehog faceplusplus)
		{
			Name:      FacePlusPlusSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:faceplusplus).{0,40}?\b([0-9a-zA-Z_-]{32})\b`,
			},
		},

		// FastForexKey (trufflehog fastforex)
		{
			Name:      FastForexKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fastforex).{0,40}?\b([a-z0-9-]{28})\b`,
			},
		},

		// FeedierKey (trufflehog feedier)
		{
			Name:      FeedierKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:feedier).{0,40}?\b([a-z0-9A-Z]{32})\b`,
			},
		},

		// FetchrssKey (trufflehog fetchrss)
		{
			Name:      FetchrssKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fetchrss).{0,40}?\b([a-zA-Z0-9.]{40})\b`,
			},
		},

		// FiberyKey (trufflehog fibery)
		{
			Name:      FiberyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fibery).{0,40}?\b([0-9a-f]{8}\.[0-9a-f]{35})\b`,
			},
		},

		// FigmaPATV3 (trufflehog figmapersonalaccesstoken/v3)
		{
			Name:      FigmaPATV3Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(figp_[a-zA-Z0-9_=-]{40,54})(?:[^a-zA-Z0-9_=-]|$)`,
			},
		},

		// FileIOKey (trufflehog fileio)
		{
			Name:      FileIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fileio).{0,40}?\b([A-Z0-9.-]{39})\b`,
			},
		},

		// FinageKey (trufflehog finage)
		{
			Name:      FinageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(API_KEY[0-9A-Z]{32})\b`,
			},
		},

		// FinancialModelingPrepKey (trufflehog financialmodelingprep)
		{
			Name:      FinancialModelingPrepKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:financialmodelingprep).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// FindlKey (trufflehog findl)
		{
			Name:      FindlKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:findl).{0,40}?\b([a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{12})\b`,
			},
		},

		// FixerIOKey (trufflehog fixerio)
		{
			Name:      FixerIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fixer).{0,40}?\b([A-Za-z0-9]{32})\b`,
			},
		},

		// FlatIOKey (trufflehog flatio)
		{
			Name:      FlatIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:flat\.?io).{0,40}?\b([0-9a-z]{128})\b`,
			},
		},

		// FleetbaseKey (trufflehog fleetbase)
		{
			Name:      FleetbaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(flb_live_[0-9a-zA-Z]{20})\b`,
			},
		},

		// FlexportKey (trufflehog flexport)
		{
			Name:      FlexportKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(shltm_[0-9a-zA-Z-_]{40})`,
			},
		},

		// FlickrKey (trufflehog flickr)
		{
			Name:      FlickrKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:flickr).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// FlightAPIKey (trufflehog flightapi)
		{
			Name:      FlightAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:flightapi).{0,40}?\b([a-z0-9]{24})\b`,
			},
		},

		// FlightLabsKey (trufflehog flightlabs)
		{
			Name:      FlightLabsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9\.ey[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]{86})\b`,
			},
		},

		// FlightstatsKey (trufflehog flightstats)
		{
			Name:      FlightstatsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:flightstats).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// FloatKey (trufflehog float)
		{
			Name:      FloatKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:float).{0,40}?\b([a-f0-9]{16}[A-Za-z0-9+/]{42,43}=)`,
			},
		},

		// FlowFluKey (trufflehog flowflu)
		{
			Name:      FlowFluKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:flowflu).{0,40}?\b([a-zA-Z0-9]{51})\b`,
			},
		},

		// FmfwKey (trufflehog fmfw)
		{
			Name:      FmfwKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fmfw).{0,40}?\b([a-zA-Z0-9_-]{32})\b`,
			},
		},

		// FormcraftKey (trufflehog formcraft)
		{
			Name:      FormcraftKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:formcraft).{0,40}?\b([0-9a-z]{16})\b`,
			},
		},

		// FormsiteKey (trufflehog formsite)
		{
			Name:      FormsiteKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:formsite).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// FourSquareSecret (trufflehog foursquare)
		{
			Name:      FourSquareSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:foursquare).{0,40}?\b([0-9A-Z]{48})\b`,
			},
		},

		// FrontKey (trufflehog front)
		{
			Name:      FrontKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:front).{0,40}?\b([0-9a-zA-Z]{36}.[0-9a-zA-Z\.\-\_]{188,244})\b`,
			},
		},

		// FulcrumKey (trufflehog fulcrum)
		{
			Name:      FulcrumKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fulcrum).{0,40}?\b([a-z0-9]{80})\b`,
			},
		},

		// FXMarketKey (trufflehog fxmarket)
		{
			Name:      FXMarketKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:fxmarket).{0,40}?\b([0-9Aa-zA-Z-_=]{20})\b`,
			},
		},

		// GeckoboardKey (trufflehog geckoboard)
		{
			Name:      GeckoboardKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:geckoboard).{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// GeminiKey (trufflehog gemini)
		{
			Name:      GeminiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:master-|account-)[0-9A-Za-z]{20})\b`,
			},
		},

		// GengoSecret (trufflehog gengo)
		{
			Name:      GengoSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:gengo).{0,40}?([0-9a-zA-Z\[\]\-\(\)\{\}|_^@$=~]{64})(?:[ \r\n]|$)`,
			},
		},

		// GeoapifyKey (trufflehog geoapify)
		{
			Name:      GeoapifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:geoapify).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// GeocodeKey (trufflehog geocode)
		{
			Name:      GeocodeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:geocode).{0,40}?\b([a-z0-9]{28})\b`,
			},
		},

		// GeocodifyKey (trufflehog geocodify)
		{
			Name:      GeocodifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:geocodify).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// GeocodioKey (trufflehog geocodio)
		{
			Name:      GeocodioKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:geocod).{0,40}?\b([a-z0-9]{39})\b`,
			},
		},

		// GeoIpifiKey (trufflehog geoipifi)
		{
			Name:      GeoIpifiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ipifi).{0,40}?\b([a-z0-9A-Z_]{32})\b`,
			},
		},

		// GetEmailKey (trufflehog getemail)
		{
			Name:      GetEmailKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:getemail).{0,40}?\b([a-zA-Z0-9-]{20})\b`,
			},
		},

		// GetEmailsKey (trufflehog getemails)
		{
			Name:      GetEmailsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:getemails).{0,40}?\b([a-z0-9-]{26})\b`,
			},
		},

		// GetGeoAPIKey (trufflehog getgeoapi)
		{
			Name:      GetGeoAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:getgeoapi).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// GetgistKey (trufflehog getgist)
		{
			Name:      GetgistKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:getgist).{0,40}?\b([a-z0-9A-Z+=]{68})`,
			},
		},

		// GetSandboxKey (trufflehog getsandbox)
		{
			Name:      GetSandboxKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:getsandbox).{0,40}?\b([a-z0-9-]{40})\b`,
			},
		},

		// GitLabOAuthAppSecret (trufflehog gitlaboauth2)
		{
			Name:      GitLabOAuthAppSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(gloas-[0-9a-f]{64})\b`,
			},
		},

		// GitterKey (trufflehog gitter)
		{
			Name:      GitterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:gitter).{0,40}?\b([a-z0-9-]{40})\b`,
			},
		},

		// GlassnodeKey (trufflehog glassnode)
		{
			Name:      GlassnodeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:glassnode).{0,40}?\b([0-9A-Za-z]{27})\b`,
			},
		},

		// GoCanvasKey (trufflehog gocanvas)
		{
			Name:      GoCanvasKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:gocanvas).{0,40}?\b([0-9A-Za-z/+]{43}=)(?:[ \r\n]|$)`,
			},
		},

		// GoCardlessKey (trufflehog gocardless)
		{
			Name:      GoCardlessKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(live_[0-9A-Za-z\_\-]{40})(?:[ "'\r\n]|$)`,
			},
		},

		// GoodDayKey (trufflehog goodday)
		{
			Name:      GoodDayKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:goodday).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// GraphhopperKey (trufflehog graphhopper)
		{
			Name:      GraphhopperKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:graphhopper).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// GroovehqKey (trufflehog groovehq)
		{
			Name:      GroovehqKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:groove).{0,40}?\b([a-z0-9A-Z]{64})`,
			},
		},

		// GTMetrixKey (trufflehog gtmetrix)
		{
			Name:      GTMetrixKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:gtmetrix).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// GuardianapiKey (trufflehog guardianapi)
		{
			Name:      GuardianapiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:guardian).{0,40}?\b([0-9Aa-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// GuruKey (trufflehog guru)
		{
			Name:      GuruKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:guru).{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// GyazoKey (trufflehog gyazo)
		{
			Name:      GyazoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:gyazo).{0,40}?\b([0-9A-Za-z-]{43})\b`,
			},
		},

		// HappyscribeKey (trufflehog happyscribe)
		{
			Name:      HappyscribeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:happyscribe).{0,40}?\b([0-9a-zA-Z]{24})\b`,
			},
		},

		// HarvestKey (trufflehog harvest)
		{
			Name:      HarvestKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:harvest).{0,40}?\b([a-z0-9A-Z._]{97})\b`,
			},
		},

		// HashiCorpVaultBatchToken (trufflehog hashicorpvault/hashicorpvaultbatchtoken)
		{
			Name:      HashiCorpVaultBatchTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(hvb\.[A-Za-z0-9_.-]{50,300})(?:[^A-Za-z0-9_.-]|$)`,
			},
		},

		// HasuraKey (trufflehog hasura)
		{
			Name:      HasuraKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:hasura).{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// HelloSignKey (trufflehog hellosign)
		{
			Name:      HelloSignKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:hellosign).{0,40}?\b([a-zA-Z-0-9/+]{64})\b`,
			},
		},

		// HelpCrunchKey (trufflehog helpcrunch)
		{
			Name:      HelpCrunchKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:helpcrunch).{0,40}?\b([a-zA-Z-0-9+/=]{328})`,
			},
		},

		// HelpscoutKey (trufflehog helpscout)
		{
			Name:      HelpscoutKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:helpscout).{0,40}?\b([a-z0-9]{40})\b`,
			},
		},

		// HerokuAPIKeyV2 (trufflehog heroku/v2)
		{
			Name:      HerokuAPIKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(HRKU-AA[0-9a-zA-Z_-]{58})\b`,
			},
		},

		// HiveKey (trufflehog hive)
		{
			Name:      HiveKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:hive).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// HiveageKey (trufflehog hiveage)
		{
			Name:      HiveageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:hiveage).{0,40}?\b([0-9A-Za-z\_\-]{20})\b`,
			},
		},

		// HolidayAPIKey (trufflehog holidayapi)
		{
			Name:      HolidayAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:holidayapi).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// HolisticKey (trufflehog holistic)
		{
			Name:      HolisticKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:holistic).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// HostKey (trufflehog host)
		{
			Name:      HostKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:host\.io).{0,40}?\b([a-z0-9]{14})\b`,
			},
		},

		// Html2PdfKey (trufflehog html2pdf)
		{
			Name:      Html2PdfKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:html2pdf).{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// HubSpotPrivateAppToken (trufflehog hubspot_apikey/v2)
		{
			Name:      HubSpotPrivateAppTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pat-(?:eu|na)1-[A-Za-z0-9]{8}\-[A-Za-z0-9]{4}\-[A-Za-z0-9]{4}\-[A-Za-z0-9]{4}\-[A-Za-z0-9]{12})\b`,
			},
		},

		// HumanityKey (trufflehog humanity)
		{
			Name:      HumanityKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:humanity).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// HumioAPIToken (trufflehog humioapitoken)
		{
			Name:      HumioAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b([A-Za-z0-9]{24}(?:[A-Za-z0-9]{8})?~[A-Za-z0-9]{44})\b`,
			},
		},

		// HybiscusKey (trufflehog hybiscus)
		{
			Name:      HybiscusKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:hybiscus).{0,40}?\b([0-9a-zA-Z]{43})\b`,
			},
		},

		// HypertrackKey (trufflehog hypertrack)
		{
			Name:      HypertrackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:hypertrack).{0,40}?\b([0-9a-zA-Z\_\-]{54})\b`,
			},
		},

		// IbmCloudUserKey (trufflehog ibmclouduserkey)
		{
			Name:      IbmCloudUserKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ibm).{0,40}?\b([A-Za-z0-9_-]{44})\b`,
			},
		},

		// IconFinderKey (trufflehog iconfinder)
		{
			Name:      IconFinderKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:iconfinder).{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// IexapisKey (trufflehog iexapis)
		{
			Name:      IexapisKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:iexapis).{0,40}?\b(sk_[a-z0-9]{32})\b`,
			},
		},

		// IexcloudKey (trufflehog iexcloud)
		{
			Name:      IexcloudKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:iexcloud).{0,40}?\b([a-z0-9_]{35})\b`,
			},
		},

		// ImagekitKey (trufflehog imagekit)
		{
			Name:      ImagekitKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:imagekit).{0,40}?\b([a-zA-Z0-9_=]{36})`,
			},
		},

		// ImaggaKey (trufflehog imagga)
		{
			Name:      ImaggaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:imagga).{0,40}?\b([a-z0-9A-Z=]{72})`,
			},
		},

		// ImpalaKey (trufflehog impala)
		{
			Name:      ImpalaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:impala).{0,40}?\b([0-9A-Za-z_]{46})\b`,
			},
		},

		// InfisicalKey (trufflehog infisical)
		{
			Name:      InfisicalKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:st\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\.[0-9a-f]{32})(?:\.[0-9a-f]{32})?)\b`,
			},
		},

		// InsightlyKey (trufflehog insightly)
		{
			Name:      InsightlyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:insightly).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// InstabotKey (trufflehog instabot)
		{
			Name:      InstabotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:instabot).{0,40}?\b([0-9a-zA-Z=+\/]{43}[0-9a-zA-Z+\/=]{1})`,
			},
		},

		// InstamojoSecret (trufflehog instamojo)
		{
			Name:      InstamojoSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:instamojo).{0,40}?\b([0-9a-zA-Z]{128})\b`,
			},
		},

		// IntersellerKey (trufflehog interseller)
		{
			Name:      IntersellerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:interseller).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// Intra42Key (trufflehog intra42)
		{
			Name:      Intra42KeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(s-s4t2(?:ud|af)-[a-f0-9]{64})\b`,
			},
		},

		// IntrinioKey (trufflehog intrinio)
		{
			Name:      IntrinioKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:intrinio).{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// InvoiceOceanKey (trufflehog invoiceocean)
		{
			Name:      InvoiceOceanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:invoiceocean).{0,40}?\b([0-9A-Za-z]{20})\b`,
			},
		},

		// Ip2locationKey (trufflehog ip2location)
		{
			Name:      Ip2locationKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ip2location).{0,40}?\b([0-9A-Z]{32})\b`,
			},
		},

		// IpapiKey (trufflehog ipapi)
		{
			Name:      IpapiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ipapi).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// IPGeolocationKey (trufflehog ipgeolocation)
		{
			Name:      IPGeolocationKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ipgeolocation).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// IPInfoDBKey (trufflehog ipinfodb)
		{
			Name:      IPInfoDBKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ipinfodb).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// IPQualityKey (trufflehog ipquality)
		{
			Name:      IPQualityKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ipquality).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// JotformKey (trufflehog jotform)
		{
			Name:      JotformKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:jotform).{0,40}?\b([0-9Aa-z]{32})\b`,
			},
		},

		// JuroKey (trufflehog juro)
		{
			Name:      JuroKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:juro).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// KanbanKey (trufflehog kanban)
		{
			Name:      KanbanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:kanban).{0,40}?\b([0-9A-Z]{12})\b`,
			},
		},

		// KarmaCRMKey (trufflehog karmacrm)
		{
			Name:      KarmaCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:karmacrm|karma_?crm).{0,40}?\b([a-zA-Z0-9]{20})\b`,
			},
		},

		// KeenIOKey (trufflehog keenio)
		{
			Name:      KeenIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:keen).{0,40}?\b([0-9A-Z]{64})\b`,
			},
		},

		// KickboxKey (trufflehog kickbox)
		{
			Name:      KickboxKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:kickbox).{0,40}?\b([a-zA-Z0-9_]+[a-zA-Z0-9]{64})\b`,
			},
		},

		// KlipfolioKey (trufflehog klipfolio)
		{
			Name:      KlipfolioKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:klipfolio).{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// KnapsackProKey (trufflehog knapsackpro)
		{
			Name:      KnapsackProKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:knapsackpro).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// KongKonnectKey (trufflehog kong)
		{
			Name:      KongKonnectKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:kpat_|spat_)[a-zA-Z0-9]{49})\b`,
			},
		},

		// KontentKey (trufflehog kontent)
		{
			Name:      KontentKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:kontent).{0,40}?\b(ey[0-9a-zA-Z]{30,34}.ey[0-9a-zA-Z-\/_]{200,400}.[0-9a-zA-Z-\/_]{40,43})\b`,
			},
		},

		// KrakenSecret (trufflehog kraken)
		{
			Name:      KrakenSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:kraken).{0,40}?\b([0-9A-Za-z\/\+=]{86,88})(?:[ "'\r\n]|$)`,
			},
		},

		// KuCoinSecret (trufflehog kucoin)
		{
			Name:      KuCoinSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:kucoin).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// KylasKey (trufflehog kylas)
		{
			Name:      KylasKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:kylas).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// LambdaCloudKey (trufflehog lambdacloud)
		{
			Name:      LambdaCloudKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(secret_[a-z0-9][a-z0-9-]{0,63}_[0-9a-f]{12}4[0-9a-f]{3}[89ab][0-9a-f]{15}\.[A-Za-z0-9]{32})(?:[^A-Za-z0-9]|$)`,
			},
		},

		// LanguageLayerKey (trufflehog languagelayer)
		{
			Name:      LanguageLayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:languagelayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// LeadfeederKey (trufflehog leadfeeder)
		{
			Name:      LeadfeederKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:leadfeeder).{0,40}?\b([a-zA-Z0-9-]{43})\b`,
			},
		},

		// LemlistKey (trufflehog lemlist)
		{
			Name:      LemlistKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:lemlist).{0,40}?\b([a-f0-9]{32})\b`,
			},
		},

		// LendflowKey (trufflehog lendflow)
		{
			Name:      LendflowKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:lendflow).{0,40}?\b([a-zA-Z0-9]{36}\.[a-zA-Z0-9]{235}\.[a-zA-Z0-9]{32}\-[a-zA-Z0-9]{47}\-[a-zA-Z0-9_]{162}\-[a-zA-Z0-9]{42}\-[a-zA-Z0-9_]{40}\-[a-zA-Z0-9_]{66}\-[a-zA-Z0-9_]{59}\-[a-zA-Z0-9]{7}\-[a-zA-Z0-9_]{220})\b`,
			},
		},

		// LessAnnoyingCRMKey (trufflehog lessannoyingcrm)
		{
			Name:      LessAnnoyingCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:lessannoying|less_annoying).{0,40}?\b([a-zA-Z0-9-]{57})\b`,
			},
		},

		// LexigramKey (trufflehog lexigram)
		{
			Name:      LexigramKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:lexigram).{0,40}?\b([a-zA-Z0-9\S]{301})\b`,
			},
		},

		// LineMessagingKey (trufflehog linemessaging)
		{
			Name:      LineMessagingKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:line).{0,40}?\b([A-Za-z0-9+/]{171,172})\b`,
			},
		},

		// LineNotifyKey (trufflehog linenotify)
		{
			Name:      LineNotifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:linenotify).{0,40}?\b([0-9A-Za-z]{43})\b`,
			},
		},

		// LinkPreviewKey (trufflehog linkpreview)
		{
			Name:      LinkPreviewKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:linkpreview).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// LiveAgentKey (trufflehog liveagent)
		{
			Name:      LiveAgentKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:liveagent).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// LoadmillKey (trufflehog loadmill)
		{
			Name:      LoadmillKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:loadmill).{0,40}?\b([0-9a-zA-Z]{40})\b`,
			},
		},

		// LobKey (trufflehog lob)
		{
			Name:      LobKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:live|test)_[a-f0-9]{35})\b`,
			},
		},

		// LocationIQKey (trufflehog locationiq)
		{
			Name:      LocationIQKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:locationiq).{0,40}?\b(pk\.[a-zA-Z-0-9]{32})\b`,
			},
		},

		// LoginradiusKey (trufflehog loginradius)
		{
			Name:      LoginradiusKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:loginradius).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// LokaliseToken (trufflehog lokalisetoken)
		{
			Name:      LokaliseTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:lokalise).{0,40}?\b([a-z0-9]{40})\b`,
			},
		},

		// LoyverseKey (trufflehog loyverse)
		{
			Name:      LoyverseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:loyverse).{0,40}?\b([0-9-a-z]{32})\b`,
			},
		},

		// LunchMoneyKey (trufflehog lunchmoney)
		{
			Name:      LunchMoneyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:lunchmoney).{0,40}?\b([a-f0-9]{50})\b`,
			},
		},

		// LunoKey (trufflehog luno)
		{
			Name:      LunoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:luno).{0,40}?\b([a-zA-Z0-9_-]{43})\b`,
			},
		},

		// M3oKey (trufflehog m3o)
		{
			Name:      M3oKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:m3o).{0,40}?\b([0-9A-Za-z]{48})\b`,
			},
		},

		// MadKuduKey (trufflehog madkudu)
		{
			Name:      MadKuduKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:madkudu).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// MagicBellKey (trufflehog magicbell)
		{
			Name:      MagicBellKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:magicbell).{0,40}?\b([a-zA-Z-0-9]{40})\b`,
			},
		},

		// MagneticKey (trufflehog magnetic)
		{
			Name:      MagneticKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:magnetic).{0,40}?\b([0-9Aa-z]{8}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{12})\b`,
			},
		},

		// MailboxlayerKey (trufflehog mailboxlayer)
		{
			Name:      MailboxlayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mailboxlayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// MailJetBasicAuthKey (trufflehog mailjetbasicauth)
		{
			Name:      MailJetBasicAuthKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mailjet).{0,40}?\b([A-Za-z0-9]{87}\=)`,
			},
		},

		// MailJetSMSKey (trufflehog mailjetsms)
		{
			Name:      MailJetSMSKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mailjet).{0,40}?\b([A-Za-z0-9]{32})\b`,
			},
		},

		// MailmodoKey (trufflehog mailmodo)
		{
			Name:      MailmodoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mailmodo).{0,40}?\b([A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7}-[A-Z0-9]{7})\b`,
			},
		},

		// MailsacKey (trufflehog mailsac)
		{
			Name:      MailsacKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mailsac).{0,40}?\b(k_[0-9A-Za-z]{36,})\b`,
			},
		},

		// ManifestKey (trufflehog manifest)
		{
			Name:      ManifestKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:manifest).{0,40}?\b([a-zA-z0-9]{32})\b`,
			},
		},

		// MapquestKey (trufflehog mapquest)
		{
			Name:      MapquestKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mapquest).{0,40}?\b([0-9A-Za-z]{32})\b`,
			},
		},

		// MarketstackKey (trufflehog marketstack)
		{
			Name:      MarketstackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:marketstack).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// MavenlinkKey (trufflehog mavenlink)
		{
			Name:      MavenlinkKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mavenlink).{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// MaxMindLicenseKey (trufflehog maxmindlicense/v1)
		{
			Name:      MaxMindLicenseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:maxmind|geoip).{0,40}?\b([0-9A-Za-z]{16})\b`,
			},
		},

		// MaxMindLicenseKeyV2 (trufflehog maxmindlicense/v2)
		{
			Name:      MaxMindLicenseKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b([a-zA-Z0-9]{6}_[a-zA-Z0-9]{29}_mmk)\b`,
			},
		},

		// MeaningCloudKey (trufflehog meaningcloud)
		{
			Name:      MeaningCloudKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:meaningcloud).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// MeistertaskKey (trufflehog meistertask)
		{
			Name:      MeistertaskKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:meistertask).{0,40}?\b([a-zA-Z0-9]{43})\b`,
			},
		},

		// MerakiKey (trufflehog meraki)
		{
			Name:      MerakiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:meraki).{0,40}?([0-9a-f]{40})`,
			},
		},

		// MesiboKey (trufflehog mesibo)
		{
			Name:      MesiboKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mesibo).{0,40}?\b([0-9A-Za-z]{64})\b`,
			},
		},

		// MetaAPIKey (trufflehog metaapi)
		{
			Name:      MetaAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:metaapi|meta-api).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// MetabaseKey (trufflehog metabase)
		{
			Name:      MetabaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:metabase).{0,40}?\b([a-zA-Z0-9-]{36})\b`,
			},
		},

		// MetriloKey (trufflehog metrilo)
		{
			Name:      MetriloKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:metrilo).{0,40}?\b([a-z0-9]{16})\b`,
			},
		},

		// MindmeisterKey (trufflehog mindmeister)
		{
			Name:      MindmeisterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mindmeister).{0,40}?\b([a-zA-Z0-9]{43})\b`,
			},
		},

		// MiroKey (trufflehog miro)
		{
			Name:      MiroKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:miro).{0,40}?\b([0-9a-zA-Z]{27})\b`,
			},
		},

		// MiteKey (trufflehog mite)
		{
			Name:      MiteKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mite).{0,40}?\b([0-9a-z]{16})\b`,
			},
		},

		// MixmaxKey (trufflehog mixmax)
		{
			Name:      MixmaxKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mixmax).{0,40}?\b([a-zA-Z0-9_-]{36})\b`,
			},
		},

		// ModerationKey (trufflehog moderation)
		{
			Name:      ModerationKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:moderation).{0,40}?\b([a-zA-Z0-9]{36}\.[a-zA-Z0-9]{115}\.[a-zA-Z0-9_]{43})\b`,
			},
		},

		// MonkeyLearnKey (trufflehog monkeylearn)
		{
			Name:      MonkeyLearnKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:monkeylearn).{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// MoonclerkKey (trufflehog moonclerk)
		{
			Name:      MoonclerkKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:moonclerk).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// MuxSecret (trufflehog mux)
		{
			Name:      MuxSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:mux).{0,40}?([0-9A-Za-z\/\+]{75})(?:[ \r\n]|$)`,
			},
		},

		// MyfreshworksKey (trufflehog myfreshworks)
		{
			Name:      MyfreshworksKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:freshworks).{0,40}?\b([a-z0-9A-Z-_]{22})\b`,
			},
		},

		// MyIntervalsKey (trufflehog myintervals)
		{
			Name:      MyIntervalsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:myintervals).{0,40}?\b([0-9a-z]{11})\b`,
			},
		},

		// NasdaqDataLinkKey (trufflehog nasdaqdatalink)
		{
			Name:      NasdaqDataLinkKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nasdaq).{0,40}?\b([a-zA-Z0-9_-]{20})\b`,
			},
		},

		// NethuntKey (trufflehog nethunt)
		{
			Name:      NethuntKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nethunt).{0,40}?\b([a-z0-9-\S]{36})\b`,
			},
		},

		// NetsuiteSecret (trufflehog netsuite)
		{
			Name:      NetsuiteSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:netsuite).{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// NeutrinoAPIKey (trufflehog neutrinoapi)
		{
			Name:      NeutrinoAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:neutrinoapi).{0,40}?\b([a-zA-Z0-9]{48})\b`,
			},
		},

		// NewRelicBrowserKeyV2 (trufflehog newrelicbrowserkey)
		{
			Name:      NewRelicBrowserKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(NRBR-[0-9a-f]{19})\b`,
			},
		},

		// NewRelicInsightsInsertKey (trufflehog newrelicinsightsinsertkey)
		{
			Name:      NewRelicInsightsInsertKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(NRII-[a-zA-Z0-9-_]{25})`,
			},
		},

		// NewRelicInsightsQueryKey (trufflehog newrelicinsightsquerykey)
		{
			Name:      NewRelicInsightsQueryKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(NRIQ-[a-zA-Z0-9-_]{25})`,
			},
		},

		// NewRelicLicenseKeyV2 (trufflehog newreliclicensekey)
		{
			Name:      NewRelicLicenseKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:[0-9a-f]{32}|eu01xx[0-9a-f]{26})FFFFNRAL)\b`,
			},
		},

		// NewRelicMobileAppToken (trufflehog newrelicmobileapptoken)
		{
			Name:      NewRelicMobileAppTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:AA[0-9a-f]{40}|eu01xx[0-9a-f]{36})-NRMA)\b`,
			},
		},

		// NewRelicUserKey (trufflehog newrelicuserkey)
		{
			Name:      NewRelicUserKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(NRAK-[A-Z0-9]{27})\b`,
			},
		},

		// NewsapiKey (trufflehog newsapi)
		{
			Name:      NewsapiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:newsapi).{0,40}?\b([a-z0-9]{32})`,
			},
		},

		// NewscatcherKey (trufflehog newscatcher)
		{
			Name:      NewscatcherKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:newscatcher).{0,40}?\b([0-9A-Za-z_]{43})\b`,
			},
		},

		// NexmoAPIKey (trufflehog nexmoapikey)
		{
			Name:      NexmoAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nexmo).{0,40}?\b([A-Za-z0-9_-]{16})\b`,
			},
		},

		// NftportKey (trufflehog nftport)
		{
			Name:      NftportKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nftport).{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// NicereplyKey (trufflehog nicereply)
		{
			Name:      NicereplyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nicereply).{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// NimbleKey (trufflehog nimble)
		{
			Name:      NimbleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nimble).{0,40}?\b([a-zA-Z0-9]{30})\b`,
			},
		},

		// NoticeableKey (trufflehog noticeable)
		{
			Name:      NoticeableKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:noticeable).{0,40}?\b([0-9a-zA-Z]{20})\b`,
			},
		},

		// NozbeTeamsKey (trufflehog nozbeteams)
		{
			Name:      NozbeTeamsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nozbe|nozbeteams).{0,40}?\b([0-9A-Za-z]{16}_[0-9A-Za-z\-_]{64})(?:[ \r\n]|$)`,
			},
		},

		// NumverifyKey (trufflehog numverify)
		{
			Name:      NumverifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:numverify).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// NutritionixKey (trufflehog nutritionix)
		{
			Name:      NutritionixKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nutritionix).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// NylasKey (trufflehog nylas)
		{
			Name:      NylasKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:nylas).{0,40}?\b([0-9A-Za-z]{30})\b`,
			},
		},

		// OandaKey (trufflehog oanda)
		{
			Name:      OandaKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:oanda).{0,40}?\b([a-zA-Z0-9]{24})\b`,
			},
		},

		// OctopusDeployToken (trufflehog octopusdeploy)
		{
			Name:      OctopusDeployTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(API-[A-Z0-9]{29,34})\b`,
			},
		},

		// OnepageCRMKey (trufflehog onepagecrm)
		{
			Name:      OnepageCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:onepagecrm).{0,40}?\b([a-zA-Z0-9=]{44})`,
			},
		},

		// OnfleetKey (trufflehog onfleet)
		{
			Name:      OnfleetKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:onfleet).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// OOPSpamKey (trufflehog oopspam)
		{
			Name:      OOPSpamKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:oopspam).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// OpenCageDataKey (trufflehog opencagedata)
		{
			Name:      OpenCageDataKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:opencagedata).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// OpenRouterKey (trufflehog openrouter)
		{
			Name:      OpenRouterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sk-or-v1-[0-9a-f]{64})\b`,
			},
		},

		// OpenuvKey (trufflehog openuv)
		{
			Name:      OpenuvKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:openuv).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// OpenVpnSecret (trufflehog openvpn)
		{
			Name:      OpenVpnSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:openvpn).{0,40}?\b([a-zA-Z0-9_-]{64,})\b`,
			},
		},

		// OpenWeatherKey (trufflehog openweather)
		{
			Name:      OpenWeatherKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:openweather).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// OverloopKey (trufflehog overloop)
		{
			Name:      OverloopKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:overloop).{0,40}?\b([a-zA-Z\_\-0-9]{50})\b`,
			},
		},

		// OwlbotKey (trufflehog owlbot)
		{
			Name:      OwlbotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:owlbot).{0,40}?\b([a-z0-9]{40})\b`,
			},
		},

		// PagarmeKey (trufflehog pagarme)
		{
			Name:      PagarmeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ak_live_[a-zA-Z0-9]{30})\b`,
			},
		},

		// PandadocKey (trufflehog pandadoc)
		{
			Name:      PandadocKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pandadoc).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// PandaScoreKey (trufflehog pandascore)
		{
			Name:      PandaScoreKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pandascore).{0,40}?([0-9A-Za-z\-\_]{51})(?:[ \r\n]|$)`,
			},
		},

		// PaperformKey (trufflehog paperform)
		{
			Name:      PaperformKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:paperform).{0,40}?\b([a-z0-9A-Z-._]{850,1000})\b`,
			},
		},

		// ParallelDotsKey (trufflehog paralleldots)
		{
			Name:      ParallelDotsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:paralleldots).{0,40}?\b([0-9A-Za-z]{43})\b`,
			},
		},

		// ParsehubKey (trufflehog parsehub)
		{
			Name:      ParsehubKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:parsehub).{0,40}?\b([0-9a-zA-Z]{12})\b`,
			},
		},

		// ParseurKey (trufflehog parseur)
		{
			Name:      ParseurKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:parseur[^il]).{0,40}?\b([a-f0-9]{40})\b`,
			},
		},

		// PartnerstackKey (trufflehog partnerstack)
		{
			Name:      PartnerstackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:partnerstack).{0,40}?\b([0-9A-Za-z]{64})\b`,
			},
		},

		// PastebinKey (trufflehog pastebin)
		{
			Name:      PastebinKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pastebin).{0,40}?\b([a-zA-Z0-9_]{32})\b`,
			},
		},

		// PaydirtappKey (trufflehog paydirtapp)
		{
			Name:      PaydirtappKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:paydirtapp).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// PaymoappKey (trufflehog paymoapp)
		{
			Name:      PaymoappKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:paymoapp).{0,40}?\b([a-zA-Z0-9]{44})\b`,
			},
		},

		// PaymongoKey (trufflehog paymongo)
		{
			Name:      PaymongoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:paymongo).{0,40}?\b([a-zA-Z0-9_]{32})\b`,
			},
		},

		// PayPalOAuthSecret (trufflehog paypaloauth)
		{
			Name:      PayPalOAuthSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:paypal).{0,40}?\b([A-Za-z0-9_\.\-]{44,80})\b`,
			},
		},

		// PdfLayerKey (trufflehog pdflayer)
		{
			Name:      PdfLayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pdflayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// PdfShiftKey (trufflehog pdfshift)
		{
			Name:      PdfShiftKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pdfshift).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// PepipostKey (trufflehog pepipost)
		{
			Name:      PepipostKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pepipost|netcore).{0,40}?\b([a-zA-Z-0-9]{32})\b`,
			},
		},

		// PgAnalyzeReadKey (trufflehog pganalyzereadkey)
		{
			Name:      PgAnalyzeReadKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pgar_[A-Za-z0-9]{27})\b`,
			},
		},

		// PhotoroomKey (trufflehog photoroom)
		{
			Name:      PhotoroomKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:photoroom).{0,40}?\b(?:sandbox_)?(sk_pr_[a-zA-Z0-9]{1,64}_[a-fA-F0-9]{40})\b`,
			},
		},

		// PhraseAccessToken (trufflehog phraseaccesstoken)
		{
			Name:      PhraseAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:phrase).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// PineconeKeyV2 (trufflehog pinecone)
		{
			Name:      PineconeKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pcsk_(?:[A-Za-z0-9]{5,6})_[A-Za-z0-9]{63})\b`,
			},
		},

		// PivotalTrackerKey (trufflehog pivotaltracker)
		{
			Name:      PivotalTrackerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pivotal).{0,40}?([a-z0-9]{32})`,
			},
		},

		// PixabayKey (trufflehog pixabay)
		{
			Name:      PixabayKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pixabay).{0,40}?\b([a-z0-9-]{34})\b`,
			},
		},

		// PlanviewLeanKitKey (trufflehog planviewleankit)
		{
			Name:      PlanviewLeanKitKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:planviewleankit|planview).{0,40}?\b([0-9a-f]{128})\b`,
			},
		},

		// PlanyoKey (trufflehog planyo)
		{
			Name:      PlanyoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:planyo).{0,40}?\b([0-9a-z]{62})\b`,
			},
		},

		// PodioKey (trufflehog podio)
		{
			Name:      PodioKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:podio).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// PollsAPIKey (trufflehog pollsapi)
		{
			Name:      PollsAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pollsapi).{0,40}?\b([A-Z0-9]{28})\b`,
			},
		},

		// PoloniexSecret (trufflehog poloniex)
		{
			Name:      PoloniexSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:poloniex).{0,40}?\b([0-9a-f]{128})\b`,
			},
		},

		// PostageAppKey (trufflehog postageapp)
		{
			Name:      PostageAppKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:postageapp).{0,40}?\b([0-9A-Za-z]{32})\b`,
			},
		},

		// PostbacksKey (trufflehog postbacks)
		{
			Name:      PostbacksKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:postbacks).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// PowrbotKey (trufflehog powrbot)
		{
			Name:      PowrbotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:powrbot).{0,40}?\b([a-z0-9A-Z]{40})\b`,
			},
		},

		// PrefectTokenV2 (trufflehog prefect)
		{
			Name:      PrefectTokenV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(pnu_[a-zA-Z0-9]{36})\b`,
			},
		},

		// PrivacyKey (trufflehog privacy)
		{
			Name:      PrivacyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:privacy).{0,40}?\b([a-z0-9]{8}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{12})\b`,
			},
		},

		// ProdpadKey (trufflehog prodpad)
		{
			Name:      ProdpadKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:prodpad).{0,40}?\b([a-f0-9]{64})\b`,
			},
		},

		// ProspectCRMKey (trufflehog prospectcrm)
		{
			Name:      ProspectCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:prospect).{0,40}?\b([a-z0-9-]{32})\b`,
			},
		},

		// ProtocolsIOKey (trufflehog protocolsio)
		{
			Name:      ProtocolsIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:protocols).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// ProxyCrawlKey (trufflehog proxycrawl)
		{
			Name:      ProxyCrawlKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:proxycrawl).{0,40}?\b([a-zA-Z0-9_]{22})\b`,
			},
		},

		// PureStakeKey (trufflehog purestake)
		{
			Name:      PureStakeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:purestake).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// PushBulletAPIKey (trufflehog pushbulletapikey)
		{
			Name:      PushBulletAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:pushbullet).{0,40}?\b([A-Za-z0-9_\.]{34})\b`,
			},
		},

		// QaseKey (trufflehog qase)
		{
			Name:      QaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:qase).{0,40}?\b([0-9a-zA-Z]{40})\b`,
			},
		},

		// QualarooKey (trufflehog qualaroo)
		{
			Name:      QualarooKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:qualaroo).{0,40}?\b([a-z0-9A-Z=]{64})`,
			},
		},

		// QuboleKey (trufflehog qubole)
		{
			Name:      QuboleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:qubole).{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// RampSecret (trufflehog ramp)
		{
			Name:      RampSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ramp_sec_[[:alnum:]]{48})\b`,
			},
		},

		// RavenKey (trufflehog raven)
		{
			Name:      RavenKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:raven).{0,40}?\b([A-Z0-9-]{16})\b`,
			},
		},

		// RawgKey (trufflehog rawg)
		{
			Name:      RawgKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:rawg).{0,40}?\b([0-9Aa-z]{32})\b`,
			},
		},

		// ReachmailKey (trufflehog reachmail)
		{
			Name:      ReachmailKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:reachmail).{0,40}?\b([a-zA-Z0-9-_]{64})\b`,
			},
		},

		// ReadMeKey (trufflehog readme)
		{
			Name:      ReadMeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(rdme_[a-z0-9]{70})`,
			},
		},

		// ReallySimpleSystemsKey (trufflehog reallysimplesystems)
		{
			Name:      ReallySimpleSystemsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(ey[a-zA-Z0-9-._]{153}.ey[a-zA-Z0-9-._]{916,1000})\b`,
			},
		},

		// RebrandlyKey (trufflehog rebrandly)
		{
			Name:      RebrandlyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:rebrandly).{0,40}?\b([a-zA-Z0-9_]{32})\b`,
			},
		},

		// RedHatPyxisKey (trufflehog redhatpyxis)
		{
			Name:      RedHatPyxisKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:redhat|pyxis).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// RefinerKey (trufflehog refiner)
		{
			Name:      RefinerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:refiner).{0,40}?\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// RentmanKey (trufflehog rentman)
		{
			Name:      RentmanKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:rentman).{0,40}?\b(ey[a-zA-Z0-9]{34}.ey[a-zA-Z0-9._-]{250,300})\b`,
			},
		},

		// RepairshoprKey (trufflehog repairshopr)
		{
			Name:      RepairshoprKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:repairshopr).{0,40}?\b([a-zA-Z0-9-]{51})\b`,
			},
		},

		// ReplyIOKey (trufflehog replyio)
		{
			Name:      ReplyIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:replyio).{0,40}?\b([0-9A-Za-z]{24})\b`,
			},
		},

		// RequestFinanceKey (trufflehog requestfinance)
		{
			Name:      RequestFinanceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:requestfinance).{0,40}?\b([0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7}-[0-9A-Z]{7})\b`,
			},
		},

		// ResendKey (trufflehog resend)
		{
			Name:      ResendKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(re_[1-9A-HJ-NP-Za-km-z]{8}_[1-9A-HJ-NP-Za-km-z]{24})\b`,
			},
		},

		// RestpackHtmlToPdfAPIKey (trufflehog restpackhtmltopdfapi)
		{
			Name:      RestpackHtmlToPdfAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:restpack).{0,40}?\b([0-9A-Za-z]{48})\b`,
			},
		},

		// RevKey (trufflehog rev)
		{
			Name:      RevKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:rev).{0,40}?\b([0-9a-zA-Z\/\+]{27}\=)(?:[ \r\n]|$)`,
			},
		},

		// RevampCRMKey (trufflehog revampcrm)
		{
			Name:      RevampCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:revamp).{0,40}?\b([a-zA-Z0-9]{40}\b)`,
			},
		},

		// RingCentralKey (trufflehog ringcentral)
		{
			Name:      RingCentralKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ringcentral).{0,40}?\b([0-9A-Za-z_-]{22})\b`,
			},
		},

		// RiteKitKey (trufflehog ritekit)
		{
			Name:      RiteKitKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ritekit).{0,40}?\b([0-9a-f]{44})\b`,
			},
		},

		// RoaringSecret (trufflehog roaring)
		{
			Name:      RoaringSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:roaring).{0,40}?\b([0-9A-Za-z_-]{28})\b`,
			},
		},

		// RootlyKey (trufflehog rootly)
		{
			Name:      RootlyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(rootly_[a-f0-9]{64})\b`,
			},
		},

		// Route4meKey (trufflehog route4me)
		{
			Name:      Route4meKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:route4me).{0,40}?\b([0-9A-Z]{32})\b`,
			},
		},

		// RowndSecret (trufflehog rownd)
		{
			Name:      RowndSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:rownd).{0,40}?\b([a-z0-9]{48})\b`,
			},
		},

		// RunRunItKey (trufflehog runrunit)
		{
			Name:      RunRunItKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:runrunit).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// SaladCloudAPIKey (trufflehog saladcloudapikey)
		{
			Name:      SaladCloudAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(salad_cloud_[0-9A-Za-z]{1,7}_[0-9A-Za-z]{7,235})\b`,
			},
		},

		// SalescookieKey (trufflehog salescookie)
		{
			Name:      SalescookieKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:salescookie).{0,40}?\b([a-zA-z0-9]{32})\b`,
			},
		},

		// SalesflareKey (trufflehog salesflare)
		{
			Name:      SalesflareKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:salesflare).{0,40}?\b([a-zA-Z0-9_]{45})\b`,
			},
		},

		// SalesmateKey (trufflehog salesmate)
		{
			Name:      SalesmateKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:salesmate).{0,40}?\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// SatismeterProjectkey (trufflehog satismeterprojectkey)
		{
			Name:      SatismeterProjectkeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:satismeter).{0,40}?\b([A-Za-z0-9]{32})\b`,
			},
		},

		// ScalrKey (trufflehog scalr)
		{
			Name:      ScalrKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scalr).{0,40}?\b([0-9a-zA-Z._]{136})`,
			},
		},

		// ScrapeowlKey (trufflehog scrapeowl)
		{
			Name:      ScrapeowlKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scrapeowl).{0,40}?\b([0-9a-z]{30})\b`,
			},
		},

		// ScraperAPIKey (trufflehog scraperapi)
		{
			Name:      ScraperAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scraperapi).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ScraperBoxKey (trufflehog scraperbox)
		{
			Name:      ScraperBoxKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scraperbox).{0,40}?\b([A-Z0-9]{32})\b`,
			},
		},

		// ScrapeStackKey (trufflehog scrapestack)
		{
			Name:      ScrapeStackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scrapestack).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ScrapflyKey (trufflehog scrapfly)
		{
			Name:      ScrapflyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scrapfly).{0,40}?\b([a-z0-9]{32}|scp-(?:live|test)-[a-z0-9]{32})\b`,
			},
		},

		// ScrapingAntKey (trufflehog scrapingant)
		{
			Name:      ScrapingAntKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scrapingant).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ScrapingBeeKey (trufflehog scrapingbee)
		{
			Name:      ScrapingBeeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:scraping[ _-]?bee).{0,40}?\b([A-Z0-9]{80})\b`,
			},
		},

		// ScreenshotAPIKey (trufflehog screenshotapi)
		{
			Name:      ScreenshotAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:screenshotapi).{0,40}?\b([0-9A-Z]{7}\-[0-9A-Z]{7}\-[0-9A-Z]{7}\-[0-9A-Z]{7})\b`,
			},
		},

		// ScreenshotLayerKey (trufflehog screenshotlayer)
		{
			Name:      ScreenshotLayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:screenshotlayer).{0,40}?\b([a-zA-Z0-9_]{32})\b`,
			},
		},

		// SelectPDFKey (trufflehog selectpdf)
		{
			Name:      SelectPDFKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:selectpdf).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// SemaphoreKey (trufflehog semaphore)
		{
			Name:      SemaphoreKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:semaphore).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// SerphouseKey (trufflehog serphouse)
		{
			Name:      SerphouseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:serphouse).{0,40}?\b([0-9A-Za-z]{60})\b`,
			},
		},

		// SerpStackKey (trufflehog serpstack)
		{
			Name:      SerpStackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:serpstack).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// ServalSecret (trufflehog serval)
		{
			Name:      ServalSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(svl_secret_(?:pk|wk|mk)_(?:[0-9A-Za-z]{43})(?:[0-9A-Za-z]{6}))\b`,
			},
		},

		// SheetyKey (trufflehog sheety)
		{
			Name:      SheetyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sheety).{0,40}?\b([0-9a-z]{64})\b`,
			},
		},

		// SherpadeskKey (trufflehog sherpadesk)
		{
			Name:      SherpadeskKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sherpadesk).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// ShipdayKey (trufflehog shipday)
		{
			Name:      ShipdayKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:shipday).{0,40}?\b([a-zA-Z0-9.]{11}[a-zA-Z0-9]{20})\b`,
			},
		},

		// ShippoToken (trufflehog shippo)
		{
			Name:      ShippoTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(shippo_(?:live|test)_[a-f0-9]{40})\b`,
			},
		},

		// ShortcutKey (trufflehog shortcut)
		{
			Name:      ShortcutKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:shortcut).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// ShotstackKey (trufflehog shotstack)
		{
			Name:      ShotstackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:shotstack).{0,40}?\b([a-zA-Z0-9]{40})\b`,
			},
		},

		// ShutterstockSecret (trufflehog shutterstock)
		{
			Name:      ShutterstockSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:shutterstock).{0,40}?\b([0-9a-zA-Z]{16})\b`,
			},
		},

		// ShutterstockOAuthKey (trufflehog shutterstockoauth)
		{
			Name:      ShutterstockOAuthKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:shutterstock).{0,40}?\b(v2/[0-9A-Za-z]{388})\b`,
			},
		},

		// SignaturitKey (trufflehog signaturit)
		{
			Name:      SignaturitKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:signaturit).{0,40}?\b([0-9A-Za-z]{86})\b`,
			},
		},

		// SignupgeniusKey (trufflehog signupgenius)
		{
			Name:      SignupgeniusKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:signupgenius).{0,40}?\b([0-9A-Za-z]{32})\b`,
			},
		},

		// SigoptKey (trufflehog sigopt)
		{
			Name:      SigoptKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sigopt).{0,40}?\b([A-Z0-9]{48})\b`,
			},
		},

		// SimFinKey (trufflehog simfin)
		{
			Name:      SimFinKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:simfin).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// SimplesatKey (trufflehog simplesat)
		{
			Name:      SimplesatKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:simplesat).{0,40}?\b([a-z0-9]{40})`,
			},
		},

		// SimplyNotedKey (trufflehog simplynoted)
		{
			Name:      SimplyNotedKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:simplynoted).{0,40}?\b([a-zA-Z0-9\S]{340,360})\b`,
			},
		},

		// SimvolyKey (trufflehog simvoly)
		{
			Name:      SimvolyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:simvoly).{0,40}?\b([a-z0-9]{33})\b`,
			},
		},

		// SinchMessageKey (trufflehog sinchmessage)
		{
			Name:      SinchMessageKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sinch).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// SirvKey (trufflehog sirv)
		{
			Name:      SirvKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sirv).{0,40}?\b([a-zA-Z0-9\S]{88})`,
			},
		},

		// SiteleafKey (trufflehog siteleaf)
		{
			Name:      SiteleafKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:siteleaf).{0,40}?\b([0-9Aa-z]{32})\b`,
			},
		},

		// SkrappioKey (trufflehog skrappio)
		{
			Name:      SkrappioKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:skrapp).{0,40}?\b([a-z0-9A-Z]{42})\b`,
			},
		},

		// SkyBiometrySecret (trufflehog skybiometry)
		{
			Name:      SkyBiometrySecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:skybiometry).{0,40}?\b([0-9a-z]{25,26})\b`,
			},
		},

		// SmartyStreetsKey (trufflehog smartystreets)
		{
			Name:      SmartyStreetsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:smartystreets).{0,40}?\b([a-zA-Z0-9]{20})\b`,
			},
		},

		// SmoochSecret (trufflehog smooch)
		{
			Name:      SmoochSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:smooch).{0,40}?\b([0-9a-zA-Z_-]{86})\b`,
			},
		},

		// SolarWindsObservabilityKey (trufflehog solarwindsobservability)
		{
			Name:      SolarWindsObservabilityKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:solarwinds).{0,40}?\b([0-9a-zA-Z_-]{71})\b`,
			},
		},

		// SonarCloudTokenV2 (trufflehog sonarcloud/v2)
		{
			Name:      SonarCloudTokenV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sqco_[[:alnum:]]{59})\b`,
			},
		},

		// SonarQubeTokenV2 (trufflehog sonarqube)
		{
			Name:      SonarQubeTokenV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(sq[apu]_[0-9a-f]{40})\b`,
			},
		},

		// SpectralOpsToken (trufflehog spectralops)
		{
			Name:      SpectralOpsTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(spu-[a-z0-9]{32})\b`,
			},
		},

		// SpeechTextAIKey (trufflehog speechtextai)
		{
			Name:      SpeechTextAIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:speechtext).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// SpoonacularKey (trufflehog spoonacular)
		{
			Name:      SpoonacularKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:spoonacular).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// SportsmonkKey (trufflehog sportsmonk)
		{
			Name:      SportsmonkKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sportsmonk).{0,40}?\b([0-9a-zA-Z]{60})\b`,
			},
		},

		// SpotifyKey (trufflehog spotifykey)
		{
			Name:      SpotifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:spotify).{0,40}?\b([A-Za-z0-9]{32})\b`,
			},
		},

		// SquarespaceKey (trufflehog squarespace)
		{
			Name:      SquarespaceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:squarespace).{0,40}?\b([0-9Aa-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// SslMateKey (trufflehog sslmate)
		{
			Name:      SslMateKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sslmate).{0,40}?\b([a-zA-Z0-9]{36})\b`,
			},
		},

		// StatuscakeKey (trufflehog statuscake)
		{
			Name:      StatuscakeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:statuscake).{0,40}?\b([a-zA-Z0-9]{20})\b`,
			},
		},

		// StatuspalKey (trufflehog statuspal)
		{
			Name:      StatuspalKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:statuspal).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// StockdataKey (trufflehog stockdata)
		{
			Name:      StockdataKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:stockdata).{0,40}?\b([0-9A-Za-z]{40})\b`,
			},
		},

		// StorecoveKey (trufflehog storecove)
		{
			Name:      StorecoveKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:storecove).{0,40}?\b([a-zA-Z0-9_-]{43})\b`,
			},
		},

		// StormboardKey (trufflehog stormboard)
		{
			Name:      StormboardKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:stormboard).{0,40}?\b([a-f0-9]{40})\b`,
			},
		},

		// StormglassKey (trufflehog stormglass)
		{
			Name:      StormglassKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:stormglass).{0,40}?\b([0-9Aa-z-]{73})\b`,
			},
		},

		// StorychiefKey (trufflehog storychief)
		{
			Name:      StorychiefKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:storychief).{0,40}?\b([a-zA-Z0-9_\-.]{940,1000})`,
			},
		},

		// StravaSecret (trufflehog strava)
		{
			Name:      StravaSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:strava).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// StreakKey (trufflehog streak)
		{
			Name:      StreakKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:streak).{0,40}?\b([0-9Aa-f]{32})\b`,
			},
		},

		// StripoKey (trufflehog stripo)
		{
			Name:      StripoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:stripo).{0,40}?\b(eyJhbGciOiJIUzI1NiJ9\.[0-9A-Za-z]{130}\.[0-9A-Za-z_-]{43})\b`,
			},
		},

		// SugesterKey (trufflehog sugester)
		{
			Name:      SugesterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:sugester).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// SuperNotesAPIKey (trufflehog supernotesapi)
		{
			Name:      SuperNotesAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:supernotes).{0,40}?([0-9A-Za-z\-_]{43})(?:[ \r\n]|$)`,
			},
		},

		// SurveyAnyplaceKey (trufflehog surveyanyplace)
		{
			Name:      SurveyAnyplaceKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:survey).{0,40}?\b([a-z0-9A-Z]{32})\b`,
			},
		},

		// SurveyBotKey (trufflehog surveybot)
		{
			Name:      SurveyBotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:surveybot).{0,40}?\b([A-Za-z0-9-]{80})\b`,
			},
		},

		// SurveySparrowKey (trufflehog surveysparrow)
		{
			Name:      SurveySparrowKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:surveysparrow).{0,40}?\b([a-zA-Z0-9-_]{88})\b`,
			},
		},

		// SurvicateKey (trufflehog survicate)
		{
			Name:      SurvicateKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:survicate).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// SwiftypeKey (trufflehog swiftype)
		{
			Name:      SwiftypeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:swiftype).{0,40}?\b([a-zA-z-0-9]{6}\_[a-zA-z-0-9]{6}\-[a-zA-z-0-9]{6})\b`,
			},
		},

		// TableauPersonalAccessToken (trufflehog tableau)
		{
			Name:      TableauPersonalAccessTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tableau|online\.tableau\.com).{0,40}?\b([A-Za-z0-9+/]{22}==:[A-Za-z0-9]{32})\b`,
			},
		},

		// TailscaleKey (trufflehog tailscale)
		{
			Name:      TailscaleKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\btskey-[a-z]+-[0-9A-Za-z_]+-[0-9A-Za-z_]+\b`,
			},
		},

		// TallyfyKey (trufflehog tallyfy)
		{
			Name:      TallyfyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tallyfy).{0,40}?\b([0-9A-Za-z]{36}\.[0-9A-Za-z]{264}\.[0-9A-Za-z\-\_]{683})\b`,
			},
		},

		// TatumIOKey (trufflehog tatumio)
		{
			Name:      TatumIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tatum).{0,40}?\b([0-9a-z-]{36})\b`,
			},
		},

		// TaxjarKey (trufflehog taxjar)
		{
			Name:      TaxjarKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:taxjar).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// TeamgateToken (trufflehog teamgate)
		{
			Name:      TeamgateTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:teamgate).{0,40}?\b([a-z0-9]{40})\b`,
			},
		},

		// TeamworkCRMKey (trufflehog teamworkcrm)
		{
			Name:      TeamworkCRMKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:teamwork).{0,40}?\b(tkn\.v1_[0-9A-Za-z]{71}=)(?:[ \r\n]|$)`,
			},
		},

		// TechnicalAnalysisAPIKey (trufflehog technicalanalysisapi)
		{
			Name:      TechnicalAnalysisAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:technicalanalysisapi).{0,40}?\b([A-Z0-9]{48})\b`,
			},
		},

		// TefterKey (trufflehog tefter)
		{
			Name:      TefterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tefter).{0,40}?\b([0-9a-zA-Z]{20})\b`,
			},
		},

		// TeletypeKey (trufflehog teletype)
		{
			Name:      TeletypeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:teletype).{0,40}?\b([0-9a-zA-Z-]{64})\b`,
			},
		},

		// TestingBotKey (trufflehog testingbot)
		{
			Name:      TestingBotKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:testingbot).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// TheOddsAPIKey (trufflehog theoddsapi)
		{
			Name:      TheOddsAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:theoddsapi|the-odds-api).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// ThinkificKey (trufflehog thinkific)
		{
			Name:      ThinkificKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:thinkific).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// ThousandEyesKey (trufflehog thousandeyes)
		{
			Name:      ThousandEyesKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:thousandeyes).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// TicketMasterKey (trufflehog ticketmaster)
		{
			Name:      TicketMasterKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:ticketmaster).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// TickettailorKey (trufflehog tickettailor)
		{
			Name:      TickettailorKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tickettailor).{0,40}?\b(sk_[0-9]{4}_[0-9]{6}_[a-f0-9]{32})`,
			},
		},

		// TiingoKey (trufflehog tiingo)
		{
			Name:      TiingoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tiingo).{0,40}?\b([0-9a-z]{40})\b`,
			},
		},

		// TimeCampKey (trufflehog timecamp)
		{
			Name:      TimeCampKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:timecamp).{0,40}?\b([0-9a-z]{26})\b`,
			},
		},

		// TimezoneapiKey (trufflehog timezoneapi)
		{
			Name:      TimezoneapiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:timezoneapi).{0,40}?\b([a-zA-Z]{20})\b`,
			},
		},

		// TLyKey (trufflehog tly)
		{
			Name:      TLyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tly).{0,40}?\b([0-9A-Za-z]{60})\b`,
			},
		},

		// TmetricKey (trufflehog tmetric)
		{
			Name:      TmetricKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tmetric).{0,40}?\b([0-9A-Z]{64})\b`,
			},
		},

		// TogglTrackKey (trufflehog toggltrack)
		{
			Name:      TogglTrackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:toggl).{0,40}?\b([0-9Aa-z]{32})\b`,
			},
		},

		// TokeetKey (trufflehog tokeet)
		{
			Name:      TokeetKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tokeet).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// TomorrowIOKey (trufflehog tomorrowio)
		{
			Name:      TomorrowIOKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tomorrow).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// TradierKey (trufflehog tradier)
		{
			Name:      TradierKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tradier).{0,40}?\b([a-zA-Z0-9]{28})\b`,
			},
		},

		// TravelPayoutsKey (trufflehog travelpayouts)
		{
			Name:      TravelPayoutsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:travelpayouts).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// TrufflehogEnterpriseSecret (trufflehog trufflehogenterprise)
		{
			Name:      TrufflehogEnterpriseSecretRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\bthog-secret-[0-9a-f]{32}\b`,
			},
		},

		// TwistToken (trufflehog twist)
		{
			Name:      TwistTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:twist).{0,40}?\b(?:oauth2:)?([0-9a-f]{40})\b`,
			},
		},

		// TyntecKey (trufflehog tyntec)
		{
			Name:      TyntecKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:tyntec).{0,40}?\b([a-zA-Z0-9]{32})\b`,
			},
		},

		// TypetalkKey (trufflehog typetalk)
		{
			Name:      TypetalkKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:typetalk).{0,40}?\b([0-9a-zA-Z]{64})\b`,
			},
		},

		// UbidotsKey (trufflehog ubidots)
		{
			Name:      UbidotsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(BBFF-[0-9a-zA-Z]{30})\b`,
			},
		},

		// UclassifyKey (trufflehog uclassify)
		{
			Name:      UclassifyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:uclassify).{0,40}?\b([a-z0-9A-Z]{12})\b`,
			},
		},

		// UnifyIDKey (trufflehog unifyid)
		{
			Name:      UnifyIDKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:unify).{0,40}?\b([0-9A-Za-z_=-]{44})`,
			},
		},

		// UnpluggKey (trufflehog unplugg)
		{
			Name:      UnpluggKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:unplu).{0,40}?\b([a-z0-9]{64})\b`,
			},
		},

		// UnsplashKey (trufflehog unsplash)
		{
			Name:      UnsplashKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:unsplash).{0,40}?\b([0-9A-Za-z_]{43})\b`,
			},
		},

		// UPCDatabaseKey (trufflehog upcdatabase)
		{
			Name:      UPCDatabaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:upcdatabase).{0,40}?\b([A-Z0-9]{32})\b`,
			},
		},

		// UpleadKey (trufflehog uplead)
		{
			Name:      UpleadKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:uplead).{0,40}?\b([a-z0-9-]{32})\b`,
			},
		},

		// UploadCareKey (trufflehog uploadcare)
		{
			Name:      UploadCareKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:uploadcare).{0,40}?\b([a-z0-9]{20})\b`,
			},
		},

		// UpwaveKey (trufflehog upwave)
		{
			Name:      UpwaveKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:upwave).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// UserKey (trufflehog user)
		{
			Name:      UserKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:user\.com).{0,40}?\b([A-Za-z0-9]{64})\b`,
			},
		},

		// UserflowKey (trufflehog userflow)
		{
			Name:      UserflowKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:userflow).{0,40}?\b([0-9a-z_]{29})\b`,
			},
		},

		// UserStackKey (trufflehog userstack)
		{
			Name:      UserStackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:userstack).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// VagrantCloudPersonalToken (trufflehog vagrantcloudpersonaltoken)
		{
			Name:      VagrantCloudPersonalTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:vagrant).{0,40}?\b([A-Za-z0-9]{14}.atlasv1.[A-Za-z0-9]{67})\b`,
			},
		},

		// VatLayerKey (trufflehog vatlayer)
		{
			Name:      VatLayerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:vatlayer).{0,40}?\b([a-z0-9]{32})\b`,
			},
		},

		// VboutKey (trufflehog vbout)
		{
			Name:      VboutKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:vbout).{0,40}?\b([0-9]{25})\b`,
			},
		},

		// VerifierKey (trufflehog verifier)
		{
			Name:      VerifierKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:verifier).{0,40}?\b([a-z0-9]{96})\b`,
			},
		},

		// VerimailKey (trufflehog verimail)
		{
			Name:      VerimailKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:verimail).{0,40}?\b([A-Z0-9]{32})\b`,
			},
		},

		// VeriphoneKey (trufflehog veriphone)
		{
			Name:      VeriphoneKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:veriphone).{0,40}?\b([0-9A-Z]{32})\b`,
			},
		},

		// VersionEyeKey (trufflehog versioneye)
		{
			Name:      VersionEyeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:versioneye).{0,40}?\b([a-zA-Z0-9-]{40})\b`,
			},
		},

		// ViewneoKey (trufflehog viewneo)
		{
			Name:      ViewneoKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:viewneo).{0,40}?\b([a-z0-9A-Z]{120,300}.[a-z0-9A-Z]{150,300}.[a-z0-9A-Z-_]{600,800})`,
			},
		},

		// VisualCrossingKey (trufflehog visualcrossing)
		{
			Name:      VisualCrossingKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:visualcrossing).{0,40}?\b([0-9A-Z]{25})\b`,
			},
		},

		// VoiceflowKey (trufflehog voiceflow)
		{
			Name:      VoiceflowKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(VF\.(?:(?:DM|WS)\.)?[a-fA-F0-9]{24}\.[a-zA-Z0-9]{16})\b`,
			},
		},

		// VoicegainKey (trufflehog voicegain)
		{
			Name:      VoicegainKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:voicegain).{0,40}?\b(ey[0-9a-zA-Z_-]{34}.ey[0-9a-zA-Z_-]{108}.[0-9a-zA-Z_-]{43})\b`,
			},
		},

		// VoodooSMSKey (trufflehog voodoosms)
		{
			Name:      VoodooSMSKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:voodoosms).{0,40}?\b([0-9a-zA-Z]{46})\b`,
			},
		},

		// VoucheryKey (trufflehog vouchery)
		{
			Name:      VoucheryKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:vouchery).{0,40}?\b([a-z0-9-]{36})\b`,
			},
		},

		// VpnapiKey (trufflehog vpnapi)
		{
			Name:      VpnapiKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:vpnapi).{0,40}?\b([a-z0-9A-Z]{32})\b`,
			},
		},

		// VyteKey (trufflehog vyte)
		{
			Name:      VyteKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:vyte).{0,40}?\b([0-9a-z]{50})\b`,
			},
		},

		// WalkScoreKey (trufflehog walkscore)
		{
			Name:      WalkScoreKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:walkscore).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// WeatherBitKey (trufflehog weatherbit)
		{
			Name:      WeatherBitKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:weatherbit).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// WeatherStackKey (trufflehog weatherstack)
		{
			Name:      WeatherStackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:weatherstack).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// WebScraperKey (trufflehog webscraper)
		{
			Name:      WebScraperKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:webscraper).{0,40}?\b([a-zA-Z0-9]{60})\b`,
			},
		},

		// WebscrapingKey (trufflehog webscraping)
		{
			Name:      WebscrapingKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:webscraping).{0,40}?\b([0-9A-Za-z]{32})\b`,
			},
		},

		// WebsitepulseKey (trufflehog websitepulse)
		{
			Name:      WebsitepulseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:websitepulse).{0,40}?\b([0-9a-f]{32})\b`,
			},
		},

		// WeightsAndBiasesKeyV2 (trufflehog weightsandbiases/v2)
		{
			Name:      WeightsAndBiasesKeyV2Regex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(wandb_v1_[A-Za-z0-9]{27}_[A-Za-z0-9]{49})\b`,
			},
		},

		// WePayKey (trufflehog wepay)
		{
			Name:      WePayKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:wepay).{0,40}?\b([a-zA-Z0-9_?]{62})\b`,
			},
		},

		// WhoxyKey (trufflehog whoxy)
		{
			Name:      WhoxyKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:whoxy).{0,40}?\b([0-9a-z]{33})\b`,
			},
		},

		// WitKey (trufflehog wit)
		{
			Name:      WitKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:wit\.ai|wit[_-]).{0,40}?\b([A-Z0-9]{32})\b`,
			},
		},

		// WorksnapsKey (trufflehog worksnaps)
		{
			Name:      WorksnapsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:worksnaps).{0,40}?\b([0-9A-Za-z]{40})\b`,
			},
		},

		// WorkstackKey (trufflehog workstack)
		{
			Name:      WorkstackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:workstack).{0,40}?\b([0-9Aa-zA-Z]{60})\b`,
			},
		},

		// WorldCoinIndexKey (trufflehog worldcoinindex)
		{
			Name:      WorldCoinIndexKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:worldcoinindex).{0,40}?\b([a-zA-Z0-9]{35})\b`,
			},
		},

		// WorldWeatherKey (trufflehog worldweather)
		{
			Name:      WorldWeatherKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:worldweather).{0,40}?\b([0-9a-z]{31})\b`,
			},
		},

		// WrikeKey (trufflehog wrike)
		{
			Name:      WrikeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:wrike).{0,40}?\b(ey[a-zA-Z0-9-._]{333})\b`,
			},
		},

		// YandexKey (trufflehog yandex)
		{
			Name:      YandexKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:yandex).{0,40}?\b([a-z0-9A-Z.]{83})\b`,
			},
		},

		// YelpKey (trufflehog yelp)
		{
			Name:      YelpKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:yelp).{0,40}?\b([a-zA-Z0-9_\\=\.\-]{128})\b`,
			},
		},

		// YouNeedABudgetKey (trufflehog youneedabudget)
		{
			Name:      YouNeedABudgetKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:youneedabudget).{0,40}?\b([0-9a-f]{64})\b`,
			},
		},

		// YouSignKey (trufflehog yousign)
		{
			Name:      YouSignKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:yousign).{0,40}?\b([0-9a-z]{32})\b`,
			},
		},

		// YoutubeAPIKey (trufflehog youtubeapikey)
		{
			Name:      YoutubeAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:youtube).{0,40}?\b([a-zA-Z-0-9_]{39})\b`,
			},
		},

		// ZendeskAPIToken (trufflehog zendeskapi)
		{
			Name:      ZendeskAPITokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zendesk).{0,40}?([A-Za-z0-9_-]{40})`,
			},
		},

		// ZenkitAPIKey (trufflehog zenkitapi)
		{
			Name:      ZenkitAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zenkit).{0,40}?\b([0-9a-z]{8}\-[0-9A-Za-z]{32})\b`,
			},
		},

		// ZenRowsKey (trufflehog zenrows)
		{
			Name:      ZenRowsKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zenrows).{0,40}?\b([0-9a-f]{40})\b`,
			},
		},

		// ZenscrapeKey (trufflehog zenscrape)
		{
			Name:      ZenscrapeKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zenscrape).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// ZenserpKey (trufflehog zenserp)
		{
			Name:      ZenserpKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zenserp).{0,40}?\b([0-9a-z-]{36})\b`,
			},
		},

		// ZeplinKey (trufflehog zeplin)
		{
			Name:      ZeplinKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zeplin).{0,40}?\b([a-zA-Z0-9-.]{350,400})\b`,
			},
		},

		// ZeroTierKey (trufflehog zerotier)
		{
			Name:      ZeroTierKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zerotier).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// ZipCodeAPIKey (trufflehog zipcodeapi)
		{
			Name:      ZipCodeAPIKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zipcodeapi).{0,40}?\b([a-zA-Z0-9]{64})\b`,
			},
		},

		// ZipcodebaseKey (trufflehog zipcodebase)
		{
			Name:      ZipcodebaseKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zipcodebase).{0,40}?\b([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})\b`,
			},
		},

		// ZonkaFeedbackKey (trufflehog zonkafeedback)
		{
			Name:      ZonkaFeedbackKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zonka).{0,40}?\b([A-Za-z0-9]{36})\b`,
			},
		},

		// ZulipChatKey (trufflehog zulipchat)
		{
			Name:      ZulipChatKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:zulip).{0,40}?\b([0-9a-zA-Z]{32})\b`,
			},
		},

		// AWS access key IDs with prefixes not covered by AWSAccessKeyIDRegex (trufflehog aws/access_keys, shhgit)
		{
			Name:      AWSExtendedAccessKeyIDRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b((?:A3T[A-Z0-9]|ABIA|ACCA|AGPA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b`,
			},
		},

		// AWS credentials file entries (shhgit "AWS cred file info")
		{
			Name:      AWSCredFileInfoRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:aws_access_key_id|aws_secret_access_key).{0,20}?=.([0-9a-zA-Z/+]{20,40})`,
			},
		},

		// Stripe restricted API key (trufflehog stripe)
		{
			Name:      StripeRestrictedKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(rk_(?:test|live)_[a-zA-Z0-9]{20,247})\b`,
			},
		},

		// Salesforce OAuth refresh token (trufflehog salesforcerefreshtoken)
		{
			Name:      SalesforceRefreshTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)\b(5AEP861[a-zA-Z0-9._=]{80,})\b`,
			},
		},

		// Salesforce connected app consumer key (trufflehog salesforceoauth2)
		{
			Name:      SalesforceConsumerKeyRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\b(3MVG9[0-9a-zA-Z._+/=]{80,251})`,
			},
		},

		// Signable API token (trufflehog signable)
		{
			Name:      SignableTokenRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i:signable).{0,40}?\b([a-zA-Z-0-9]{32})\b`,
			},
		},

		// SQL Server connection string with password (trufflehog sqlserver)
		{
			Name:      SQLServerConnStringRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `(?i)(?:Server|Data Source|Network Address|Addr|Address)\s*=\s*[^;]+;.*?(?:Password|Pwd)\s*=\s*([^;'"\s]+)`,
			},
		},

		// LDAP bind credentials in an ADSI OpenDSObject call (trufflehog ldap)
		{
			Name:      LDAPOpenDSObjectRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `OpenDSObject\(\"(?i:ldaps?://[\S]+)\", ?\"[\S]+\", ?\"([\S]+)\",[ \d]+\)`,
			},
		},

		// GCP application default credentials JSON (trufflehog gcpapplicationdefaultcredentials)
		{
			Name:      GCPApplicationDefaultCredentialsRegex.String(),
			Processor: search.Regex.String(),
			RegexProcessorConfig: config.RegexProcessorConfig{
				RegexString: `\{[^{}]*"client_secret"[^{}]*"refresh_token"[^{}]*\}|\{[^{}]*"refresh_token"[^{}]*"client_secret"[^{}]*\}`,
			},
		},
	}
}
