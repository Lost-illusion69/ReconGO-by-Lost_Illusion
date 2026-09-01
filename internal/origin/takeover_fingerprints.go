package origin

// TakeoverFingerprint describes one dangling-service signature used for
// subdomain-takeover detection. A host is only ever reported as a *confirmed*
// takeover when both signals line up: the DNS record still points at the
// third-party service (CNAMEContains or IPPrefixes) AND the live response
// carries that service's own "nothing here" fingerprint (BodyContains).
// DNS alone is not proof — the service may still be legitimately in use.
//
// This is a curated, non-exhaustive starting set of the most commonly abused
// services (same two-factor model as EdOverflow's can-i-take-over-xyz and
// nuclei's takeover templates). Hosted-service error pages change over time;
// re-verify BodyContains against the live provider before trusting a new
// entry, and prefer adding entries you have personally confirmed.
var takeoverFingerprints = []TakeoverFingerprint{
	{
		Service:       "GitHub Pages",
		CNAMEContains: []string{"github.io"},
		BodyContains:  []string{"There isn't a GitHub Pages site here"},
	},
	{
		Service:       "Heroku",
		CNAMEContains: []string{"herokudns.com", "herokuapp.com", "herokussl.com"},
		BodyContains:  []string{"No such app"},
	},
	{
		Service:       "AWS S3",
		CNAMEContains: []string{"s3.amazonaws.com", "s3-website"},
		BodyContains:  []string{"NoSuchBucket", "The specified bucket does not exist"},
	},
	{
		Service:       "Azure Web Apps",
		CNAMEContains: []string{"azurewebsites.net"},
		BodyContains:  []string{"404 Web Site not found", "Web App not found"},
	},
	{
		Service:       "Shopify",
		CNAMEContains: []string{"myshopify.com"},
		BodyContains:  []string{"Sorry, this shop is currently unavailable"},
	},
	{
		Service:       "Fastly",
		CNAMEContains: []string{"fastly.net"},
		BodyContains:  []string{"Fastly error: unknown domain"},
	},
	{
		// Wix commonly points unclaimed custom domains at a fixed IP range
		// rather than a CNAME — the classic CNAME-only checker misses this
		// entirely. IP prefix confirmed from a live flyiin.com finding.
		Service:       "Wix",
		CNAMEContains: []string{"wixdns.net"},
		IPPrefixes:    []string{"23.236.62."},
		BodyContains:  []string{"ConnectYourDomain Error", "Look Like You've Lost Your Way"},
	},
	{
		Service:       "Bitbucket",
		CNAMEContains: []string{"bitbucket.io"},
		BodyContains:  []string{"Repository not found"},
	},
	{
		Service:       "Pantheon",
		CNAMEContains: []string{"pantheonsite.io"},
		BodyContains:  []string{"The gods are wise, but do not know of the site"},
	},
	{
		Service:       "Help Scout",
		CNAMEContains: []string{"helpscoutdocs.com"},
		BodyContains:  []string{"No settings were found for this company"},
	},
	{
		Service:       "UserVoice",
		CNAMEContains: []string{"uservoice.com"},
		BodyContains:  []string{"This UserVoice subdomain is currently available"},
	},
	{
		Service:       "Tumblr",
		CNAMEContains: []string{"domains.tumblr.com"},
		BodyContains:  []string{"Whatever you were looking for doesn't currently exist"},
	},
	{
		Service:       "Webflow",
		CNAMEContains: []string{"proxy-ssl.webflow.com", "webflow.io"},
		BodyContains:  []string{"The page you are looking for doesn't exist or has been moved"},
	},
	{
		Service:       "Ghost (Pro)",
		CNAMEContains: []string{"ghost.io"},
		BodyContains:  []string{"The thing you were looking for is no longer here, or never was"},
	},
	{
		Service:       "Zendesk",
		CNAMEContains: []string{"zendesk.com"},
		BodyContains:  []string{"Help Center Closed"},
	},
	{
		Service:       "Campaign Monitor",
		CNAMEContains: []string{"createsend.com"},
		BodyContains:  []string{"Trying to access your account?"},
	},
	{
		Service:       "Unbounce",
		CNAMEContains: []string{"unbouncepages.com"},
		BodyContains:  []string{"The requested URL was not found on this server"},
	},
	{
		Service:       "Netlify",
		CNAMEContains: []string{"netlify.app"},
		BodyContains:  []string{"Not Found - Request ID"},
	},
	{
		Service:       "HubSpot",
		CNAMEContains: []string{"hs-sites.com"},
		BodyContains:  []string{"Domain not configured"},
	},
}
