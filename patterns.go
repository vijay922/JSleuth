// patterns.go
package main

var RegexPatterns = map[string]string{
	// --- API Keys / Cloud ---
	"Google API Key":                   `AIza[0-9A-Za-z\-_]{35}`,
	"Google OAuth Access Token":        `ya29\.[0-9A-Za-z\-_]+`,
	"Firebase API Key":                 `AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}`,
	"AWS Access Key ID":                `A[SK]IA[0-9A-Z]{16}`,
	"AWS Secret Access Key (env/var)":  `(?i)(?:aws[_\- ]?secret[_\- ]?access[_\- ]?key|aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[:=]\s*['"]?([A-Za-z0-9+/]{40})['"]?`,
	"DigitalOcean Token":               `dop_v1_[a-f0-9]{64}`,
	"Heroku API Key":                   `heroku_[0-9a-fA-F]{32}`,
	"GitHub Token":                     `ghp_[A-Za-z0-9]{36,}`,
	"GitLab Token":                     `glpat-[0-9a-zA-Z\-_]{20,}`,
	"Slack Webhook":                    `https://hooks\.slack\.com/services/[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+`,
	"Slack Token":                      `xox[baprs]-[0-9a-zA-Z]{10,48}`,
	"Stripe Live Key":                  `sk_live_[0-9a-zA-Z]{24}`,
	"SendGrid API Key":                 `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`,
	"Mailgun API Key":                  `key-[0-9a-zA-Z]{32}`,
	"Facebook Access Token":            `EAACEdEose0cBA[0-9A-Za-z]+`,
	"Discord Token":                    `[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}`,
	"X API Key":                        `"X-API-KEY":"([0-9a-fA-F-]+)"`,
	"AccessKey":                        `accesskey:\s*"[^"]*`,
	"SecretKey":                        `secretkey:\s*"[^"]*`,

	// --- Auth / JWT / Session ---
	"JWT Token":         `eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+`,
	"Bearer Token":      `(?i)bearer\s+[A-Za-z0-9_\-\.=:_\+\/]+`,
	"Basic Auth Header": `(?i)basic\s+[A-Za-z0-9=:_\+\/-]{5,100}`,
	"Session ID":        `(sessionid|_session|sessid|connect\.sid|sid|JSESSIONID|PHPSESSID)=[A-Za-z0-9\-_]{10,}`,

	// --- Database URIs ---
	"MongoDB URI":    `mongodb(?:\+srv)?:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?\/[A-Za-z0-9._%+\-]+`,
	"PostgreSQL URI": `postgres(?:ql)?:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?\/[A-Za-z0-9._%+\-]+`,
	"MySQL URI":      `mysql:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?\/[A-Za-z0-9._%+\-]+`,
	"Redis URI":      `redis:\/\/(?:[A-Za-z0-9._%+\-]+:[^@]+@)?[A-Za-z0-9\.\-]+(?::\d+)?`,
	"db_username": `(?i)(?:database|db)_?(?:user|username)[\s]*[=:>]\s*['"]*([a-zA-Z0-9_\-\.]+)['"]*`,
	"db_password": `(?i)(?:database|db)_?(?:pass|password|pwd)[\s]*[=:>]\s*['"]*([^'"\s]{6,})['"]*`,
	"db_host": `(?i)(?:database|db)_?host[\s]*[=:>]\s*['"]*([a-zA-Z0-9\.\-]+)['"]*`,
	"mssql_connection": `(?i)(?:mssql|sqlserver)://[^:\s]+:[^@\s]+@[^/\s]+`,

	// --- Private Keys ---
	"RSA PRIVATE KEY":     `-----BEGIN RSA PRIVATE KEY-----[\s\S]+?-----END RSA PRIVATE KEY-----`,
	"OPENSSH PRIVATE KEY": `-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]+?-----END OPENSSH PRIVATE KEY-----`,
	"PGP PRIVATE KEY BLOCK": `-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]+?-----END PGP PRIVATE KEY BLOCK-----`,

	// --- Cloud Buckets / Endpoints ---
	"S3 Bucket URL":   `[A-Za-z0-9\-_]+\.s3(?:[.-][A-Za-z0-9\-_]+)?\.amazonaws\.com|s3:\/\/[A-Za-z0-9\-_]+`,
	"Firebase DB URL": `https?:\/\/[a-z0-9\-]+\.firebaseio\.com`,

	// --- Config / Secrets / Env Vars ---
	"ENV Style Secrets": `(?i)(?:api[_\- ]?key|access[_\- ]?token|client[_\- ]?secret|secret|refresh[_\- ]?token)[=:]['"]?([A-Za-z0-9\-_\/+=\.]{8,})['"]?`,
	"Password Variable": `(?i)(?:password|passwd|pwd|passphrase)[\s]*[:=][\s]*['"]?([^\s'"]{4,})['"]?`,

	// --- Miscellaneous ---
	"Email Address": `[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,7}`,
	"UUID":          `\b[a-f0-9]{8}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{4}\-[a-f0-9]{12}\b`,
	"IPv4":          `\b(?:(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\.){3}(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\b`,

	// === Cloud Service Tokens ===
	"Stripe Publishable Key":    `pk_live_[0-9a-zA-Z]{24}`,
	"Stripe Restricted Key":     `rk_live_[0-9a-zA-Z]{24}`,
	"Shopify Access Token":      `shpat_[0-9a-fA-F]{32}`,
	"Shopify Private App Token": `shppa_[a-fA-F0-9]{32}`,
	"Dropbox Access Token":      `sl\.[A-Za-z0-9_-]{20,100}`,
	"Square Access Token":       `sq0atp-[0-9A-Za-z\-_]{22}`,
	"Square OAuth Secret":       `sq0csp-[0-9A-Za-z\-_]{43}`,

	// === OAuth & Authentication ===
	"OAuth Client Secret":  `(?i)client_secret['\"\s:=]+[a-zA-Z0-9\-_.~]{10,100}`,
	"OAuth Client ID":      `(?i)client_id['\"\s:=]+[a-zA-Z0-9\-_.~]{10,100}`,
	"OAuth Access Token":   `(?i)oauth[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_.~+/]{20,}`,
	"OAuth Refresh Token":  `(?i)refresh[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_.~+/]{20,}`,
	"Authorization Header": `(?i)authorization[\s]*:[\s]*['"\"]?(Bearer|Basic)[\s]+[A-Za-z0-9\-_\.=:_\+\/]+['"\"]?`,

	// === Additional API Keys ===
	"Algolia API Key":           `(?i)algolia[_\-]?(api[_\-]?key|application[_\-]?id)['\"\s:=]+[a-zA-Z0-9]{10,}`,
	"Amplitude API Key":         `(?i)amplitude['\"\s:=]+[a-z0-9\-]{32,64}`,
	"Cloudinary URL":            `cloudinary://[0-9]{15}:[a-zA-Z0-9]+@[a-zA-Z]+`,
	"Intercom Access Token":     `(?i)intercom(.{0,20})?token['\"\s:=]+[a-zA-Z0-9\-_]{20,}`,
	"Mixpanel Token":            `(?i)mixpanel(.{0,20})?token['\"\s:=]+[a-z0-9]{32}`,
	"New Relic License Key":     `NRII-[a-zA-Z0-9]{20,}`,
	"New Relic API Key":         `NRAK-[A-Z0-9]{27}`,
	"Plaid Secret":              `(?i)plaid(.{0,20})?secret['\"\s:=]+[a-z0-9\-_]{30,}`,
	"Rollbar Access Token":      `(?i)rollbar[_\-]?access[_\-]?token['\"\s:=]+[a-z0-9]{32}`,
	"Segment Public Key":        `(?i)segment['\"\s:=]+[a-zA-Z0-9]{20,}`,
	"Sentry DSN":                `https://[a-zA-Z0-9]+@[a-z]+\.ingest\.sentry\.io/\d+`,
	"Snyk API Token":            `snyk_token[\s]*=[\s]*[a-f0-9\-]{36}`,

	// === Cloud Provider Tokens ===
	"Azure Client Secret":       `(?i)azure(.{0,20})?client.?secret(.{0,20})?['"\"][a-zA-Z0-9._%+\-]{32,}['"\"]`,
	"Azure SAS Token":           `\?sv=\d{4}-\d{2}-\d{2}&s[st]=[\w\-]+&s[ep]=[\d\-T:]+Z&sr=[bqtc]&sp=[rwdlacu]+&sig=[\w%]+`,
	"GCP Service Account":       `"type":\s*"service_account"`,
	"GCP API Key":               `(?i)gcp[_\-]?api[_\-]?key['\"\s:=]+[A-Za-z0-9\-_]{39}`,
	"Azure Storage Account Key": `(?i)azure[_\-]?storage[_\-]?key['\"\s:=]+[A-Za-z0-9+/=]{88}`,

	// === Database Connection Strings ===
	"Supabase URL":                     `https://[a-z0-9]{20}\.supabase\.co`,
	"Elasticsearch Connection String":  `elasticsearch://[^\s'"]+`,
	"CouchDB Connection String":        `couchdb://[^\s'"]+`,
	"JDBC Connection String":           `jdbc:\w+://[^\s'"]+`,

	// === Payment & E-commerce ===
	"Braintree Access Token": `access_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}`,
	"Razorpay Key ID":        `rzp_(?:live|test)_[A-Za-z0-9]{14}`,

	// === Communication & Social Media ===
	"Discord Webhook":         `https://discord(?:app)?\.com/api/webhooks/[0-9]+/[a-zA-Z0-9_\-]+`,
	"Microsoft Teams Webhook": `https://[a-z]+\.webhook\.office\.com/webhookb2/[a-zA-Z0-9@\-]+/.*`,
	"Slack Incoming Webhook":  `https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}`,
	"Twitch API Key":          `(?i)twitch(.{0,20})?(?:api[_\-]?key|client[_\-]?secret)['\"\s:=]+[a-zA-Z0-9]{30}`,

	// === Gaming APIs ===
	"Steam Web API Key":  `(?i)steam(.{0,20})?(?:api[_\-]?key|key)['\"\s:=]+[a-zA-Z0-9]{32}`,
	"Riot Games API Key": `RGAPI-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,

	// === CI/CD & DevOps ===
	"CircleCI Token":                      `circle-token=[a-z0-9]{40}`,
	"Travis CI Token":                     `(?i)travis(.{0,20})?token['\"\s:=]+[a-z0-9]{22}`,
	"Jenkins Crumb":                       `Jenkins-Crumb:\s*[a-z0-9]{32,}`,
	"Bitbucket App Password":              `(?i)bitbucket(.{0,20})?(?:password|token)['\"\s:=]+[a-zA-Z0-9]{16}`,
	"GitLab Runner Token":                 `glrt-[a-zA-Z0-9_\-]{20}`,
	"GitHub Personal Access Token (FG)":   `github_pat_[0-9a-zA-Z_]{82}`,
	"GitHub OAuth App Secret":             `gho_[0-9a-zA-Z]{36}`,
	"GitHub App Installation Token":       `ghs_[0-9a-zA-Z]{36}`,

	// === Container & Cloud Native ===
	"Docker Hub Access Token":          `dckr_pat_[a-zA-Z0-9_\-]{26,}`,
	"NPM Access Token":                 `npm_[a-zA-Z0-9]{36}`,
	"PyPI Access Token":                `pypi-[A-Za-z0-9\-_]{107}`,
	"HashiCorp Vault Token":            `hvs\.[a-zA-Z0-9_\-]{90,}`,

	// === Monitoring & Analytics ===
	"Grafana API Key":      `eyJrIjoi[a-zA-Z0-9]{32,}`,
	"PagerDuty API Key":    `pd[ru]_[a-zA-Z0-9_\-]{18,}`,
	"Heap Analytics App ID": `(?i)heap['\"\s:=]+[a-z0-9]{8,12}`,
	"Keen IO Project ID":   `(?i)keen(.{0,20})?project[_\-]?id['\"\s:=]+[a-f0-9]{24}`,
	"Keen IO Write Key":    `(?i)keen(.{0,20})?write[_\-]?key['\"\s:=]+[a-zA-Z0-9]{64}`,

	// === Content Delivery ===
	"Netlify Access Token": `(?i)netlify[_\-]?(?:auth[_\-]?token|token)['\"\s:=]+[a-z0-9_\-]{43}`,
	"Vercel Token":         `(?i)vercel[_\-]?token['\"\s:=]+[a-zA-Z0-9]{24}`,

	// === Location Services ===
	"Mapbox Access Token": `(?:pk|sk|tk)\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}`,
	"Google Maps API Key": `AIza[0-9A-Za-z\-_]{35}`,

	// === CMS & Content Platforms ===
	"Contentful Management Token":  `CFPAT-[a-zA-Z0-9_\-]{40}`,
	"WordPress API Key":            `wp_[a-zA-Z0-9]{20}`,

	// === Node.js Specific ===
	"Package.json Auth Token":  `(?i)_auth[Tt]oken['\"\s:=]+[A-Za-z0-9+/=]{20,}`,

	// === Generic Patterns (JavaScript-specific) ===
	"API Key in Variable":      `(?i)(?:api[_\-]?key|apikey)['\"\s:=]+[a-zA-Z0-9\-_.]{16,}`,
	"Secret in Variable":       `(?i)(?:secret|secret[_\-]?key)['\"\s:=]+[a-zA-Z0-9\-_.]{16,}`,
	"Private Key in Variable":  `(?i)(?:private[_\-]?key|priv[_\-]?key)['\"\s:=]+[a-zA-Z0-9\-_.+/=]{40,}`,
	"Access Token Generic":     `(?i)access[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_.]{20,}`,
	"Client Secret Generic":    `(?i)client[_\-]?secret['\"\s:=]+[a-zA-Z0-9\-_.]{20,}`,

	// === Base64 & Encoding ===
	"Base64 Basic Auth":   `(?i)authorization[\s]*:[\s]*['"\"]?Basic[\s]+[A-Za-z0-9+/=]{20,}['"\"]?`,

	// === URLs with Credentials ===
	"URL with Username Password":      `[a-zA-Z]{3,10}://[^/\s:@]{3,20}:[^/\s:@]{3,20}@[^\s]{1,100}`,

	// === Private IPs & Internal URLs ===
	"Private IP Address (10.x)":  `\b10\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`,
	"Private IP Address (172.x)": `\b172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}\b`,
	"Private IP Address (192.x)": `\b192\.168\.\d{1,3}\.\d{1,3}\b`,
	"Localhost with Port":        `localhost:[0-9]{2,5}`,
	"Dev/Staging URL":            `(?i)(?:dev|staging|test|qa|preprod)\.[a-z0-9\-]+\.(?:com|net|io|org)`,
	"Internal Domain":            `https?://[a-z0-9\.\-]+\.(?:internal|local|private)\.[a-z]{2,}`,

	// === Session & Cookie Tokens ===
	"Session Token Generic": `(?i)(?:session[_\-]?id|sess|phpsessid|jsessionid)['\"\s:=]+[a-zA-Z0-9]{10,}`,
	"Cookie Value":          `(?i)(?:set-cookie|cookie)[\s]*:[\s]*[a-zA-Z0-9_\-]+=([a-zA-Z0-9_\-\.%]+)`,


	// === Encryption Keys ===
	"AES Key":        `(?i)aes[_\-]?key['\"\s:=]+[a-zA-Z0-9+/=]{32,}`,
	"Encryption Key": `(?i)encryption[_\-]?key['\"\s:=]+[a-zA-Z0-9+/=]{32,}`,
	"Master Key":     `(?i)master[_\-]?key['\"\s:=]+[a-zA-Z0-9+/=]{32,}`,

	// === Storage Keys (JavaScript specific) ===
	"LocalStorage Token":    `localStorage\.setItem\(['\"](?:token|auth|jwt)['\"],\s*['\"]([a-zA-Z0-9\-_.]+)['\"]`,
	"SessionStorage Token":  `sessionStorage\.setItem\(['\"](?:token|auth|jwt)['\"],\s*['\"]([a-zA-Z0-9\-_.]+)['\"]`,

	// === Additional Certificate & Key Formats ===
	"PEM Certificate":  `-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----`,
	"Public Key Block": `-----BEGIN PUBLIC KEY-----[\s\S]+?-----END PUBLIC KEY-----`,
	"EC Private Key":   `-----BEGIN EC PRIVATE KEY-----[\s\S]+?-----END EC PRIVATE KEY-----`,
	"DSA Private Key":  `-----BEGIN DSA PRIVATE KEY-----[\s\S]+?-----END DSA PRIVATE KEY-----`,

	// === SSH Keys ===
	"SSH Public Key":      `ssh-(?:rsa|dss|ed25519|ecdsa) [A-Za-z0-9+/=]+`,
	"SSH Key Fingerprint": `(?:SHA256|MD5):[A-Za-z0-9+/=:]{32,}`,

	// === Cloud Storage URLs ===
	"GCS Bucket URL":         `gs://[a-z0-9\-_\.]{3,63}`,
	"Azure Blob Storage URL": `https://[a-z0-9\-]+\.blob\.core\.windows\.net`,

	// === Webhook URLs ===
	"Generic Webhook URL": `https://(?:hooks?|webhooks?)\.[a-z0-9\-\.]+/[a-zA-Z0-9\-_/]+`,
	"Zapier Webhook":      `https://hooks\.zapier\.com/hooks/catch/\d+/[a-z0-9]+`,

	// === API Gateway ===
	"Kong Admin Token": `(?i)kong[_\-]?admin[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_]{32,}`,

	// === Additional Cloud Services ===
	"Cloudflare Global API Key":      `(?i)cloudflare[_\-]?api[_\-]?key['\"\s:=]+[a-z0-9]{37}`,
	"Oracle Cloud API Key":           `ocid1\.tenancy\.oc1\.[a-z0-9]{60}`,
	"IBM Cloud IAM Key":              `(?i)ibm[_\-]?cloud[_\-]?api[_\-]?key['\"\s:=]+[A-Za-z0-9_\-]{44}`,
	"microsoft_teams_webhook": `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-f0-9\-]+@[a-f0-9\-]+/IncomingWebhook/[a-f0-9]+/[a-f0-9\-]+`,
	"azure_storage_key": `(?i)(?:azure|storage)_?(?:account)?_?key[\s]*[=:>]\s*['"]*([A-Za-z0-9/+=]{88})['"]*`,
	"azure_client_secret": `(?i)azure_?client_?secret[\s]*[=:>]\s*['"]*([A-Za-z0-9\-_~\.]{34,})['"]*`,


	// === Container Registries ===
	"Docker Hub Token":               `dckr_pat_[a-zA-Z0-9_\-]{26,}`,
	"GitHub Container Registry Token": `ghcr_[a-zA-Z0-9]{36}`,
	"Google Container Registry Token": `(?i)gcr[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_=]{100,}`,
	"JFrog Artifactory Token":        `(?i)artifactory[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_=]{100,}`,
	"Quay.io Token":                  `(?i)quay[_\-]?token['\"\s:=]+[a-zA-Z0-9+/=]{100,}`,

	// === Communication Platforms (Enhanced) ===
	"Zoom JWT Token":                 `(?i)zoom[_\-]?jwt['\"\s:=]+[a-zA-Z0-9\-_\.]{200,}`,
	"Zoom OAuth Token":               `(?i)zoom[_\-]?oauth['\"\s:=]+[a-zA-Z0-9\-_]{20,}`,
	"Mattermost Access Token":        `(?i)mattermost[_\-]?token['\"\s:=]+[a-z0-9]{26}`,
	"Rocket.Chat Token":              `(?i)rocketchat[_\-]?token['\"\s:=]+[a-zA-Z0-9\-_]{43}`,

	// === Analytics & Tracking ===
	"Amplitude Secret Key":           `(?i)amplitude[_\-]?secret['\"\s:=]+[a-z0-9]{32}`,
	"Mixpanel Secret":                `(?i)mixpanel[_\-]?secret['\"\s:=]+[a-z0-9]{32}`,
	"PostHog API Key":                `phc_[a-zA-Z0-9]{43}`,
	"Hotjar Site ID":                 `hjid:\s*[0-9]{6,}`,

	// === Email Services ===
	"SendGrid API Key (v2)":          `SG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}`,
	"Mailgun Private Key":            `key-[0-9a-z]{32}`,
	"Mailgun Signing Key":            `(?i)mailgun[_\-]?signing[_\-]?key['\"\s:=]+[a-z0-9]{32}`,
	"Amazon SES SMTP Credentials":    `(?i)ses[_\-]?smtp[_\-]?password['\"\s:=]+[A-Za-z0-9+/=]{44}`,


	// === SMS & Voice Services ===
	"Twilio API Key SID":             `SK[a-f0-9]{32}`,
	"Twilio API Secret":              `(?i)twilio[_\-]?api[_\-]?secret['\"\s:=]+[A-Za-z0-9]{32}`,
	"Vonage API Key":                 `(?i)vonage[_\-]?api[_\-]?key['\"\s:=]+[a-f0-9]{8}`,
	"Vonage API Secret":              `(?i)vonage[_\-]?api[_\-]?secret['\"\s:=]+[A-Za-z0-9]{16}`,


	// === Search Services ===
	"Elasticsearch API Key":          `(?i)elastic[_\-]?api[_\-]?key['\"\s:=]+[A-Za-z0-9_\-]{20,}`,


	// === CMS & Website Builders ===
	"Sanity API Token":               `sk[a-z0-9]{41}`,

	// === E-commerce Platforms ===
	"WooCommerce Consumer Key":       `ck_[a-f0-9]{40}`,
	"WooCommerce Consumer Secret":    `cs_[a-f0-9]{40}`,

	// === File Storage & CDN ===
	"Cloudinary URL Credentials":     `cloudinary://[0-9]{15}:[a-zA-Z0-9_\-]+@[a-z]+`,
	"Imgix Secure URL Token":         `(?i)imgix[_\-]?token['\"\s:=]+[a-zA-Z0-9_\-]{43}`,

	// === Authentication Services ===
	"Clerk Secret Key":               `sk_test_[a-zA-Z0-9]{44}`,
	"Clerk Publishable Key":          `pk_test_[a-zA-Z0-9]{44}`,

	// === Project Management & Collaboration ===
	"Notion Integration Token":       `secret_[a-zA-Z0-9]{43}`,
	"ClickUp API Token":              `pk_[0-9]{7,9}_[A-Z0-9]{32}`,

	// === Developer Tools ===
	"SonarQube Token":                `(?i)sonar[_\-]?token['\"\s:=]+[a-f0-9]{40}`,
	"Sentry Auth Token":              `sntrys_[a-zA-Z0-9]{64}`,


	// === Form & Survey Services ===
	"Typeform Token":                 `tfp_[a-zA-Z0-9_\-]{43}`,


	// === Machine Learning & AI ===
	"Anthropic API Key":              `sk-ant-api03-[a-zA-Z0-9\-_]{95}`,
	"Replicate API Token":            `r8_[a-zA-Z0-9]{38}`,
	"Stability AI API Key":           `sk-[a-zA-Z0-9]{48}`,
	"Google AI Studio API Key":       `AIza[0-9A-Za-z\-_]{35}`,


	// === Financial Services ===
	"Plaid Access Token":             `access-[a-z]{8}-[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`,

	// === Miscellaneous Services ===
	"Figma Personal Access Token":    `figd_[a-zA-Z0-9\-_]{43}`,
	"Clearbit API Key":               `sk_[a-f0-9]{32}`,
	"Mapbox Secret Token":            `sk\.[a-zA-Z0-9_\-]{20,}\.[a-zA-Z0-9_\-]{20,}`,


	// === Additional Private Keys ===
	"X25519 Private Key":             `-----BEGIN X25519 PRIVATE KEY-----[\s\S]+?-----END X25519 PRIVATE KEY-----`,
	"SSH Certificate":                `-----BEGIN SSH2 ENCRYPTED PRIVATE KEY-----[\s\S]+?-----END SSH2 ENCRYPTED PRIVATE KEY-----`,

	// === Environment & Configuration Files ===
	"Kubernetes Secret":              `(?i)(?:password|token|api[_\-]?key):\s*[A-Za-z0-9+/=]{20,}`,
	"Terraform Variable":             `(?i)(?:secret|password|token)\s*=\s*['\"]([^'\"]{10,})['\"]`,

	// === Additional Generic Patterns ===
	"Generic Bearer Token Header":    `(?i)authorization:\s*bearer\s+([a-zA-Z0-9\-\._~\+\/]+=*)`,
	"Generic X-API-Key Header":       `(?i)x-api-key:\s*([a-zA-Z0-9\-_]{16,})`,
	"Generic Private Token":          `(?i)private[_\-]?token['\"\s:=]+([a-zA-Z0-9\-_\.]{20,})`,
	"Generic Access Token ID":        `(?i)access[_\-]?token[_\-]?id['\"\s:=]+([a-zA-Z0-9\-_]{20,})`,
	"Generic Webhook Secret":         `(?i)webhook[_\-]?secret['\"\s:=]+([a-zA-Z0-9\-_]{20,})`,
	"Generic Signing Secret":         `(?i)signing[_\-]?secret['\"\s:=]+([a-zA-Z0-9\-_]{20,})`,
	"Generic App Secret":             `(?i)app[_\-]?secret['\"\s:=]+([a-zA-Z0-9\-_]{20,})`,
	"atlassian_api_token": `(?i)atlassian_?api_?token[\s]*[=:>]\s*['"]*([A-Za-z0-9]{24})['"]*`,
	"auth0_client_secret": `(?i)auth0_?client_?secret[\s]*[=:>]\s*['"]*([A-Za-z0-9\-_]{32,})['"]*`,
	"okta_token": `(?i)okta_?(?:token|api_?key)[\s]*[=:>]\s*['"]*([A-Za-z0-9\-_]{42})['"]*`,
	"salesforce_token": `(?i)salesforce_?(?:token|api_?key|password)[\s]*[=:>]\s*['"]*([A-Za-z0-9]{15,})['"]*`,
}
