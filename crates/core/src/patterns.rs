use lazy_static::lazy_static;
use regex::Regex;

use crate::types::{SecretKind, Severity};

pub struct SecretPattern {
    pub regex: Regex,
    pub prefixes: &'static [&'static str],
    pub kind: SecretKind,
    pub label: &'static str,
    pub severity: Severity,
}

lazy_static! {
    pub static ref PATTERNS: Vec<SecretPattern> = vec![
        // Match by a fixed prefix or structure baked into the key itself.

        // AWS Access Key ID
        SecretPattern {
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            prefixes: &["AKIA"],
            kind: SecretKind::AwsAccessKey,
            label: "AWS Access Key ID",
            severity: Severity::Critical,
        },
        // AWS Temporary Access Key (STS)
        SecretPattern {
            regex: Regex::new(r"ASIA[0-9A-Z]{16}").unwrap(),
            prefixes: &["ASIA"],
            kind: SecretKind::AwsTempAccessKey,
            label: "AWS Temporary Access Key (STS)",
            severity: Severity::Critical,
        },
        // GitHub Personal Access Token
        SecretPattern {
            regex: Regex::new(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}").unwrap(),
            prefixes: &["ghp_", "github_pat_"],
            kind: SecretKind::GitHubToken,
            label: "GitHub Personal Access Token",
            severity: Severity::Critical,
        },
        // GitHub OAuth Access Token
        SecretPattern {
            regex: Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            prefixes: &["gho_"],
            kind: SecretKind::GitHubOAuthToken,
            label: "GitHub OAuth Token",
            severity: Severity::Critical,
        },
        // GitHub App Tokens (user-to-server, installation, refresh)
        SecretPattern {
            regex: Regex::new(r"gh[usr]_[A-Za-z0-9]{36}").unwrap(),
            prefixes: &["ghu_", "ghs_", "ghr_"],
            kind: SecretKind::GitHubAppToken,
            label: "GitHub App Token",
            severity: Severity::Critical,
        },
        // Private Key (PEM)
        SecretPattern {
            regex: Regex::new(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            ).unwrap(),
            prefixes: &["-----BEGIN"],
            kind: SecretKind::PrivateKeyBlock,
            label: "Private Key (PEM)",
            severity: Severity::Critical,
        },
        // Password in URL
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:https?|ftp|ssh|mysql|postgresql|postgres|redis|mongodb|amqp|smtp|mariadb|cockroachdb)://[A-Za-z0-9._~-]+:([A-Za-z0-9._~!%*+-]{8,})@[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z]{2,}"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::PasswordInUrl,
            label: "Password in URL",
            severity: Severity::Critical,
        },
        // JWT Token
        SecretPattern {
            regex: Regex::new(
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ).unwrap(),
            prefixes: &["eyJ"],
            kind: SecretKind::JwtToken,
            label: "JWT Token",
            severity: Severity::High,
        },
        // Slack Token
        SecretPattern {
            regex: Regex::new(r"xox[bpors]-[0-9]{10,13}-[A-Za-z0-9\-]{10,}").unwrap(),
            prefixes: &["xox"],
            kind: SecretKind::SlackToken,
            label: "Slack Token",
            severity: Severity::Critical,
        },
        // Slack App-Level Token
        SecretPattern {
            regex: Regex::new(r"xapp-[0-9]-[A-Za-z0-9]{10,}-[0-9]{10,}-[A-Za-z0-9]{10,}").unwrap(),
            prefixes: &["xapp-"],
            kind: SecretKind::SlackAppToken,
            label: "Slack App-Level Token",
            severity: Severity::Critical,
        },
        // Google API Key
        SecretPattern {
            regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            prefixes: &["AIza"],
            kind: SecretKind::GoogleApiKey,
            label: "Google API Key",
            severity: Severity::Medium,
        },
        // Stripe Secret Key
        SecretPattern {
            regex: Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
            prefixes: &["sk_live_", "sk_test_"],
            kind: SecretKind::StripeKey,
            label: "Stripe Secret Key",
            severity: Severity::Critical,
        },
        // Stripe Publishable Key
        SecretPattern {
            regex: Regex::new(r"pk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
            prefixes: &["pk_live_", "pk_test_"],
            kind: SecretKind::StripePublishableKey,
            label: "Stripe Publishable Key",
            severity: Severity::Low,
        },
        // Stripe Restricted Key
        SecretPattern {
            regex: Regex::new(r"rk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
            prefixes: &["rk_live_", "rk_test_"],
            kind: SecretKind::StripeRestrictedKey,
            label: "Stripe Restricted Key",
            severity: Severity::High,
        },
        // Stripe Webhook Secret
        SecretPattern {
            regex: Regex::new(r"whsec_[A-Za-z0-9]{32,}").unwrap(),
            prefixes: &["whsec_"],
            kind: SecretKind::StripeWebhookSecret,
            label: "Stripe Webhook Secret",
            severity: Severity::Critical,
        },
        // Twilio API Key
        SecretPattern {
            regex: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            prefixes: &["SK"],
            kind: SecretKind::TwilioKey,
            label: "Twilio API Key",
            severity: Severity::Critical,
        },
        // SendGrid API Key
        SecretPattern {
            regex: Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap(),
            prefixes: &["SG."],
            kind: SecretKind::SendGridKey,
            label: "SendGrid API Key",
            severity: Severity::Critical,
        },
        // Discord Bot Token
        SecretPattern {
            regex: Regex::new(r"[MN][A-Za-z0-9_-]{17,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}").unwrap(),
            prefixes: &[],
            kind: SecretKind::DiscordToken,
            label: "Discord Bot Token",
            severity: Severity::Critical,
        },
        // Mailgun API Key
        SecretPattern {
            regex: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(),
            prefixes: &["key-"],
            kind: SecretKind::MailgunApiKey,
            label: "Mailgun API Key",
            severity: Severity::High,
        },
        // npm Access Token
        SecretPattern {
            regex: Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap(),
            prefixes: &["npm_"],
            kind: SecretKind::NpmToken,
            label: "npm Access Token",
            severity: Severity::Critical,
        },
        // PyPI API Token
        SecretPattern {
            regex: Regex::new(r"pypi-[A-Za-z0-9_-]{50,}").unwrap(),
            prefixes: &["pypi-"],
            kind: SecretKind::PyPiToken,
            label: "PyPI API Token",
            severity: Severity::Critical,
        },
        // Shopify Access Token
        SecretPattern {
            regex: Regex::new(r"shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}").unwrap(),
            prefixes: &["shp"],
            kind: SecretKind::ShopifyToken,
            label: "Shopify Token",
            severity: Severity::Critical,
        },
        // Square Access Token
        SecretPattern {
            regex: Regex::new(r"sq0atp-[A-Za-z0-9_-]{22}").unwrap(),
            prefixes: &["sq0atp-"],
            kind: SecretKind::SquareAccessToken,
            label: "Square Access Token",
            severity: Severity::Critical,
        },
        // Anthropic API Key
        SecretPattern {
            regex: Regex::new(r"sk-ant-api03-[A-Za-z0-9_-]{93}").unwrap(),
            prefixes: &["sk-ant-api03-"],
            kind: SecretKind::AnthropicApiKey,
            label: "Anthropic API Key",
            severity: Severity::Critical,
        },
        // OpenAI API Key (legacy format)
        SecretPattern {
            regex: Regex::new(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}").unwrap(),
            prefixes: &["sk-"],
            kind: SecretKind::OpenAiApiKey,
            label: "OpenAI API Key",
            severity: Severity::Critical,
        },
        // OpenAI API Key (new project/service account format)
        SecretPattern {
            regex: Regex::new(r"sk-(?:proj|svcacct)-[A-Za-z0-9_-]{20,}").unwrap(),
            prefixes: &["sk-proj-", "sk-svcacct-"],
            kind: SecretKind::OpenAiApiKey,
            label: "OpenAI API Key",
            severity: Severity::Critical,
        },
        // DigitalOcean Token
        SecretPattern {
            regex: Regex::new(r"dop_v1_[0-9a-f]{64}").unwrap(),
            prefixes: &["dop_v1_"],
            kind: SecretKind::DigitalOceanToken,
            label: "DigitalOcean Token",
            severity: Severity::Critical,
        },
        // Linear API Key
        SecretPattern {
            regex: Regex::new(r"lin_api_[A-Za-z0-9]{40}").unwrap(),
            prefixes: &["lin_api_"],
            kind: SecretKind::LinearApiKey,
            label: "Linear API Key",
            severity: Severity::High,
        },
        // PostHog API Key (phc_ for project, phx_ for personal)
        SecretPattern {
            regex: Regex::new(r"ph[cx]_[A-Za-z0-9]{30,}").unwrap(),
            prefixes: &["phc_", "phx_"],
            kind: SecretKind::PostHogApiKey,
            label: "PostHog API Key",
            severity: Severity::Medium,
        },
        // GitLab Personal Access Token
        SecretPattern {
            regex: Regex::new(r"glpat-[A-Za-z0-9_\-]{20}").unwrap(),
            prefixes: &["glpat-"],
            kind: SecretKind::GitLabPat,
            label: "GitLab Personal Access Token",
            severity: Severity::Critical,
        },
        // Cloudflare API Token
        SecretPattern {
            regex: Regex::new(r"cf_[A-Za-z0-9_\-]{37}").unwrap(),
            prefixes: &["cf_"],
            kind: SecretKind::CloudflareApiToken,
            label: "Cloudflare API Token",
            severity: Severity::Critical,
        },
        // Supabase Service Key
        SecretPattern {
            regex: Regex::new(r"sbp_[a-f0-9]{40}").unwrap(),
            prefixes: &["sbp_"],
            kind: SecretKind::SupabaseServiceKey,
            label: "Supabase Service Key",
            severity: Severity::Critical,
        },
        // GCP OAuth Access Token
        SecretPattern {
            regex: Regex::new(r"ya29\.[A-Za-z0-9_\-]{50,}").unwrap(),
            prefixes: &["ya29."],
            kind: SecretKind::GcpOAuthToken,
            label: "GCP OAuth Access Token",
            severity: Severity::Critical,
        },
        // Hashicorp Vault Token
        SecretPattern {
            regex: Regex::new(r"hvs\.[A-Za-z0-9_\-]{24,}").unwrap(),
            prefixes: &["hvs."],
            kind: SecretKind::HashicorpVaultToken,
            label: "Hashicorp Vault Token",
            severity: Severity::Critical,
        },
        // Doppler Token
        SecretPattern {
            regex: Regex::new(r"dp\.(?:st|sa|ct)\.[A-Za-z0-9_\-]{40,}").unwrap(),
            prefixes: &["dp."],
            kind: SecretKind::DopplerToken,
            label: "Doppler Token",
            severity: Severity::Critical,
        },
        // Vercel Token
        SecretPattern {
            regex: Regex::new(r"vercel_[A-Za-z0-9_\-]{24,}").unwrap(),
            prefixes: &["vercel_"],
            kind: SecretKind::VercelToken,
            label: "Vercel Token",
            severity: Severity::Critical,
        },
        // Databricks Token
        SecretPattern {
            regex: Regex::new(r"dapi[0-9a-f]{32}").unwrap(),
            prefixes: &["dapi"],
            kind: SecretKind::DatabricksToken,
            label: "Databricks Token",
            severity: Severity::Critical,
        },
        // Grafana API Key / Service Account
        SecretPattern {
            regex: Regex::new(r"glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}").unwrap(),
            prefixes: &["glsa_"],
            kind: SecretKind::GrafanaApiKey,
            label: "Grafana API Key",
            severity: Severity::High,
        },
        // Pulumi Access Token
        SecretPattern {
            regex: Regex::new(r"pul-[A-Za-z0-9]{40}").unwrap(),
            prefixes: &["pul-"],
            kind: SecretKind::PulumiAccessToken,
            label: "Pulumi Access Token",
            severity: Severity::Critical,
        },
        // Hugging Face Access Token
        SecretPattern {
            regex: Regex::new(r"hf_[A-Za-z0-9]{36,}").unwrap(),
            prefixes: &["hf_"],
            kind: SecretKind::HuggingFaceToken,
            label: "Hugging Face Access Token",
            severity: Severity::Critical,
        },

        // ── Keyword patterns: service-specific (4) ──────────────────────
        // Match by a service name in the variable/key name.

        // AWS Secret Access Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['\x22]?([A-Za-z0-9/+=]{40})['\x22]?"
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::AwsSecretKey,
            label: "AWS Secret Access Key",
            severity: Severity::Critical,
        },
        // Heroku API Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:heroku[_\-]?api[_\-]?key)\s*[:=]\s*['\x22]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\x22]?"
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::HerokuApiKey,
            label: "Heroku API Key",
            severity: Severity::High,
        },
        // Azure Subscription Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:subscription[_\-]?key|ocp-apim-subscription-key)\s*[:=]\s*['\x22]?([0-9a-f]{32})['\x22]?"
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::AzureSubscriptionKey,
            label: "Azure Subscription Key",
            severity: Severity::High,
        },
        // Datadog API Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:dd[_\-]?api[_\-]?key|datadog[_\-]?api[_\-]?key)\s*[:=]\s*['\x22]?([0-9a-f]{32})['\x22]?"
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::DatadogApiKey,
            label: "Datadog API Key",
            severity: Severity::High,
        },

        // ── Keyword patterns: generic dev words (3) ─────────────────────
        // Match by common developer variable names (api_key, token, etc.).

        // Generic API Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[:=]\s*['\x22]?([A-Za-z0-9_\-]{20,64})['\x22]?"
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::GenericApiKey,
            label: "Generic API Key",
            severity: Severity::Medium,
        },
        // Bearer Token in Authorization header
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:authorization|auth)\s*[:=]\s*['\x22]?Bearer\s+([A-Za-z0-9_\-\.]{20,512})['\x22]?"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::BearerToken,
            label: "Bearer Token",
            severity: Severity::High,
        },
        // Generic Token assignment
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:api[_\-]?token|auth[_\-]?token|access[_\-]?token|client[_\-]?secret)\s*[:=]\s*['\x22]([A-Za-z0-9_\-\.]{20,512})['\x22]"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::GenericToken,
            label: "Generic API Token",
            severity: Severity::High,
        },

        // ── Entropy-based fallback (2) ──────────────────────────────────
        // Broad keyword match + Shannon entropy check (done in detector.rs).

        // High-entropy catch-all: key/token/secret assignment with a long alphanumeric value
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:key|token|secret|credential|auth|password|apikey|api_key|api[_-]?secret|private[_-]?key|access[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|session[_-]?secret)\s*[:=]\s*['\x22]([A-Za-z0-9+/=_\-]{32,256})['\x22]"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::HighEntropyString,
            label: "High-Entropy Secret",
            severity: Severity::Low,
        },
        // Generic Secret/Password — require variable-assignment context
        // Must be preceded by a separator (not a minified object key like {TOKEN:"..."})
        // Value must contain some entropy (mixed chars, not plain-english-words)
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:^|[\s,;{(]|(?:export|const|let|var|def|set)\s+)(?:password|passwd|pwd|secret_key|api_secret|private_key)\s*[:=]\s*['\x22]([^'\x22\s]{12,64})['\x22]"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::GenericSecret,
            label: "Generic Secret/Password",
            severity: Severity::Medium,
        },
    ];
}
