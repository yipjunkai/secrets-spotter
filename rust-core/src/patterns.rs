use lazy_static::lazy_static;
use regex::Regex;

use crate::types::{SecretKind, Severity};

pub struct SecretPattern {
    pub regex: Regex,
    pub kind: SecretKind,
    pub label: &'static str,
    pub severity: Severity,
}

lazy_static! {
    pub static ref PATTERNS: Vec<SecretPattern> = vec![
        // AWS Access Key ID
        SecretPattern {
            regex: Regex::new(r"AKIA[0-9A-Z]{16}").unwrap(),
            kind: SecretKind::AwsAccessKey,
            label: "AWS Access Key ID",
            severity: Severity::Critical,
        },
        // AWS Secret Access Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:aws_secret_access_key|aws_secret|secret_key)\s*[:=]\s*['\x22]?([A-Za-z0-9/+=]{40})['\x22]?"
            ).unwrap(),
            kind: SecretKind::AwsSecretKey,
            label: "AWS Secret Access Key",
            severity: Severity::Critical,
        },
        // GitHub Personal Access Token
        SecretPattern {
            regex: Regex::new(r"ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}").unwrap(),
            kind: SecretKind::GitHubToken,
            label: "GitHub Personal Access Token",
            severity: Severity::Critical,
        },
        // GitHub OAuth Access Token
        SecretPattern {
            regex: Regex::new(r"gho_[A-Za-z0-9]{36}").unwrap(),
            kind: SecretKind::GitHubOAuthToken,
            label: "GitHub OAuth Token",
            severity: Severity::High,
        },
        // Generic API Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:api[_\-]?key|apikey|api[_\-]?secret)\s*[:=]\s*['\x22]?([A-Za-z0-9_\-]{20,64})['\x22]?"
            ).unwrap(),
            kind: SecretKind::GenericApiKey,
            label: "Generic API Key",
            severity: Severity::Medium,
        },
        // Private Key (PEM)
        SecretPattern {
            regex: Regex::new(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"
            ).unwrap(),
            kind: SecretKind::PrivateKeyBlock,
            label: "Private Key (PEM)",
            severity: Severity::Critical,
        },
        // Password in URL — user and pass are simple tokens, host starts with a letter
        // User: alphanumeric/dots/hyphens/underscores only (no ? / = &)
        // Pass: same plus some special chars, no semicolons or quotes
        // Host: must start with a letter (not digits like @300)
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:https?|ftp|ssh|mysql|postgresql)://[A-Za-z0-9._~-]+:([A-Za-z0-9._~!%*+-]{3,})@[A-Za-z][A-Za-z0-9.-]*\.[A-Za-z]{2,}"#
            ).unwrap(),
            kind: SecretKind::PasswordInUrl,
            label: "Password in URL",
            severity: Severity::Critical,
        },
        // JWT Token
        SecretPattern {
            regex: Regex::new(
                r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"
            ).unwrap(),
            kind: SecretKind::JwtToken,
            label: "JWT Token",
            severity: Severity::High,
        },
        // Slack Token
        SecretPattern {
            regex: Regex::new(r"xox[bpors]-[0-9]{10,13}-[A-Za-z0-9\-]{10,}").unwrap(),
            kind: SecretKind::SlackToken,
            label: "Slack Token",
            severity: Severity::Critical,
        },
        // Google API Key
        SecretPattern {
            regex: Regex::new(r"AIza[0-9A-Za-z_-]{35}").unwrap(),
            kind: SecretKind::GoogleApiKey,
            label: "Google API Key",
            severity: Severity::High,
        },
        // Heroku API Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:heroku[_\-]?api[_\-]?key)\s*[:=]\s*['\x22]?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})['\x22]?"
            ).unwrap(),
            kind: SecretKind::HerokuApiKey,
            label: "Heroku API Key",
            severity: Severity::High,
        },
        // Stripe Secret Key
        SecretPattern {
            regex: Regex::new(r"sk_(?:live|test)_[A-Za-z0-9]{24,}").unwrap(),
            kind: SecretKind::StripeKey,
            label: "Stripe Secret Key",
            severity: Severity::Critical,
        },
        // Twilio API Key
        SecretPattern {
            regex: Regex::new(r"SK[0-9a-fA-F]{32}").unwrap(),
            kind: SecretKind::TwilioKey,
            label: "Twilio API Key",
            severity: Severity::High,
        },
        // SendGrid API Key
        SecretPattern {
            regex: Regex::new(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}").unwrap(),
            kind: SecretKind::SendGridKey,
            label: "SendGrid API Key",
            severity: Severity::Critical,
        },
        // Bearer Token in Authorization header
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:authorization|auth)\s*[:=]\s*['\x22]?Bearer\s+([A-Za-z0-9_\-\.]{20,})['\x22]?"#
            ).unwrap(),
            kind: SecretKind::BearerToken,
            label: "Bearer Token",
            severity: Severity::Critical,
        },
        // Generic Token assignment
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:api[_\-]?token|auth[_\-]?token|access[_\-]?token|client[_\-]?secret)\s*[:=]\s*['\x22]([A-Za-z0-9_\-\.]{20,})['\x22]"#
            ).unwrap(),
            kind: SecretKind::GenericToken,
            label: "Generic API Token",
            severity: Severity::High,
        },
        // Discord Bot Token
        SecretPattern {
            regex: Regex::new(r"[MN][A-Za-z0-9]{23,}\.[\w-]{6}\.[\w-]{27,}").unwrap(),
            kind: SecretKind::DiscordToken,
            label: "Discord Bot Token",
            severity: Severity::Critical,
        },
        // Mailgun API Key
        SecretPattern {
            regex: Regex::new(r"key-[0-9a-zA-Z]{32}").unwrap(),
            kind: SecretKind::MailgunApiKey,
            label: "Mailgun API Key",
            severity: Severity::High,
        },
        // npm Access Token
        SecretPattern {
            regex: Regex::new(r"npm_[A-Za-z0-9]{36}").unwrap(),
            kind: SecretKind::NpmToken,
            label: "npm Access Token",
            severity: Severity::Critical,
        },
        // PyPI API Token
        SecretPattern {
            regex: Regex::new(r"pypi-[A-Za-z0-9_-]{50,}").unwrap(),
            kind: SecretKind::PyPiToken,
            label: "PyPI API Token",
            severity: Severity::Critical,
        },
        // Azure Subscription Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:subscription[_\-]?key|ocp-apim-subscription-key)\s*[:=]\s*['\x22]?([0-9a-f]{32})['\x22]?"
            ).unwrap(),
            kind: SecretKind::AzureSubscriptionKey,
            label: "Azure Subscription Key",
            severity: Severity::High,
        },
        // Datadog API Key
        SecretPattern {
            regex: Regex::new(
                r"(?i)(?:dd[_\-]?api[_\-]?key|datadog[_\-]?api[_\-]?key)\s*[:=]\s*['\x22]?([0-9a-f]{32})['\x22]?"
            ).unwrap(),
            kind: SecretKind::DatadogApiKey,
            label: "Datadog API Key",
            severity: Severity::High,
        },
        // Shopify Access Token
        SecretPattern {
            regex: Regex::new(r"shpat_[0-9a-fA-F]{32}").unwrap(),
            kind: SecretKind::ShopifyToken,
            label: "Shopify Access Token",
            severity: Severity::Critical,
        },
        // Square Access Token
        SecretPattern {
            regex: Regex::new(r"sq0atp-[A-Za-z0-9_-]{22}").unwrap(),
            kind: SecretKind::SquareAccessToken,
            label: "Square Access Token",
            severity: Severity::Critical,
        },
        // Anthropic API Key
        SecretPattern {
            regex: Regex::new(r"sk-ant-api03-[A-Za-z0-9_-]{93}").unwrap(),
            kind: SecretKind::AnthropicApiKey,
            label: "Anthropic API Key",
            severity: Severity::Critical,
        },
        // OpenAI API Key
        SecretPattern {
            regex: Regex::new(r"sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}").unwrap(),
            kind: SecretKind::OpenAiApiKey,
            label: "OpenAI API Key",
            severity: Severity::Critical,
        },
        // DigitalOcean Token
        SecretPattern {
            regex: Regex::new(r"dop_v1_[0-9a-f]{64}").unwrap(),
            kind: SecretKind::DigitalOceanToken,
            label: "DigitalOcean Token",
            severity: Severity::Critical,
        },
        // Linear API Key
        SecretPattern {
            regex: Regex::new(r"lin_api_[A-Za-z0-9]{40}").unwrap(),
            kind: SecretKind::LinearApiKey,
            label: "Linear API Key",
            severity: Severity::High,
        },
        // PostHog API Key (phc_ for project, phx_ for personal)
        SecretPattern {
            regex: Regex::new(r"ph[cx]_[A-Za-z0-9]{30,}").unwrap(),
            kind: SecretKind::PostHogApiKey,
            label: "PostHog API Key",
            severity: Severity::High,
        },
        // High-entropy catch-all: key/token/secret assignment with a long alphanumeric value
        // Entropy check is done in the detector, not here — regex just finds candidates
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:key|token|secret|credential|auth|password|apikey|api_key|api[_-]?secret|private[_-]?key|access[_-]?key|client[_-]?secret|signing[_-]?key|encryption[_-]?key|session[_-]?secret)\s*[:=]\s*['\x22]([A-Za-z0-9+/=_\-]{32,256})['\x22]"#
            ).unwrap(),
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
            kind: SecretKind::GenericSecret,
            label: "Generic Secret/Password",
            severity: Severity::Medium,
        },
    ];
}
