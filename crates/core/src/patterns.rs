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
            regex: Regex::new(r"(?-u:\b)AKIA[0-9A-Z]{16}(?-u:\b)").unwrap(),
            prefixes: &["AKIA"],
            kind: SecretKind::AwsAccessKey,
            label: "AWS Access Key ID",
            severity: Severity::Critical,
        },
        // AWS Temporary Access Key (STS)
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)ASIA[0-9A-Z]{16}(?-u:\b)").unwrap(),
            prefixes: &["ASIA"],
            kind: SecretKind::AwsTempAccessKey,
            label: "AWS Temporary Access Key (STS)",
            severity: Severity::Critical,
        },
        // GitHub Personal Access Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)ghp_[A-Za-z0-9]{36}(?-u:\b)|(?-u:\b)github_pat_[A-Za-z0-9_]{82}(?-u:\b)").unwrap(),
            prefixes: &["ghp_", "github_pat_"],
            kind: SecretKind::GitHubToken,
            label: "GitHub Personal Access Token",
            severity: Severity::Critical,
        },
        // GitHub OAuth Access Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)gho_[A-Za-z0-9]{36}(?-u:\b)").unwrap(),
            prefixes: &["gho_"],
            kind: SecretKind::GitHubOAuthToken,
            label: "GitHub OAuth Token",
            severity: Severity::Critical,
        },
        // GitHub App Tokens — user-to-server (ghu_) and refresh (ghr_) are fixed 36 chars
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)gh[ur]_[A-Za-z0-9]{36}(?-u:\b)").unwrap(),
            prefixes: &["ghu_", "ghr_"],
            kind: SecretKind::GitHubAppToken,
            label: "GitHub App Token",
            severity: Severity::Critical,
        },
        // GitHub App installation tokens — legacy 36-char OR new stateless ~520-char format
        SecretPattern {
            // New stateless tokens are `ghs_<id>_<base64url-JWT>` (~520 chars,
            // containing '.', '-', '_'); the legacy form is 36 base62 chars.
            regex: Regex::new(r"(?-u:\b)ghs_[A-Za-z0-9._-]{36,}").unwrap(),
            prefixes: &["ghs_"],
            kind: SecretKind::GitHubAppToken,
            label: "GitHub App Installation Token",
            severity: Severity::Critical,
        },
        // Private Key (PEM)
        SecretPattern {
            regex: Regex::new(
                r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----"
            ).unwrap(),
            prefixes: &["-----BEGIN"],
            kind: SecretKind::PrivateKeyBlock,
            label: "Private Key (PEM)",
            severity: Severity::Critical,
        },
        // Password in URL
        SecretPattern {
            regex: Regex::new(
                r#"(?i)(?:https?|ftp|ssh|mysql|postgresql|postgres|redis|mongodb|amqp|smtp|mariadb|cockroachdb)://[A-Za-z0-9._~-]+:([A-Za-z0-9._~!%*+-]{8,})@(?:\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._-]+)(?::[0-9]+)?"#
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
            severity: Severity::Medium,
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
            label: "Google API Key (may be restricted)",
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
            label: "Stripe Publishable Key (public)",
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
        // Twilio API Key SID — `SK` + 32 hex is the key's public SID, not the
        // secret itself; word-bounded so it doesn't fire inside words like "RISK".
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)SK[0-9a-fA-F]{32}(?-u:\b)").unwrap(),
            prefixes: &["SK"],
            kind: SecretKind::TwilioKey,
            label: "Twilio API Key SID",
            severity: Severity::High,
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
            regex: Regex::new(r"[MNO][A-Za-z0-9_-]{17,28}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,40}").unwrap(),
            prefixes: &[],
            kind: SecretKind::DiscordToken,
            label: "Discord Bot Token",
            severity: Severity::Critical,
        },
        // Mailgun API Key — gated on a "mailgun" keyword so it doesn't fire on
        // unrelated `key-<hash>` strings (cache keys, asset digests, etc.).
        SecretPattern {
            regex: Regex::new(
                r#"(?i)mailgun[a-z0-9_\-]*\s*[:=]\s*['\x22]?(key-[0-9a-zA-Z]{32})['\x22]?"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::MailgunApiKey,
            label: "Mailgun API Key",
            severity: Severity::High,
        },
        // npm Access Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)npm_[A-Za-z0-9]{36}(?-u:\b)").unwrap(),
            prefixes: &["npm_"],
            kind: SecretKind::NpmToken,
            label: "npm Access Token",
            severity: Severity::Critical,
        },
        // PyPI API Token
        SecretPattern {
            // Always begins with the constant macaroon header AgEIcHlwaS5vcmc.
            regex: Regex::new(r"pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}").unwrap(),
            prefixes: &["pypi-"],
            kind: SecretKind::PyPiToken,
            label: "PyPI API Token",
            severity: Severity::Critical,
        },
        // Shopify Access Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)shp(?:at|ss|ca|pa)_[0-9a-fA-F]{32}(?-u:\b)").unwrap(),
            prefixes: &["shp"],
            kind: SecretKind::ShopifyToken,
            label: "Shopify Token",
            severity: Severity::Critical,
        },
        // Square Access Token — legacy `sq0atp-`+22 and modern `EAAA`+60.
        SecretPattern {
            regex: Regex::new(r"(?:sq0atp-[A-Za-z0-9_-]{22}|EAAA[A-Za-z0-9_-]{60})").unwrap(),
            prefixes: &["sq0atp-", "EAAA"],
            kind: SecretKind::SquareAccessToken,
            label: "Square Access Token",
            severity: Severity::Critical,
        },
        // Anthropic API Key
        SecretPattern {
            regex: Regex::new(r"sk-ant-(?:api03|admin01)-[A-Za-z0-9_-]{93}AA").unwrap(),
            prefixes: &["sk-ant-api03-", "sk-ant-admin01-"],
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
            // Modern keys embed a literal T3BlbkFJ marker mid-body.
            regex: Regex::new(r"sk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}").unwrap(),
            prefixes: &["sk-proj-", "sk-svcacct-", "sk-admin-"],
            kind: SecretKind::OpenAiApiKey,
            label: "OpenAI API Key",
            severity: Severity::Critical,
        },
        // DigitalOcean Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)dop_v1_[0-9a-f]{64}(?-u:\b)").unwrap(),
            prefixes: &["dop_v1_"],
            kind: SecretKind::DigitalOceanToken,
            label: "DigitalOcean Token",
            severity: Severity::Critical,
        },
        // Linear API Key
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)lin_api_[A-Za-z0-9]{40}(?-u:\b)").unwrap(),
            prefixes: &["lin_api_"],
            kind: SecretKind::LinearApiKey,
            label: "Linear API Key",
            severity: Severity::Critical,
        },
        // PostHog Project Key — public by design, embedded in browser JS snippets
        SecretPattern {
            regex: Regex::new(r"phc_[A-Za-z0-9]{30,}").unwrap(),
            prefixes: &["phc_"],
            kind: SecretKind::PostHogProjectKey,
            label: "PostHog Project Key (public)",
            severity: Severity::Low,
        },
        // PostHog Personal API Key — full account access
        SecretPattern {
            regex: Regex::new(r"phx_[A-Za-z0-9]{30,}").unwrap(),
            prefixes: &["phx_"],
            kind: SecretKind::PostHogPersonalKey,
            label: "PostHog Personal API Key",
            severity: Severity::Critical,
        },
        // GitLab Personal Access Token
        SecretPattern {
            regex: Regex::new(r"glpat-[A-Za-z0-9_\-]{20}").unwrap(),
            prefixes: &["glpat-"],
            kind: SecretKind::GitLabPat,
            label: "GitLab Personal Access Token",
            severity: Severity::Critical,
        },
        // Cloudflare API Token — real tokens have no fixed prefix, so gate on a
        // "cloudflare" keyword near a 37-40 char value.
        SecretPattern {
            regex: Regex::new(
                r#"(?i)cloudflare[a-z0-9_\-]*\s*[:=]\s*['\x22]?([A-Za-z0-9_\-]{37,40})['\x22]?"#
            ).unwrap(),
            prefixes: &[],
            kind: SecretKind::CloudflareApiToken,
            label: "Cloudflare API Token",
            severity: Severity::Critical,
        },
        // Cloudflare Origin CA Key — fixed `v1.0-<24hex>-<146hex>` structure.
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)v1\.0-[0-9a-f]{24}-[0-9a-f]{146}(?-u:\b)").unwrap(),
            prefixes: &["v1.0-"],
            kind: SecretKind::CloudflareApiToken,
            label: "Cloudflare Origin CA Key",
            severity: Severity::Critical,
        },
        // Supabase Access Token — `sbp_` is the personal/management API token;
        // the service-role key is a JWT (caught by the JWT pattern instead).
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)sbp_[a-f0-9]{40}(?-u:\b)").unwrap(),
            prefixes: &["sbp_"],
            kind: SecretKind::SupabaseAccessToken,
            label: "Supabase Access Token",
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
        // Vercel Token — real tokens use vcp_/vci_/vca_/vcr_/vck_ prefixes
        // (introduced 2026 for secret scanning); the old `vercel_` never existed.
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)vc[pirak]_[A-Za-z0-9]{24,}(?-u:\b)").unwrap(),
            prefixes: &["vcp_", "vci_", "vca_", "vcr_", "vck_"],
            kind: SecretKind::VercelToken,
            label: "Vercel Token",
            severity: Severity::Critical,
        },
        // Databricks Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)dapi[0-9a-f]{32}(?-u:\b)").unwrap(),
            prefixes: &["dapi"],
            kind: SecretKind::DatabricksToken,
            label: "Databricks Token",
            severity: Severity::Critical,
        },
        // Grafana API Key / Service Account
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8}(?-u:\b)").unwrap(),
            prefixes: &["glsa_"],
            kind: SecretKind::GrafanaApiKey,
            label: "Grafana API Key",
            severity: Severity::Critical,
        },
        // Pulumi Access Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)pul-[a-f0-9]{40}(?-u:\b)").unwrap(),
            prefixes: &["pul-"],
            kind: SecretKind::PulumiAccessToken,
            label: "Pulumi Access Token",
            severity: Severity::Critical,
        },
        // Hugging Face Access Token
        SecretPattern {
            regex: Regex::new(r"(?-u:\b)hf_[A-Za-z0-9]{34,}(?-u:\b)").unwrap(),
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
            severity: Severity::Critical,
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
            severity: Severity::Critical,
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

#[cfg(test)]
mod tests {
    use crate::scan_text;
    use crate::test_fixtures::{body, ALNUM, DIGITS, URL_SAFE};
    use crate::types::SecretKind;

    fn matches_github_app(text: &str) -> bool {
        scan_text(text)
            .iter()
            .any(|f| matches!(f.kind, SecretKind::GitHubAppToken) && f.full_match == text)
    }

    #[test]
    fn ghs_legacy_36_char_token_matches() {
        let token = format!("ghs_{}", body(ALNUM, 36));
        assert_eq!(token.len(), 40);
        assert!(matches_github_app(&token));
    }

    #[test]
    fn ghs_new_stateless_long_token_matches() {
        // New stateless format is `ghs_<id>_<base64url JWT>` (~520 chars) and
        // contains '.', '-', '_' — the old [A-Za-z0-9]{400,600} branch rejected it.
        let token = format!(
            "ghs_{}_{}.{}.{}",
            body(DIGITS, 5),
            body(URL_SAFE, 180),
            body(URL_SAFE, 180),
            body(URL_SAFE, 140)
        );
        assert!(token.len() > 500);
        assert!(matches_github_app(&token));
    }

    #[test]
    fn ghs_too_short_token_does_not_match() {
        // Fewer than 36 chars after the prefix must not match.
        let token = format!("ghs_{}", body(ALNUM, 20));
        assert!(!matches_github_app(&token));
    }
}
