//! Per-pattern positive and near-miss negative cases for every detection
//! pattern in `patterns.rs`.
//!
//! FIXTURE POLICY: positive fixtures are assembled at runtime via
//! `test_fixtures` (prefix joined with a generated body) so that no
//! secret-shaped string ever appears contiguously in source. See
//! `test_fixtures.rs` for why. Negative cases that are too short or
//! wrongly-prefixed to be secret-shaped may stay as plain literals.

use crate::detector::SecretDetector;
use crate::test_fixtures::{body, opaque, tok, ALNUM, DIGITS, HEX, UPPER_NUM, URL_SAFE};
use crate::types::SecretKind;
use rstest::rstest;

/// Helper: scan text and check if any finding matches the expected SecretKind.
fn has_finding(text: &str, expected: &SecretKind) -> bool {
    let findings = SecretDetector::scan(text);
    findings
        .iter()
        .any(|f| std::mem::discriminant(&f.kind) == std::mem::discriminant(expected))
}

// ── Known-prefix patterns ────────────────────────────────────────────

#[rstest]
// AWS Access Key ID
#[case(&tok("AKIA", UPPER_NUM, 16), SecretKind::AwsAccessKey, true)]
#[case("AKIA", SecretKind::AwsAccessKey, false)] // too short
#[case(&tok("BKIA", UPPER_NUM, 16), SecretKind::AwsAccessKey, false)] // wrong prefix
// AWS Temporary Access Key (STS)
#[case(&tok("ASIA", UPPER_NUM, 16), SecretKind::AwsTempAccessKey, true)]
#[case("ASIA", SecretKind::AwsTempAccessKey, false)] // too short
// GitHub Personal Access Token — classic and fine-grained
#[case(&tok("ghp_", ALNUM, 36), SecretKind::GitHubToken, true)]
#[case(&tok("github_pat_", ALNUM, 82), SecretKind::GitHubToken, true)]
#[case("ghp_tooshort", SecretKind::GitHubToken, false)]
// GitHub OAuth Token
#[case(&tok("gho_", ALNUM, 36), SecretKind::GitHubOAuthToken, true)]
#[case("gho_short", SecretKind::GitHubOAuthToken, false)]
// GitHub App Tokens
#[case(&tok("ghu_", ALNUM, 36), SecretKind::GitHubAppToken, true)]
#[case(&tok("ghs_", ALNUM, 36), SecretKind::GitHubAppToken, true)]
#[case(&tok("ghr_", ALNUM, 36), SecretKind::GitHubAppToken, true)]
#[case(&tok("ghx_", ALNUM, 36), SecretKind::GitHubAppToken, false)] // wrong letter
fn github_and_aws_patterns(
    #[case] input: &str,
    #[case] kind: SecretKind,
    #[case] should_match: bool,
) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// Private Key (PEM) — header assembled so no PEM marker exists in source
fn pem(algo: &str, visibility: &str) -> String {
    format!("-----BEGIN {algo}{visibility} KEY-----")
}

#[rstest]
#[case("", "PRIVATE", true)]
#[case("RSA ", "PRIVATE", true)]
#[case("EC ", "PRIVATE", true)]
#[case("DSA ", "PRIVATE", true)]
#[case("OPENSSH ", "PRIVATE", true)]
#[case("ENCRYPTED ", "PRIVATE", true)]
#[case("", "PUBLIC", false)]
fn private_key_patterns(#[case] algo: &str, #[case] visibility: &str, #[case] should_match: bool) {
    let input = pem(algo, visibility);
    assert_eq!(
        has_finding(&input, &SecretKind::PrivateKeyBlock),
        should_match,
        "input={input:?}"
    );
}

// PGP private key block uses a different trailer ("KEY BLOCK"), so it can't go
// through the pem() helper above. Assembled so the header isn't a contiguous
// literal in source (keeps the scan-self dogfood guard quiet).
#[test]
fn pgp_private_key_block_matches() {
    let input = format!("-----BEGIN PGP PRIVATE KEY {}-----", "BLOCK");
    assert!(
        has_finding(&input, &SecretKind::PrivateKeyBlock),
        "input={input:?}"
    );
}

// Password in URL
#[rstest]
#[case(&format!("https://admin:{}@example.com", body(ALNUM, 14)), true)]
#[case(&format!("postgresql://user:{}@db.host.com", body(ALNUM, 14)), true)]
// Punctuation allowed in the password class
#[case(&format!("https://admin:{}!{}@example.com", body(ALNUM, 6), body(ALNUM, 6)), true)]
// Host can be localhost, an IP, or a single-label host with a port
#[case(&format!("https://admin:{}@localhost", body(ALNUM, 14)), true)]
#[case(&format!("redis://user:{}@127.0.0.1:6379", body(ALNUM, 14)), true)]
#[case("https://example.com/page", false)] // no password
#[case(&format!("https://user:{}@example.com", "short"), false)] // password too short (<8)
fn password_in_url(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::PasswordInUrl),
        should_match,
        "input={input:?}"
    );
}

// JWT Token
#[rstest]
#[case(&format!("eyJ{}.eyJ{}.{}", body(URL_SAFE, 16), body(URL_SAFE, 16), body(URL_SAFE, 16)), true)]
#[case(&format!("eyJ{}.eyJ{}.{}", "abc", "de", "short"), false)] // segments too short
fn jwt_token(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::JwtToken),
        should_match,
        "input={input:?}"
    );
}

// Slack Token
#[rstest]
#[case(&format!("xoxb-{}-{}", body(DIGITS, 10), body(ALNUM, 12)), true)]
#[case(&format!("xoxp-{}-{}", body(DIGITS, 10), body(ALNUM, 12)), true)]
#[case("xox-missing-prefix", false)]
fn slack_token(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::SlackToken),
        should_match,
        "input={input:?}"
    );
}

// Slack App-Level Token
#[rstest]
#[case(&format!("xapp-1-{}-{}-{}", body(ALNUM, 10), body(DIGITS, 10), body(ALNUM, 10)), true)]
#[case("xapp-invalid", false)]
fn slack_app_token(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::SlackAppToken),
        should_match,
        "input={input:?}"
    );
}

// Google API Key
#[rstest]
#[case(&tok("AIza", URL_SAFE, 35), true)]
#[case("AIza_short", false)]
fn google_api_key(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::GoogleApiKey),
        should_match,
        "input={input:?}"
    );
}

// Stripe keys — secret, publishable, restricted, webhook
#[rstest]
#[case(&tok("sk_live_", ALNUM, 24), SecretKind::StripeKey, true)]
#[case(&tok("sk_test_", ALNUM, 24), SecretKind::StripeKey, true)]
#[case("sk_live_short", SecretKind::StripeKey, false)]
#[case(&tok("pk_live_", ALNUM, 24), SecretKind::StripePublishableKey, true)]
#[case("pk_live_short", SecretKind::StripePublishableKey, false)]
#[case(&tok("rk_live_", ALNUM, 24), SecretKind::StripeRestrictedKey, true)]
#[case(&tok("rk_test_", ALNUM, 24), SecretKind::StripeRestrictedKey, true)]
#[case("rk_live_short", SecretKind::StripeRestrictedKey, false)]
#[case(&tok("whsec_", ALNUM, 32), SecretKind::StripeWebhookSecret, true)]
#[case("whsec_short", SecretKind::StripeWebhookSecret, false)]
fn stripe_patterns(#[case] input: &str, #[case] kind: SecretKind, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// Twilio API Key
#[rstest]
#[case(&tok("SK", HEX, 32), true)]
#[case("SK1234", false)] // too short
fn twilio_key(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::TwilioKey),
        should_match,
        "input={input:?}"
    );
}

// SendGrid API Key
#[rstest]
#[case(&format!("SG.{}.{}", body(URL_SAFE, 22), body(URL_SAFE, 43)), true)]
#[case("SG.short.short", false)]
fn sendgrid_key(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::SendGridKey),
        should_match,
        "input={input:?}"
    );
}

// Discord Bot Token
#[rstest]
#[case(&format!("M{}.{}.{}", body(ALNUM, 23), body(ALNUM, 6), body(ALNUM, 27)), true)]
#[case(&format!("O{}.{}.{}", body(ALNUM, 23), body(ALNUM, 6), body(ALNUM, 27)), true)] // O-leading IDs
#[case("MshortToken.abc.def", false)]
fn discord_token(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::DiscordToken),
        should_match,
        "input={input:?}"
    );
}

// Mailgun API Key — now requires a "mailgun" keyword in context
#[rstest]
#[case(&format!("mailgun_api_key={}", tok("key-", ALNUM, 32)), true)]
#[case(&format!(r#"mailgun_key: "{}""#, tok("key-", ALNUM, 32)), true)]
#[case(&tok("key-", ALNUM, 32), false)] // bare key- with no context — must NOT fire
#[case(&format!("cache-{}", tok("key-", HEX, 32)), false)] // cache-key-<hash> — the old false positive
#[case("mailgun_api_key=key-short", false)]
fn mailgun_key(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::MailgunApiKey),
        should_match,
        "input={input:?}"
    );
}

// npm / PyPI tokens
#[rstest]
#[case(&tok("npm_", ALNUM, 36), SecretKind::NpmToken, true)]
#[case("npm_short", SecretKind::NpmToken, false)]
#[case(&format!("pypi-AgEIcHlwaS5vcmc{}", body(URL_SAFE, 50)), SecretKind::PyPiToken, true)]
#[case(&tok("pypi-", URL_SAFE, 60), SecretKind::PyPiToken, false)] // missing macaroon header
#[case("pypi-short", SecretKind::PyPiToken, false)]
fn package_registry_tokens(
    #[case] input: &str,
    #[case] kind: SecretKind,
    #[case] should_match: bool,
) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// Shopify Access Token
#[rstest]
#[case(&tok("shpat_", HEX, 32), true)]
#[case(&tok("shpss_", HEX, 32), true)]
#[case(&tok("shpca_", HEX, 32), true)]
#[case(&tok("shppa_", HEX, 32), true)]
#[case(&tok("shpxx_", HEX, 32), false)] // wrong infix
fn shopify_token(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::ShopifyToken),
        should_match,
        "input={input:?}"
    );
}

// Square Access Token
#[rstest]
#[case(&tok("sq0atp-", URL_SAFE, 22), true)]
#[case(&tok("EAAA", URL_SAFE, 60), true)] // modern Square token format
#[case("sq0atp-short", false)]
fn square_token(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::SquareAccessToken),
        should_match,
        "input={input:?}"
    );
}

// Anthropic API Key
#[rstest]
#[case(&format!("sk-ant-api03-{}AA", body(URL_SAFE, 93)), true)]
#[case(&format!("sk-ant-admin01-{}AA", body(URL_SAFE, 93)), true)]
#[case("sk-ant-api03-short", false)]
fn anthropic_key(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::AnthropicApiKey),
        should_match,
        "input={input:?}"
    );
}

// OpenAI API Key — legacy infix format and new project/service-account format
#[rstest]
#[case(&format!("sk-{}{}{}", body(ALNUM, 20), "T3BlbkFJ", body(ALNUM, 20)), true)]
#[case(&format!("sk-short{}short", "T3BlbkFJ"), false)]
#[case(&format!("sk-proj-{}T3BlbkFJ{}", body(URL_SAFE, 24), body(URL_SAFE, 24)), true)]
#[case(&format!("sk-svcacct-{}T3BlbkFJ{}", body(URL_SAFE, 24), body(URL_SAFE, 24)), true)]
#[case(&format!("sk-admin-{}T3BlbkFJ{}", body(URL_SAFE, 24), body(URL_SAFE, 24)), true)]
#[case(&tok("sk-proj-", URL_SAFE, 24), false)] // missing the T3BlbkFJ marker
#[case("sk-proj-short", false)]
fn openai_key(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::OpenAiApiKey),
        should_match,
        "input={input:?}"
    );
}

// Cloud / infra provider tokens
#[rstest]
#[case(&tok("dop_v1_", HEX, 64), SecretKind::DigitalOceanToken, true)]
#[case("dop_v1_short", SecretKind::DigitalOceanToken, false)]
#[case(&tok("lin_api_", ALNUM, 40), SecretKind::LinearApiKey, true)]
#[case("lin_api_short", SecretKind::LinearApiKey, false)]
#[case(&tok("glpat-", URL_SAFE, 20), SecretKind::GitLabPat, true)]
#[case("glpat-short", SecretKind::GitLabPat, false)]
#[case(&format!("cloudflare_api_token={}", body(URL_SAFE, 40)), SecretKind::CloudflareApiToken, true)]
#[case(&format!("v1.0-{}-{}", body(HEX, 24), body(HEX, 146)), SecretKind::CloudflareApiToken, true)]
#[case("cloudflare_api_token=short", SecretKind::CloudflareApiToken, false)]
#[case(&tok("cf_", URL_SAFE, 37), SecretKind::CloudflareApiToken, false)] // old cf_ format is not real
#[case(&tok("sbp_", HEX, 40), SecretKind::SupabaseAccessToken, true)]
#[case("sbp_short", SecretKind::SupabaseAccessToken, false)]
#[case(&tok("ya29.", URL_SAFE, 50), SecretKind::GcpOAuthToken, true)]
#[case("ya29.short", SecretKind::GcpOAuthToken, false)]
#[case(&tok("hvs.", URL_SAFE, 24), SecretKind::HashicorpVaultToken, true)]
#[case("hvs.short", SecretKind::HashicorpVaultToken, false)]
#[case(&tok("dp.st.", URL_SAFE, 40), SecretKind::DopplerToken, true)]
#[case(&tok("dp.sa.", URL_SAFE, 40), SecretKind::DopplerToken, true)]
#[case(&tok("dp.ct.", URL_SAFE, 40), SecretKind::DopplerToken, true)]
#[case(&tok("dp.xx.", URL_SAFE, 40), SecretKind::DopplerToken, false)] // wrong infix
#[case(&tok("vcp_", ALNUM, 24), SecretKind::VercelToken, true)]
#[case(&tok("vck_", ALNUM, 24), SecretKind::VercelToken, true)]
#[case(&tok("vercel_", ALNUM, 24), SecretKind::VercelToken, false)] // old vercel_ prefix is not real
#[case("vcp_short", SecretKind::VercelToken, false)]
#[case(&tok("dapi", HEX, 32), SecretKind::DatabricksToken, true)]
#[case("dapideadbeef", SecretKind::DatabricksToken, false)] // too short
#[case(&format!("glsa_{}_{}", body(ALNUM, 32), body(HEX, 8)), SecretKind::GrafanaApiKey, true)]
#[case("glsa_short", SecretKind::GrafanaApiKey, false)]
#[case(&tok("pul-", HEX, 40), SecretKind::PulumiAccessToken, true)]
#[case("pul-short", SecretKind::PulumiAccessToken, false)]
#[case(&tok("hf_", ALNUM, 36), SecretKind::HuggingFaceToken, true)]
#[case(&tok("hf_", ALNUM, 34), SecretKind::HuggingFaceToken, true)] // real HF tokens are 34 chars
#[case("hf_short", SecretKind::HuggingFaceToken, false)]
fn provider_tokens(#[case] input: &str, #[case] kind: SecretKind, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// PostHog keys — project (public, Low) and personal (Critical) are distinct kinds
#[rstest]
#[case(&tok("phc_", ALNUM, 30), SecretKind::PostHogProjectKey, true)]
#[case("phc_short", SecretKind::PostHogProjectKey, false)]
#[case(&tok("phx_", ALNUM, 30), SecretKind::PostHogPersonalKey, true)]
#[case("phx_short", SecretKind::PostHogPersonalKey, false)]
fn posthog_keys(#[case] input: &str, #[case] kind: SecretKind, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// ── Keyword patterns: service-specific ───────────────────────────────

#[rstest]
// AWS Secret Access Key
#[case(&format!("aws_secret_access_key={}", body(ALNUM, 40)), SecretKind::AwsSecretKey, true)]
#[case(&format!("aws_secret={}", body(ALNUM, 40)), SecretKind::AwsSecretKey, true)]
// Base64 '=' padding is part of the value class and must be preserved
#[case(&format!("aws_secret_access_key={}==", body(ALNUM, 38)), SecretKind::AwsSecretKey, true)]
#[case("aws_secret_access_key=short", SecretKind::AwsSecretKey, false)]
// Heroku API Key (UUID shape)
#[case(
    &format!("heroku_api_key={}-{}-{}-{}-{}", body(HEX, 8), body(HEX, 4), body(HEX, 4), body(HEX, 4), body(HEX, 12)),
    SecretKind::HerokuApiKey,
    true
)]
#[case("heroku_api_key=not-a-uuid", SecretKind::HerokuApiKey, false)]
// Azure Subscription Key
#[case(&format!("subscription_key={}", body(HEX, 32)), SecretKind::AzureSubscriptionKey, true)]
#[case("subscription_key=short", SecretKind::AzureSubscriptionKey, false)]
// Datadog API Key
#[case(&format!("dd_api_key={}", body(HEX, 32)), SecretKind::DatadogApiKey, true)]
#[case(&format!("datadog_api_key={}", body(HEX, 32)), SecretKind::DatadogApiKey, true)]
#[case("dd_api_key=short", SecretKind::DatadogApiKey, false)]
fn keyword_service_patterns(
    #[case] input: &str,
    #[case] kind: SecretKind,
    #[case] should_match: bool,
) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// ── Keyword patterns: generic dev words ──────────────────────────────

#[rstest]
// Generic API Key — opaque digit-led value survives FP filtering
#[case(&format!("api_key={}", opaque(20)), SecretKind::GenericApiKey, true)]
// Placeholder value is rejected by the FALSE_POSITIVE filter
#[case(&format!("api_key={}", "your-api-key-value-here"), SecretKind::GenericApiKey, false)]
// Too short for the value class — regex never fires
#[case("api_key=changeme", SecretKind::GenericApiKey, false)]
// Bearer Token
#[case(&format!("Authorization: Bearer {}", opaque(30)), SecretKind::BearerToken, true)]
// Token below the 20-char minimum — regex never fires
#[case(&format!("Authorization: Bearer {}", "abc123"), SecretKind::BearerToken, false)]
// Code-identifier-shaped token rejected by the BearerToken FP arm
#[case(
    &format!("Authorization: Bearer {}", "myAuthTokenValueHandler"),
    SecretKind::BearerToken,
    false
)]
// Generic Token (quoted value required)
#[case(&format!(r#"api_token="{}""#, opaque(24)), SecretKind::GenericToken, true)]
// Unquoted value — this pattern requires quotes, unlike GenericApiKey
#[case(&format!("api_token={}", opaque(24)), SecretKind::GenericToken, false)]
// Placeholder value rejected by the FALSE_POSITIVE filter
#[case(
    &format!(r#"api_token="{}""#, "your-token-goes-here-now"),
    SecretKind::GenericToken,
    false
)]
fn keyword_generic_patterns(
    #[case] input: &str,
    #[case] kind: SecretKind,
    #[case] should_match: bool,
) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// ── Legacy formats (keyword-gated, still-valid old tokens) ───────────

#[rstest]
// GitHub pre-2021 40-char hex PAT — only with a github/gh token keyword
#[case(&format!("github_token={}", body(HEX, 40)), SecretKind::GitHubToken, true)]
#[case(&format!("gh_pat = \"{}\"", body(HEX, 40)), SecretKind::GitHubToken, true)]
#[case(&body(HEX, 40), SecretKind::GitHubToken, false)] // bare 40-hex (a SHA) — no keyword
#[case(&format!("git_sha={}", body(HEX, 40)), SecretKind::GitHubToken, false)] // commit SHA, not a token
// HashiCorp Vault legacy s. service token — only with a vault keyword
#[case(&format!("vault_token=s.{}", body(ALNUM, 24)), SecretKind::HashicorpVaultToken, true)]
#[case(&format!("s.{}", body(ALNUM, 24)), SecretKind::HashicorpVaultToken, false)] // bare, no keyword
// Vercel legacy 24-char token — only with a vercel keyword
#[case(&format!("vercel_token={}", body(ALNUM, 24)), SecretKind::VercelToken, true)]
#[case(&body(ALNUM, 24), SecretKind::VercelToken, false)] // bare 24-char, no keyword
fn legacy_keyword_patterns(
    #[case] input: &str,
    #[case] kind: SecretKind,
    #[case] should_match: bool,
) {
    assert_eq!(
        has_finding(input, &kind),
        should_match,
        "input={input:?}, expected match={should_match}"
    );
}

// ── Word-boundary regressions ────────────────────────────────────────
// Fixed-prefix patterns must not fire on a prefix embedded inside a longer
// token. These reproduce two empirically-confirmed false positives.

#[test]
fn word_boundary_rejects_sk_inside_word() {
    // "RISK" + 32 hex must NOT be flagged as a Twilio key (SK is mid-word).
    let text = format!("const RISK{} = 1;", body(HEX, 32));
    assert!(
        !has_finding(&text, &SecretKind::TwilioKey),
        "SK inside RISK must not match: {text:?}"
    );
}

#[test]
fn word_boundary_rejects_truncated_aws_key() {
    // A 36-char uppercase/digit run must not yield a truncated 20-char AWS key.
    let text = format!("AKIA{}", body(UPPER_NUM, 32));
    assert!(
        !has_finding(&text, &SecretKind::AwsAccessKey),
        "36-char run must not yield a truncated AWS key: {text:?}"
    );
}

// ── Entropy-based fallback ───────────────────────────────────────────

#[rstest]
// High entropy with mixed char classes — should detect
#[case(&format!(r#"secret="{}""#, opaque(32)), true)]
// Low entropy — should NOT detect
#[case(r#"secret="aaaabbbbccccddddeeeeffffgggghhhh""#, false)]
// Only lowercase — should NOT detect (needs 2 char classes)
#[case(r#"secret="qwertyuiopasdfghjklzxcvbnmqwerty""#, false)]
fn high_entropy_pattern(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::HighEntropyString),
        should_match,
        "input={input:?}"
    );
}

#[rstest]
// Generic Secret — real-looking password
#[case(&format!(r#"const password="{}""#, "Str0ngP@ssw0rd!"), true)]
// Generic Secret — placeholder filtered
#[case(&format!(r#"const password="{}""#, "your-password-here"), false)]
fn generic_secret_pattern(#[case] input: &str, #[case] should_match: bool) {
    assert_eq!(
        has_finding(input, &SecretKind::GenericSecret),
        should_match,
        "input={input:?}"
    );
}
