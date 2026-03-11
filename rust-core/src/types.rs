use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SecretKind {
    AwsAccessKey,
    AwsTempAccessKey,
    AwsSecretKey,
    GitHubToken,
    GitHubOAuthToken,
    GitHubAppToken,
    GenericApiKey,
    PrivateKeyBlock,
    PasswordInUrl,
    JwtToken,
    SlackToken,
    SlackAppToken,
    GoogleApiKey,
    HerokuApiKey,
    StripeKey,
    StripeRestrictedKey,
    TwilioKey,
    SendGridKey,
    BearerToken,
    GenericToken,
    DiscordToken,
    MailgunApiKey,
    NpmToken,
    PyPiToken,
    AzureSubscriptionKey,
    DatadogApiKey,
    ShopifyToken,
    SquareAccessToken,
    AnthropicApiKey,
    OpenAiApiKey,
    DigitalOceanToken,
    LinearApiKey,
    PostHogApiKey,
    GitLabPat,
    CloudflareApiToken,
    SupabaseServiceKey,
    GcpOAuthToken,
    HashicorpVaultToken,
    DopplerToken,
    VercelToken,
    DatabricksToken,
    GrafanaApiKey,
    PulumiAccessToken,
    HighEntropyString,
    GenericSecret,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SecretFinding {
    pub kind: SecretKind,
    pub label: String,
    pub matched_text: String,
    pub full_match: String,
    pub start: usize,
    pub end: usize,
    pub severity: Severity,
}
