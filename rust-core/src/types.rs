use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Clone, Debug)]
pub enum SecretKind {
    AwsAccessKey,
    AwsSecretKey,
    GitHubToken,
    GitHubOAuthToken,
    GenericApiKey,
    PrivateKeyBlock,
    PasswordInUrl,
    JwtToken,
    SlackToken,
    GoogleApiKey,
    HerokuApiKey,
    StripeKey,
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
