use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    // Binary / non-text assets that never carry scannable secrets. Source maps
    // (`.map`) are deliberately absent: they embed original source, inline
    // `sourcesContent`, and comments — a prime place for leaked keys/endpoints.
    static ref SKIP_EXTENSIONS: Regex = Regex::new(
        r"(?i-u)\.(png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|avif|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|avi|mov|pdf|zip|tar|gz|br|wasm)(\?|$)"
    ).unwrap();

    static ref SKIP_CONTENT_TYPES: Regex = Regex::new(
        r"(?i-u)^(image|audio|video|font)/"
    ).unwrap();

    // Well-known third-party library/framework path segments. A bare `cdn` token
    // is intentionally absent — it over-matched first-party routes like
    // `/cdn/config.json`; real CDN *hosts* are handled by SKIP_CDN_HOSTS below.
    static ref SKIP_PATHS: Regex = Regex::new(
        r"(?i-u)/(jquery|lodash|react|angular|vue|bootstrap|tailwind|fontawesome|googleapis|polyfill|analytics|gtag|gtm)\b"
    ).unwrap();

    static ref SKIP_CDN_HOSTS: Regex = Regex::new(
        r"(?i-u)^https?://(cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|ajax\.googleapis\.com|cdn\.bootcdn\.net|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|fonts\.googleapis\.com|use\.fontawesome\.com|cdn\.tailwindcss\.com)"
    ).unwrap();
}

pub fn should_scan(url: &str, content_type: &str) -> bool {
    if SKIP_EXTENSIONS.is_match(url) {
        return false;
    }
    if SKIP_PATHS.is_match(url) {
        return false;
    }
    if SKIP_CDN_HOSTS.is_match(url) {
        return false;
    }
    if !content_type.is_empty() && SKIP_CONTENT_TYPES.is_match(content_type) {
        return false;
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    // Ordinary resources whose bodies can carry secrets — must be scanned.
    #[rstest]
    #[case("https://api.example.com/v1/users", "application/json")]
    #[case("https://app.example.com/main.js", "text/javascript")]
    #[case("https://app.example.com/styles.css", "text/css")]
    #[case("https://app.example.com/", "text/html")]
    fn scans_ordinary_resources(#[case] url: &str, #[case] ct: &str) {
        assert!(should_scan(url, ct));
    }

    // Source maps must be scanned — they embed original source and inline
    // `sourcesContent`, a prime leak vector. Regression guard for the recall fix.
    #[rstest]
    #[case("https://app.example.com/static/bundle.js.map")]
    #[case("https://app.example.com/static/styles.css.map")]
    #[case("https://app.example.com/static/bundle.js.map?v=3")]
    fn scans_source_maps(#[case] url: &str) {
        assert!(should_scan(url, ""), "source maps must not be skipped");
    }

    // A bare `/cdn` path segment on a first-party host is no longer skipped.
    // Regression guard for the recall fix.
    #[rstest]
    #[case("https://myapp.example.com/cdn/user-config.json")]
    #[case("https://myapp.example.com/cdn-cgi/app/data.json")]
    fn scans_first_party_cdn_paths(#[case] url: &str) {
        assert!(
            should_scan(url, ""),
            "first-party /cdn paths must be scanned"
        );
    }

    // Binary / static-asset extensions stay skipped (including `.wasm`).
    #[rstest]
    #[case("https://example.com/logo.png")]
    #[case("https://example.com/font.woff2")]
    #[case("https://example.com/video.mp4")]
    #[case("https://example.com/archive.tar.gz")]
    #[case("https://example.com/module.wasm")]
    #[case("https://example.com/photo.JPG")]
    #[case("https://example.com/icon.svg?cachebust=1")]
    fn skips_binary_extensions(#[case] url: &str) {
        assert!(!should_scan(url, ""));
    }

    // Known third-party library path segments stay skipped.
    #[rstest]
    #[case("https://example.com/vendor/jquery.min.js")]
    #[case("https://example.com/assets/react.production.min.js")]
    #[case("https://example.com/js/bootstrap.bundle.js")]
    fn skips_known_library_paths(#[case] url: &str) {
        assert!(!should_scan(url, ""));
    }

    // Known CDN hosts stay skipped — independent of the removed `cdn` path token.
    #[rstest]
    #[case("https://cdnjs.cloudflare.com/ajax/libs/jquery/3.6.0/jquery.min.js")]
    #[case("https://unpkg.com/react@18/umd/react.production.min.js")]
    #[case("https://cdn.jsdelivr.net/npm/chart.js")]
    fn skips_cdn_hosts(#[case] url: &str) {
        assert!(!should_scan(url, ""));
    }

    // Non-text content types are skipped regardless of URL.
    #[rstest]
    #[case("image/png")]
    #[case("audio/mpeg")]
    #[case("video/mp4")]
    #[case("font/woff2")]
    fn skips_by_content_type(#[case] ct: &str) {
        assert!(!should_scan("https://example.com/opaque-endpoint", ct));
    }

    #[test]
    fn empty_content_type_does_not_skip() {
        assert!(should_scan("https://api.example.com/data", ""));
    }
}
