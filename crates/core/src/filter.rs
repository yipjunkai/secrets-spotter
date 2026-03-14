use lazy_static::lazy_static;
use regex::Regex;

lazy_static! {
    static ref SKIP_EXTENSIONS: Regex = Regex::new(
        r"(?i)\.(png|jpg|jpeg|gif|svg|ico|webp|bmp|tiff|avif|woff2?|ttf|eot|otf|mp3|mp4|webm|ogg|wav|avi|mov|pdf|zip|tar|gz|br|map|wasm)(\?|$)"
    ).unwrap();

    static ref SKIP_CONTENT_TYPES: Regex = Regex::new(
        r"(?i)^(image|audio|video|font)/"
    ).unwrap();

    static ref SKIP_PATHS: Regex = Regex::new(
        r"(?i)/(jquery|lodash|react|angular|vue|bootstrap|tailwind|fontawesome|googleapis|cdn|polyfill|analytics|gtag|gtm)\b"
    ).unwrap();

    static ref SKIP_CDN_HOSTS: Regex = Regex::new(
        r"(?i)^https?://(cdnjs\.cloudflare\.com|unpkg\.com|cdn\.jsdelivr\.net|ajax\.googleapis\.com|cdn\.bootcdn\.net|code\.jquery\.com|stackpath\.bootstrapcdn\.com|maxcdn\.bootstrapcdn\.com|fonts\.googleapis\.com|use\.fontawesome\.com|cdn\.tailwindcss\.com)"
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
