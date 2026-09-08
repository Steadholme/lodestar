//! HTTP handlers + shared server-render helpers.
//!
//! `health` is the unauthenticated liveness probe; `zones` is the SSO-gated zone editor + the
//! record add/delete flow + the JSON list + the test-query box.
//!
//! The shared design tokens / CSS are embedded (via `include_str!`) and served as a versioned asset,
//! matching the Steadholme enterprise brand (the same look as the Keystone/inkwell UI): brand
//! gradient, indigo accent, cards, app-bar, system font stack.

pub mod health;
pub mod zones;
mod zones_view;

use std::sync::OnceLock;

use axum::http::{header, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};

/// Lodestar-only CSS layered after Odyssey's canonical font, tokens, and components.
pub const SERVICE_CSS: &str = include_str!("../../static/service.css");
const ERROR_HTML: &str = include_str!("../../templates/error.html");

pub const APP_CSS_PATH: &str = "/assets/lodestar-20260908.css";

static APP_CSS: OnceLock<String> = OnceLock::new();

/// Embedded design system served from [`APP_CSS_PATH`].
pub fn app_css() -> &'static str {
    APP_CSS
        .get_or_init(|| {
            let mut css = String::with_capacity(odyssey::APP_CSS.len() + SERVICE_CSS.len());
            css.push_str(odyssey::APP_CSS);
            css.push_str(SERVICE_CSS);
            css
        })
        .as_str()
}

/// Long-lived, content-versioned stylesheet shared by normal and error pages.
pub async fn app_css_asset() -> Response {
    let mut response = app_css().into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/css; charset=utf-8"),
    );
    headers.insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("public, max-age=31536000, immutable"),
    );
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    response
}

/// Cross-subdomain gateway logout (Lodestar lives at dns.w33d.xyz; the IdP is at id.w33d.xyz).
pub const LOGOUT_URL: &str = "https://sso.w33d.xyz/_gw/auth/logout";


/// Minimal HTML escaping for text/attribute interpolation (defense-in-depth on every field).
pub fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#x27;")
}


/// Format epoch seconds as a compact UTC date `Mon D, YYYY` (e.g. `Jun 29, 2026`). std `time` only.
pub fn fmt_date(secs: i64) -> String {
    match time::OffsetDateTime::from_unix_timestamp(secs) {
        Ok(dt) => format!("{} {}, {}", month_abbr(dt.month()), dt.day(), dt.year()),
        Err(_) => secs.to_string(),
    }
}

fn month_abbr(m: time::Month) -> &'static str {
    use time::Month::*;
    match m {
        January => "Jan",
        February => "Feb",
        March => "Mar",
        April => "Apr",
        May => "May",
        June => "Jun",
        July => "Jul",
        August => "Aug",
        September => "Sep",
        October => "Oct",
        November => "Nov",
        December => "Dec",
    }
}


/// Icons used across the console chrome (inline so no asset request is needed).
pub const ICON_MARK: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4"/><circle cx="12" cy="12" r="3.5"/></svg>"##;
pub const ICON_GRID: &str = r##"<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/></svg>"##;
pub const ICON_GLOBE: &str = r##"<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"1.8\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><circle cx=\"12\" cy=\"12\" r=\"8.5\"/><path d=\"M3.5 12h17\"/></svg>"##;
pub const ICON_PLAY: &str = r##"<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"m6 4 14 8-14 8V4Z\"/></svg>"##;
pub const ICON_UPLOAD: &str = r##"<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"M12 20V8\"/><path d=\"m7 12 5-5 5 5\"/><path d=\"M4 4h16\"/></svg>"##;
pub const ICON_CHECK: &str = r##"<svg viewBox=\"0 0 24 24\" fill=\"none\" stroke=\"currentColor\" stroke-width=\"2.4\" stroke-linecap=\"round\" stroke-linejoin=\"round\" aria-hidden=\"true\"><path d=\"m4 12 5 5L20 6\"/></svg>"##;
/// The console pages, in app-bar order.
pub const NAV: [(&str, &str); 1] = [("/", "Zones")];

/// Render the app bar: brand lockup + host + page pills; All apps, identity and Log out.
pub fn app_bar(active: &str, email: Option<&str>) -> String {
    let mut pills = String::new();
    for (href, label) in NAV {
        pills.push_str(&format!(
            r#"<a class="surf{state}" href="{href}"{aria}>{label}</a>"#,
            state = if href == active { " is-active" } else { "" },
            href = href,
            aria = if href == active { r#" aria-current="page""# } else { "" },
            label = label,
        ));
    }
    let chip = match email {
        Some(value) if !value.is_empty() && value != "—" => {
            let initial = value
                .chars()
                .next()
                .map(|c| c.to_uppercase().to_string())
                .unwrap_or_else(|| "S".to_string());
            format!(
                r#"<span class="userchip"><span class="userchip__avatar" aria-hidden="true">{initial}</span><span class="user-email">{email}</span></span>"#,
                initial = esc(&initial),
                email = esc(value),
            )
        }
        _ => r#"<span class="user-email user-email--none">— (no gateway session)</span>"#.to_string(),
    };
    format!(
        r#"<header class="suitebar">
  <a class="suitebar__brand" href="/">
    <span class="brand-tile" aria-hidden="true">{mark}</span>
    <span class="suitebar__name"><b>Steadholme</b><span>Lodestar · authoritative DNS</span></span>
  </a>
  <span class="suitebar__host">dns.w33d.xyz</span>
  <nav class="surfaces" aria-label="Lodestar pages">{pills}</nav>
  <span class="suitebar__spacer"></span>
  <div class="suitebar__right">
    <a class="allapps" href="https://w33d.xyz">{grid}<span>All apps</span></a>
    {chip}
    <a class="btn btn-ghost btn-sm" href="{logout}">Log out</a>
  </div>
</header>"#,
        mark = ICON_MARK,
        pills = pills,
        grid = ICON_GRID,
        chip = chip,
        logout = LOGOUT_URL,
    )
}

/// The shared page footer.
pub const FOOTER: &str = r##"<footer class="v2-foot">
  <span class="v2-foot__lead">Steadholme Lodestar · dns.w33d.xyz · DNS :5353 UDP + TCP</span>
  <a href="https://audit.w33d.xyz">Watchtower</a>
  <a href="https://status.w33d.xyz">Status</a>
  <a href="https://w33d.xyz">All apps</a>
</footer>"##;

/// Resolve the viewer's theme from the cookie header.
pub fn theme_of(headers: &axum::http::HeaderMap) -> &'static str {
    odyssey::resolve_theme(
        headers
            .get(header::COOKIE)
            .and_then(|value| value.to_str().ok()),
    )
}

/// Fill a page template's chrome placeholders: theme attributes, stylesheet, app bar, footer.
pub fn shell(template: &str, active: &str, theme: &str, email: Option<&str>) -> String {
    template
        .replace("{{THEME_ATTR}}", odyssey::html_theme_attr(theme))
        .replace("{{COLOR_SCHEME}}", odyssey::color_scheme_meta(theme))
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{APPBAR}}", &app_bar(active, email))
        .replace("{{FOOTER}}", FOOTER)
}

/// Render the branded error document as one status tile.
pub fn error_page(status: StatusCode, message: &str) -> String {
    let reason = status.canonical_reason().unwrap_or("Error");
    ERROR_HTML
        .replace("{{THEME_ATTR}}", "")
        .replace("{{COLOR_SCHEME}}", "light dark")
        .replace("{{CSS_PATH}}", APP_CSS_PATH)
        .replace("{{APPBAR}}", &app_bar("/", None))
        .replace("{{FOOTER}}", FOOTER)
        .replace("{{STATUS}}", &status.as_u16().to_string())
        .replace("{{HEADING}}", &esc(reason))
        .replace("{{MESSAGE}}", &esc(message))
}

