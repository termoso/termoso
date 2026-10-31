//! Browser view of SSH ID. The same lists `GET /sshid/{handle}[/{type}]`
//! serve as `authorized_keys` text are rendered as a page when the client
//! asks for HTML (`Accept: text/html`): the command that installs the keys,
//! the key types with their OpenSSH requirements, the published keys with
//! fingerprints and a short explanation of what SSH ID is and why to trust
//! it. `curl`/`wget` never send `text/html` first, so scripts keep getting
//! plain text.

use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use sha2::{Digest, Sha256};
use termoso_proto::sshid::SshIdKeyType;

/// `true` when the client prefers HTML over plain text — i.e. a browser.
pub fn wants_html(headers: &HeaderMap) -> bool {
    let Some(accept) = headers.get(header::ACCEPT).and_then(|v| v.to_str().ok()) else {
        return false;
    };
    let mut html = None;
    let mut text = None;
    for (i, part) in accept.split(',').enumerate() {
        let mut it = part.trim().split(';');
        let mime = it.next().unwrap_or("").trim();
        let q = it
            .find_map(|p| p.trim().strip_prefix("q="))
            .and_then(|q| q.trim().parse::<f32>().ok())
            .unwrap_or(1.0);
        if q <= 0.0 {
            continue;
        }
        match mime {
            "text/html" | "application/xhtml+xml" => html.get_or_insert((q, i)),
            "text/plain" => text.get_or_insert((q, i)),
            _ => continue,
        };
    }
    match (html, text) {
        (Some((hq, hi)), Some((tq, ti))) => hq > tq || (hq == tq && hi < ti),
        (Some(_), None) => true,
        _ => false,
    }
}

/// One published key: the type and its `<alg> <base64>` line.
pub struct Key {
    pub key_type: SshIdKeyType,
    pub public_key: String,
}

/// Everything the handle page needs.
pub struct HandlePage<'a> {
    pub handle: &'a str,
    /// Canonical base the handle is published under, without the handle.
    pub base: &'a str,
    /// `None` = `all`.
    pub selected: Option<SshIdKeyType>,
    pub keys: &'a [Key],
    pub server_name: &'a str,
    pub home_url: &'a str,
    pub docs_url: Option<&'a str>,
}

fn nonce() -> String {
    let mut b = [0u8; 16];
    rand::fill(&mut b);
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            c => out.push(c),
        }
    }
    out
}

/// `SHA256:<base64>` of the key blob, as `ssh-keygen -l` prints it.
pub fn fingerprint(public_key: &str) -> Option<String> {
    let blob = public_key.split_whitespace().nth(1)?;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(blob)
        .ok()?;
    let digest = Sha256::digest(&bytes);
    Some(format!(
        "SHA256:{}",
        base64::engine::general_purpose::STANDARD_NO_PAD.encode(digest)
    ))
}

fn label(t: SshIdKeyType) -> &'static str {
    match t {
        SshIdKeyType::Ed25519 => "ED25519",
        SshIdKeyType::Ecdsa => "ECDSA",
        SshIdKeyType::Rsa => "RSA",
        SshIdKeyType::EcdsaSk => "ECDSA-SK",
        SshIdKeyType::Ed25519Sk => "ED25519-SK",
    }
}

/// Minimum OpenSSH on the *server* that accepts the type.
fn requires(t: SshIdKeyType) -> &'static str {
    match t {
        SshIdKeyType::Ed25519 => "OpenSSH 6.5+",
        SshIdKeyType::Ecdsa => "OpenSSH 5.7+",
        SshIdKeyType::Rsa => "any OpenSSH",
        SshIdKeyType::EcdsaSk | SshIdKeyType::Ed25519Sk => "OpenSSH 8.2+",
    }
}

const CSS: &str = r#"
:root{--bg:#0F1320;--surface:#1C2032;--raised:#262B3F;--line:rgba(255,255,255,.08);--line2:rgba(255,255,255,.14);--text:#F1F3F8;--muted:#8D91A5;--dim:#5A5E73;--accent:#2BB884;--accent2:#1F8F66;--sky:#5AA9E6;--mono:'JetBrains Mono','SF Mono',Menlo,Consolas,monospace}
*{box-sizing:border-box}
html{background:var(--bg);color:var(--text);font:16px/1.55 'Inter',system-ui,-apple-system,'Segoe UI',Roboto,sans-serif;-webkit-font-smoothing:antialiased}
body{margin:0;background:radial-gradient(900px 420px at 50% -120px,rgba(43,184,132,.14),transparent 70%),var(--bg)}
a{color:inherit;text-decoration:none}
.wrap{max-width:760px;margin:0 auto;padding:28px 24px 56px}
header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:56px}
.brand{display:flex;align-items:center;gap:12px}
.brand svg{width:40px;height:40px;flex:none}
.brand b{display:block;font-size:17px;font-weight:700;letter-spacing:-.01em;line-height:1.2}
.brand small{display:block;color:var(--muted);font-size:13px;line-height:1.2}
.btn{display:inline-flex;align-items:center;gap:8px;height:40px;padding:0 18px;border-radius:10px;font-weight:600;font-size:14px;border:1px solid transparent;cursor:pointer;white-space:nowrap}
.btn-primary{background:var(--accent);color:#0B1A14}
.btn-primary:hover{background:#3BC893}
h1{font-size:40px;line-height:1.15;font-weight:600;letter-spacing:-.02em;margin:0 0 12px}
h1 .at{color:var(--accent)}
.lead{color:var(--muted);margin:0 0 28px;font-size:17px}
h2{font-size:22px;font-weight:600;letter-spacing:-.01em;margin:44px 0 14px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;padding:14px}
.bar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap}
.dd{position:relative}
.dd>summary{list-style:none;display:inline-flex;align-items:center;gap:8px;height:38px;padding:0 14px;border-radius:9px;background:var(--raised);border:1px solid var(--line);font-size:14px;font-weight:500;cursor:pointer;user-select:none}
.dd>summary::-webkit-details-marker{display:none}
.dd>summary:hover{border-color:var(--line2)}
.dd>summary .chev{width:10px;height:10px;border:solid var(--muted);border-width:0 1.5px 1.5px 0;transform:translateY(-3px) rotate(45deg);transition:transform .15s}
.dd[open]>summary .chev{transform:translateY(2px) rotate(-135deg)}
.menu{position:absolute;top:calc(100% + 6px);min-width:260px;background:var(--raised);border:1px solid var(--line2);border-radius:12px;padding:6px;box-shadow:0 18px 50px rgba(0,0,0,.45);z-index:5}
.dd.right .menu{right:0}
.menu .grp{padding:8px 12px 4px;font-size:12px;color:var(--muted)}
.menu .grp+.item{margin-top:0}
.menu hr{border:0;border-top:1px solid var(--line);margin:6px 0}
.item{display:flex;align-items:center;justify-content:space-between;gap:12px;width:100%;padding:8px 12px;border:0;border-radius:8px;background:none;color:var(--text);font:inherit;text-align:left;cursor:pointer}
.item:hover{background:rgba(255,255,255,.06)}
.item .t{display:block;font-size:14px;font-weight:500}
.item .s{display:block;font-size:12px;color:var(--muted)}
.item .ck{width:14px;height:8px;border:solid var(--accent);border-width:0 0 2px 2px;transform:rotate(-45deg) translateY(-3px);flex:none;visibility:hidden}
.item.sel .ck{visibility:visible}
.item.none .t{color:var(--muted)}
.item .n{font-size:12px;color:var(--muted);flex:none}
.hw{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--sky);margin-left:6px;vertical-align:1px}
.code{display:flex;align-items:center;gap:12px;margin-top:14px;padding:14px 16px;background:var(--bg);border:1px solid var(--line);border-radius:10px}
.code pre{margin:0;flex:1;overflow:auto;font:14px/1.5 var(--mono);white-space:pre-wrap;word-break:break-all;color:var(--text)}
.code .u{color:var(--sky)}
.code .k{color:var(--accent)}
.cmd{display:none}.cmd.on{display:flex}
.copy{flex:none;display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:8px;border:1px solid var(--line);background:var(--raised);color:var(--muted);cursor:pointer}
.copy:hover{color:var(--text);border-color:var(--line2)}
.copy svg{width:16px;height:16px}
.copy .y{display:none}.copy.ok .y{display:block;color:var(--accent)}.copy.ok .c{display:none}
.hint{color:var(--muted);font-size:13px;margin:12px 2px 0}
ol.steps{margin:0;padding:0 0 0 24px;color:var(--text)}
ol.steps li{margin:6px 0}
ol.steps b{font-weight:600}
code{font:13px var(--mono);background:rgba(255,255,255,.07);padding:2px 6px;border-radius:5px}
.faq{border-top:1px solid var(--line)}
.faq details{border-bottom:1px solid var(--line)}
.faq summary{list-style:none;display:flex;align-items:center;justify-content:space-between;gap:16px;padding:18px 2px;font-weight:600;font-size:15px;cursor:pointer}
.faq summary::-webkit-details-marker{display:none}
.faq summary .pm{position:relative;width:16px;height:16px;flex:none;color:var(--muted)}
.faq summary .pm:before,.faq summary .pm:after{content:'';position:absolute;background:currentColor;left:0;top:7px;width:16px;height:2px;border-radius:1px}
.faq summary .pm:after{transform:rotate(90deg);transition:transform .15s}
.faq details[open] summary .pm:after{transform:rotate(0)}
.faq .body{padding:0 2px 18px;color:var(--muted);font-size:15px}
.faq .body p{margin:0 0 10px}
.faq pre{margin:10px 0;padding:12px 14px;background:var(--bg);border:1px solid var(--line);border-radius:10px;font:13px/1.5 var(--mono);overflow:auto;color:var(--text)}
.keys{margin:0;padding:0;list-style:none}
.keys li{display:flex;align-items:center;gap:12px;padding:8px 0;border-top:1px solid var(--line);flex-wrap:wrap}
.keys li:first-child{border-top:0}
.tag{font-size:12px;font-weight:600;color:var(--accent);min-width:84px}
.fp{font:13px var(--mono);color:var(--text);word-break:break-all;flex:1}
.keys details{width:100%}
.keys summary{font-size:13px;color:var(--sky);cursor:pointer;list-style:none}
.keys summary::-webkit-details-marker{display:none}
.keys pre{margin:8px 0 0;font:12px/1.5 var(--mono);white-space:pre-wrap;word-break:break-all;color:var(--muted)}
footer{margin-top:72px;padding-top:28px;border-top:1px solid var(--line);display:grid;grid-template-columns:1.6fr 1fr 1fr;gap:28px;font-size:14px}
footer .fb .brand{margin-bottom:10px}
footer .fb p{color:var(--muted);margin:0;font-size:13px}
footer h4{margin:0 0 10px;font-size:14px;font-weight:600}
footer a{display:block;color:var(--muted);margin:6px 0}
footer a:hover{color:var(--text)}
.fine{grid-column:1/-1;color:var(--dim);font-size:12px;padding-top:18px;border-top:1px solid var(--line)}
@media (max-width:600px){h1{font-size:30px}.wrap{padding:20px 16px 40px}header{margin-bottom:36px}.btn{padding:0 12px}footer{grid-template-columns:1fr 1fr}footer .fb{grid-column:1/-1}.menu{min-width:220px}}
"#;

const JS: &str = r#"
(function(){
var q=function(s,r){return Array.prototype.slice.call((r||document).querySelectorAll(s))};
q('.dd').forEach(function(d){d.addEventListener('toggle',function(){if(d.open)q('.dd[open]').forEach(function(o){if(o!==d)o.removeAttribute('open')})})});
document.addEventListener('click',function(e){q('.dd[open]').forEach(function(d){if(!d.contains(e.target))d.removeAttribute('open')})});
document.addEventListener('keydown',function(e){if(e.key==='Escape')q('.dd[open]').forEach(function(d){d.removeAttribute('open')})});
q('[data-cmd]').forEach(function(b){b.addEventListener('click',function(){var k=b.getAttribute('data-cmd');
q('.cmd').forEach(function(c){c.classList.toggle('on',c.getAttribute('data-kind')===k)});
q('[data-cmd]').forEach(function(x){x.classList.toggle('sel',x===b)});
var l=document.getElementById('cmd-label');if(l)l.textContent=b.getAttribute('data-label');
var d=b.closest('.dd');if(d)d.removeAttribute('open')})});
q('[data-copy]').forEach(function(b){b.addEventListener('click',function(){var el=document.getElementById(b.getAttribute('data-copy'));if(!el)return;
var t=el.getAttribute('data-text')||el.textContent;
var done=function(){b.classList.add('ok');setTimeout(function(){b.classList.remove('ok')},1400)};
if(navigator.clipboard&&navigator.clipboard.writeText){navigator.clipboard.writeText(t).then(done,function(){})}
else{var r=document.createRange();r.selectNodeContents(el);var s=getSelection();s.removeAllRanges();s.addRange(r);try{document.execCommand('copy');done()}catch(e){}}})});
})();
"#;

const LOGO: &str = r##"<svg viewBox="0 0 64 64" aria-hidden="true"><rect width="64" height="64" rx="14" fill="#12151F"/><path d="M16 20h32v8H36v20h-8V28H16z" fill="#2BB884"/><rect x="42" y="40" width="8" height="8" rx="2" fill="#5AA9E6"/></svg>"##;

const COPY_ICON: &str = r#"<svg class="c" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg><svg class="y" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>"#;

fn document(title: &str, description: &str, body: &str, nonce: &str) -> String {
    format!(
        r##"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="theme-color" content="#0F1320">
<meta name="robots" content="noindex">
<meta name="description" content="{description}">
<title>{title}</title>
<style nonce="{nonce}">{CSS}</style>
</head>
<body><div class="wrap">
{body}
</div>
<script nonce="{nonce}">{JS}</script>
</body>
</html>
"##,
        title = escape(title),
        description = escape(description),
    )
}

fn respond(status: StatusCode, html: String, nonce: &str, cache: &'static str) -> Response {
    let csp = format!(
        "default-src 'none'; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'; \
         img-src data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    );
    let mut res = (status, html).into_response();
    let h = res.headers_mut();
    h.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static(cache));
    h.insert(header::VARY, HeaderValue::from_static("Accept"));
    h.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    h.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    if let Ok(v) = HeaderValue::from_str(&csp) {
        h.insert(header::CONTENT_SECURITY_POLICY, v);
    }
    res
}

fn header_html(server_name: &str, home_url: &str) -> String {
    format!(
        r#"<header><a class="brand" href="{home}">{LOGO}<span><b>SSH ID</b><small>SSH keys · {name}</small></span></a><a class="btn btn-primary" href="{home}">Create SSH ID with Termoso</a></header>"#,
        home = escape(home_url),
        name = escape(server_name),
    )
}

fn footer_html(home_url: &str, server_name: &str, docs_url: Option<&str>) -> String {
    let home = escape(home_url);
    let docs = match docs_url {
        Some(d) => {
            let d = escape(d);
            format!(
                r#"<a href="{d}">Documentation</a><a href="{d}/keychain/ssh-id">How SSH ID works</a>"#
            )
        }
        None => String::new(),
    };
    format!(
        r#"<footer><div class="fb"><a class="brand" href="{home}">{LOGO}<span><b>Termoso</b></span></a><p>Software should report to you, not on you.<br>Free, open source, self-hosted.</p></div>
<div><h4>Resources</h4><a href="https://github.com/termoso/termoso/releases/latest">Download</a>{docs}</div>
<div><h4>Project</h4><a href="https://github.com/termoso/termoso">GitHub</a><a href="https://github.com/termoso/termoso/issues">Issues</a><a href="https://github.com/termoso/termoso/blob/main/LICENSE">License (AGPL-3.0)</a></div>
<div class="fine">SSH ID is served by {name}. Only public keys are published — they can verify a signature, never make one.</div></footer>"#,
        name = escape(server_name),
    )
}

fn copy_btn(target: &str) -> String {
    format!(
        r#"<button class="copy" type="button" data-copy="{target}" aria-label="Copy">{COPY_ICON}</button>"#
    )
}

/// Install command card: command picker (Shell / PowerShell / URL) on the left, key type
/// picker on the right, the command underneath.
fn command_html(url: &str, type_menu: &str) -> String {
    let u = escape(url);
    format!(
        r##"<div class="card">
<div class="bar">
<details class="dd"><summary><span id="cmd-label">Shell command</span><i class="chev"></i></summary><div class="menu">
<button class="item sel" type="button" data-cmd="sh" data-label="Shell command"><span><span class="t">Shell command</span><span class="s">bash, zsh, fish — Linux, macOS, WSL</span></span><i class="ck"></i></button>
<button class="item" type="button" data-cmd="ps" data-label="PowerShell command"><span><span class="t">PowerShell command</span><span class="s">Windows OpenSSH</span></span><i class="ck"></i></button>
<button class="item" type="button" data-cmd="url" data-label="URL"><span><span class="t">URL</span><span class="s">Plain authorized_keys text</span></span><i class="ck"></i></button>
</div></details>
{type_menu}
</div>
<div class="code cmd on" data-kind="sh"><pre id="c-sh" data-text="curl -fs {u} &gt;&gt; ~/.ssh/authorized_keys"><span class="k">curl</span> -fs <span class="u">{u}</span> &gt;&gt; ~/.ssh/authorized_keys</pre>{cp_sh}</div>
<div class="code cmd" data-kind="ps"><pre id="c-ps" data-text="Invoke-RestMethod {u} | Add-Content -Encoding ascii $HOME\.ssh\authorized_keys"><span class="k">Invoke-RestMethod</span> <span class="u">{u}</span> | Add-Content -Encoding ascii $HOME\.ssh\authorized_keys</pre>{cp_ps}</div>
<div class="code cmd" data-kind="url"><pre id="c-url"><span class="u">{u}</span></pre>{cp_url}</div>
</div>"##,
        cp_sh = copy_btn("c-sh"),
        cp_ps = copy_btn("c-ps"),
        cp_url = copy_btn("c-url"),
    )
}

fn faq_item(q: &str, body: &str) -> String {
    format!(
        r#"<details><summary>{q}<i class="pm"></i></summary><div class="body">{body}</div></details>"#
    )
}

fn faq_common(url: &str, server_name: &str) -> String {
    let u = escape(url);
    let name = escape(server_name);
    let mut s = String::new();
    s.push_str(&faq_item(
        "Where did these keys come from?",
        "<p>Termoso generates an SSH key pair on every device the account is signed in on, and the owner can add FIDO2 security keys. Only the <em>public</em> halves are uploaded; private keys never leave the device or the security key.</p>",
    ));
    s.push_str(&faq_item(
        "Why are those keys accessible online?",
        "<p>A public key is meant to be shared — it can only verify a signature, never create one. Publishing them under a handle lets a server trust a <em>person</em> instead of a pasted file: one command installs every current key, and a new or lost laptop is handled by the owner in Termoso, not by editing <code>authorized_keys</code> on every host.</p>",
    ));
    s.push_str(&faq_item(
        "Why should I trust these keys?",
        &format!(
            "<p>The list is served over HTTPS by <strong>{name}</strong> and can only be changed by someone signed in to this account — protected by a password that never reaches the server and, if enabled, MFA. A device's keys are listed only while that device is signed in; signing it out or removing it withdraws its keys at once.</p><p>If the access matters, compare the fingerprints under “Which keys are published right now?” with what the owner shows you in Termoso. Like any key server, the operator of {name} could in principle serve a different list, so for high-value hosts pin the fingerprints after the first install.</p>"
        ),
    ));
    s.push_str(&faq_item(
        "What is the safest option?",
        "<p><strong>Hardware</strong> keys (ECDSA-SK, ED25519-SK): the private key is inside a FIDO2 security key and every login needs a touch, so malware on the device cannot use or copy it. Among software keys <strong>ED25519</strong> is the modern default; RSA only for hosts that cannot do better.</p>",
    ));
    s.push_str(&faq_item(
        "Keep it current with AuthorizedKeysCommand",
        &format!(
            "<p>Instead of appending once, let <code>sshd</code> fetch the list at every login so removed keys stop working immediately:</p><pre>AuthorizedKeysCommand /usr/bin/curl -fs --max-time 5 {u}\nAuthorizedKeysCommandUser nobody</pre><p>Put it in a <code>Match User</code> block in <code>sshd_config</code> and keep a local key as a fallback for when the network is down.</p>"
        ),
    ));
    s
}

fn type_item(href: &str, t: SshIdKeyType, n: usize, selected: bool) -> String {
    format!(
        r#"<a class="item{sel}{none}" href="{href}"{cur}><span><span class="t">{name}{hw}</span><span class="s">{req}</span></span><span class="n">{count}</span><i class="ck"></i></a>"#,
        sel = if selected { " sel" } else { "" },
        none = if n == 0 { " none" } else { "" },
        href = escape(href),
        cur = if selected {
            r#" aria-current="page""#
        } else {
            ""
        },
        name = label(t),
        hw = if t.is_hardware() {
            r#"<i class="hw" title="Security key"></i>"#
        } else {
            ""
        },
        req = requires(t),
        count = match n {
            0 => "no keys".to_string(),
            1 => "1 key".to_string(),
            n => format!("{n} keys"),
        },
    )
}

/// The handle page: `GET /sshid/{handle}[/{type}]` for a browser.
pub fn handle_page(p: &HandlePage<'_>) -> Response {
    let nonce = nonce();
    let handle_e = escape(p.handle);
    let base_url = format!("{}/{}", p.base, p.handle);
    let href_of = |t: SshIdKeyType| {
        if t == SshIdKeyType::Ed25519 {
            base_url.clone()
        } else {
            format!("{base_url}/{}", t.url_name())
        }
    };
    let (url, selected_name) = match p.selected {
        Some(t) => (href_of(t), label(t)),
        None => (format!("{base_url}/all"), "All types"),
    };
    let count = |t: SshIdKeyType| p.keys.iter().filter(|k| k.key_type == t).count();

    let mut menu = format!(
        r#"<details class="dd right"><summary>{selected_name}{hw}<i class="chev"></i></summary><div class="menu"><div class="grp">Hardware: security keys</div>"#,
        hw = if p.selected.is_some_and(|t| t.is_hardware()) {
            r#"<i class="hw"></i>"#
        } else {
            ""
        }
    );
    for t in [SshIdKeyType::EcdsaSk, SshIdKeyType::Ed25519Sk] {
        menu.push_str(&type_item(&href_of(t), t, count(t), p.selected == Some(t)));
    }
    menu.push_str(r#"<div class="grp">Software</div>"#);
    for t in [
        SshIdKeyType::Ed25519,
        SshIdKeyType::Ecdsa,
        SshIdKeyType::Rsa,
    ] {
        menu.push_str(&type_item(&href_of(t), t, count(t), p.selected == Some(t)));
    }
    menu.push_str(&format!(
        r#"<hr><a class="item{sel}" href="{all}"><span><span class="t">All types</span><span class="s">Every published key in one list</span></span><span class="n">{n}</span><i class="ck"></i></a></div></details>"#,
        sel = if p.selected.is_none() { " sel" } else { "" },
        all = escape(&format!("{base_url}/all")),
        n = match p.keys.len() {
            0 => "no keys".to_string(),
            1 => "1 key".to_string(),
            n => format!("{n} keys"),
        },
    ));

    let shown: Vec<&Key> = p
        .keys
        .iter()
        .filter(|k| p.selected.is_none_or(|s| s == k.key_type))
        .collect();
    let mut keys = String::new();
    if shown.is_empty() {
        keys.push_str(&format!(
            "<p>No {selected_name} keys are published right now. Device keys appear while the device is signed in to Termoso; hardware keys are added by the owner.</p>"
        ));
    } else {
        keys.push_str(&format!(
            "<p>{} {} behind the command above, with SHA256 fingerprints as <code>ssh-keygen -lf</code> prints them:</p><ul class=\"keys\">",
            shown.len(),
            if shown.len() == 1 { "key is" } else { "keys are" }
        ));
        for (i, k) in shown.iter().enumerate() {
            let fp = fingerprint(&k.public_key).unwrap_or_default();
            let line = format!("{} #SSH ID - @{}", k.public_key, p.handle);
            keys.push_str(&format!(
                r#"<li><span class="tag">{name}</span><span class="fp">{fp}</span>{cp}<details><summary>Show key</summary><pre id="k-{i}">{line}</pre></details></li>"#,
                name = label(k.key_type),
                fp = escape(&fp),
                cp = copy_btn(&format!("k-{i}")),
                line = escape(&line),
            ));
        }
        keys.push_str("</ul>");
    }

    let n_all = p.keys.len();
    let lead = if n_all == 0 {
        "SSH ID is one address for a person's SSH public keys. This one has no keys published at the moment.".to_string()
    } else {
        format!(
            "SSH ID is one address for a person's SSH public keys — every signed-in device and every security key. {n_all} {} published.",
            if n_all == 1 { "key is" } else { "keys are" }
        )
    };

    let mut faq = faq_item("Which keys are published right now?", &keys);
    faq.push_str(&faq_common(&url, p.server_name));

    let body = format!(
        r#"{header}
<h1>SSH keys of <span class="at">@{handle}</span></h1>
<p class="lead">{lead}</p>
{command}
<h2>Next steps</h2>
<ol class="steps">
<li>Run the command on the server, as the user you want to log in as: it appends the public keys to <b>~/.ssh/authorized_keys</b>.</li>
<li>Connect from any device signed in to Termoso — the matching private key is already there. For hosts that should follow the list automatically, see <b>AuthorizedKeysCommand</b> below.</li>
</ol>
<h2>Questions</h2>
<section class="faq">{faq}</section>
{footer}"#,
        header = header_html(p.server_name, p.home_url),
        handle = handle_e,
        lead = escape(&lead),
        command = command_html(&url, &menu),
        footer = footer_html(p.home_url, p.server_name, p.docs_url),
    );
    let html = document(
        &format!("@{} · SSH ID · {}", p.handle, p.server_name),
        &format!(
            "Public SSH keys of @{} published with Termoso SSH ID.",
            p.handle
        ),
        &body,
        &nonce,
    );
    respond(StatusCode::OK, html, &nonce, "public, max-age=60")
}

/// Root of the dedicated SSH ID host for a browser.
pub fn index_page(
    base: &str,
    server_name: &str,
    home_url: &str,
    docs_url: Option<&str>,
) -> Response {
    let nonce = nonce();
    let b = escape(base);
    let menu = r#"<details class="dd right"><summary>ED25519<i class="chev"></i></summary><div class="menu"><div class="grp">Append <code>/&lt;type&gt;</code> to the address</div>
<div class="item"><span><span class="t">ECDSA-SK<i class="hw"></i>, ED25519-SK<i class="hw"></i></span><span class="s">Security keys · OpenSSH 8.2+</span></span></div>
<div class="item"><span><span class="t">ED25519</span><span class="s">Default when no type is given · OpenSSH 6.5+</span></span></div>
<div class="item"><span><span class="t">ECDSA, RSA</span><span class="s">For older hosts</span></span></div>
<hr><div class="item"><span><span class="t">all</span><span class="s">Every type in one list</span></span></div></div></details>"#;
    let body = format!(
        r#"{header}
<h1>SSH ID</h1>
<p class="lead">One address for a person's SSH public keys: every device signed in to Termoso and every security key they add, as plain <code>authorized_keys</code> text.</p>
{command}
<h2>Next steps</h2>
<ol class="steps">
<li>Ask for the handle. Every Termoso account can publish one from <b>Keychain → SSH ID</b>.</li>
<li>Replace <b>&lt;handle&gt;</b> in the command and run it on the server as the user who should log in. <code>{b}/&lt;handle&gt;/&lt;type&gt;</code> narrows the list to one key type, <code>{b}/&lt;handle&gt;/all</code> returns every type.</li>
</ol>
<h2>Questions</h2>
<section class="faq">{faq}</section>
{footer}"#,
        header = header_html(server_name, home_url),
        command = command_html(&format!("{base}/<handle>"), menu),
        faq = faq_common(&format!("{base}/<handle>"), server_name),
        footer = footer_html(home_url, server_name, docs_url),
    );
    let html = document(
        &format!("SSH ID · {server_name}"),
        "Publish SSH public keys under a handle with Termoso SSH ID.",
        &body,
        &nonce,
    );
    respond(StatusCode::OK, html, &nonce, "public, max-age=300")
}

/// 404 for a browser: unknown handle or key type.
pub fn not_found_page(
    what: &str,
    server_name: &str,
    home_url: &str,
    docs_url: Option<&str>,
) -> Response {
    let nonce = nonce();
    let body = format!(
        r#"{header}
<h1>No such SSH ID</h1>
<p class="lead">{what}. Handles are 3–32 characters: letters, digits, <code>-</code> and <code>_</code>. Key types are <code>ED25519</code>, <code>ECDSA</code>, <code>RSA</code>, <code>ECDSA-SK</code>, <code>ED25519-SK</code> or <code>all</code>.</p>
{footer}"#,
        header = header_html(server_name, home_url),
        what = escape(what),
        footer = footer_html(home_url, server_name, docs_url),
    );
    let html = document(
        &format!("Not found · SSH ID · {server_name}"),
        "No such SSH ID.",
        &body,
        &nonce,
    );
    respond(StatusCode::NOT_FOUND, html, &nonce, "no-store")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn accept(v: &str) -> HeaderMap {
        let mut h = HeaderMap::new();
        h.insert(header::ACCEPT, HeaderValue::from_str(v).unwrap());
        h
    }

    #[test]
    fn browsers_get_html_tools_get_text() {
        assert!(wants_html(&accept(
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,*/*;q=0.8"
        )));
        assert!(wants_html(&accept("text/html")));
        assert!(!wants_html(&accept("*/*"))); // curl
        assert!(!wants_html(&accept("text/plain, text/html;q=0.5")));
        assert!(!wants_html(&accept("text/html;q=0, */*")));
        assert!(!wants_html(&HeaderMap::new()));
    }

    #[test]
    fn fingerprint_matches_ssh_keygen() {
        // ssh-keygen -lf on this key prints SHA256:FqZxWxsvbfbuXGgQdTzGrdE5fDxuEIdcX4nrSb73ozQ
        let key =
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb2iMX5kz3o2vS3QqL2GcyKTSaqJ3FTj2cXH1gLRXfS";
        let fp = fingerprint(key).unwrap();
        assert!(fp.starts_with("SHA256:"));
        assert_eq!(fp.len(), 7 + 43);
        assert!(fingerprint("garbage").is_none());
    }

    #[test]
    fn page_escapes_and_links() {
        let keys = [Key {
            key_type: SshIdKeyType::Ed25519,
            public_key:
                "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGb2iMX5kz3o2vS3QqL2GcyKTSaqJ3FTj2cXH1gLRXfS"
                    .into(),
        }];
        let p = HandlePage {
            handle: "alice",
            base: "https://sshid.example.com",
            selected: Some(SshIdKeyType::Ed25519),
            keys: &keys,
            server_name: "Termoso <test>",
            home_url: "https://example.com",
            docs_url: Some("https://docs.example.com"),
        };
        let res = handle_page(&p);
        assert_eq!(res.status(), StatusCode::OK);
        let csp = res.headers()[header::CONTENT_SECURITY_POLICY]
            .to_str()
            .unwrap()
            .to_string();
        assert!(csp.contains("script-src 'nonce-"));
        let body =
            futures::executor::block_on(axum::body::to_bytes(res.into_body(), usize::MAX)).unwrap();
        let html = String::from_utf8(body.to_vec()).unwrap();
        assert!(
            html.contains(
                "curl -fs https://sshid.example.com/alice &gt;&gt; ~/.ssh/authorized_keys"
            )
        );
        assert!(html.contains("https://sshid.example.com/alice/RSA"));
        assert!(html.contains("Termoso &lt;test&gt;"));
        assert!(!html.contains("<test>"));
        assert!(html.contains("SHA256:"));
    }
}
