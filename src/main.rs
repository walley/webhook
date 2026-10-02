//walley 2026

use axum::{
  Router,
  body::Bytes,
  extract::State,
  http::{HeaderMap, StatusCode},
  routing::post,
};
use hmac::{Hmac, Mac};
use log::{LevelFilter, debug, error, info, warn};
use serde::Deserialize;
use sha2::Sha256;
use std::process;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use syslog::{BasicLogger, Facility, Formatter3164};
use tokio::process::Command as AsyncCommand;

const FACILITY: Facility = Facility::LOG_LOCAL6;

fn timestamp() -> u64 {
  SystemTime::now()
    .duration_since(UNIX_EPOCH)
    .expect("Time went backwards")
    .as_secs()
}

fn wlog(level: &str, message: &str) {
  // Convert to String inside here so we own the data before passing it to the thread
  let level = level.to_string();
  let message = message.to_string();

  tokio::task::spawn_blocking(move || {
    // 1. Perform the logging
    match level.as_str() {
      "info" => info!("{}", message),
      "warn" | "warning" => warn!("{}", message),
      "error" => error!("{}", message),
      "debug" => debug!("{}", message),
      _ => info!("{}", message),
    }

    // 2. Perform the println!
    let ts = timestamp();
    println!("{} {} {}", ts, level, message);
  });
}

type HmacSha256 = Hmac<Sha256>;

struct AppState {
  webhook_secret: String,
}

// 1. Define the structure of the data you want to extract
#[derive(Deserialize, Debug)]
struct PushEvent {
  #[serde(rename = "ref")]
  reference: String,
  repository: Repository,
}

#[derive(Deserialize, Debug)]
struct Repository {
  name: String,
}

async fn webhook_handler(
  headers: HeaderMap,
  State(state): State<Arc<AppState>>,
  body: Bytes,
) -> StatusCode {
  let allowed_branches = ["refs/heads/main", "refs/heads/master", "refs/heads/github"];

  // A. Verify Signature (Must be done on raw bytes)
  if !verify_signature(&state.webhook_secret, &headers, &body) {
    wlog("info", "Signature error.");
    return StatusCode::FORBIDDEN;
  }

  // B. Identify Event
  let event = headers
    .get("X-GitHub-Event")
    .and_then(|v| v.to_str().ok())
    .unwrap_or("unknown");

  // C. Decode form-encoded deliveries. Signature above was verified against the
  //    raw bytes, so decoding happens only after that check has passed.
  let payload = decode_form_payload(&headers, &body).unwrap_or_else(|| body.to_vec());

  println!("DEBUG JSON: {}", String::from_utf8_lossy(&payload));
  wlog("info", "Received a new request");

  // D. Parse JSON based on event
  match event {
    "push" => {
      // Parse the decoded bytes into your struct
      if let Ok(payload) = serde_json::from_slice::<PushEvent>(&payload) {
        wlog(
          "info",
          &format!(
            "Push to {} in repo {}",
            payload.reference, payload.repository.name,
          ),
        );
        // You can now pass this info to your script
        let is_prod_branch = allowed_branches.contains(&payload.reference.as_str());

        if is_prod_branch {
          wlog("info", "Executing hook ...");
          run_script("/usr/local/bin/github-push.sh", &payload.repository.name).await;
        } else {
          wlog("info", "Forbiden branch");
        }
      } else {
        let ts = timestamp();
        let filename = format!("/tmp/{}.payload", ts);

        // Serialize headers to a simple text block (mark non-UTF8 values)
        let header_dump = headers
          .iter()
          .map(|(k, v)| format!("{}: {}", k.as_str(), v.to_str().unwrap_or("<non-utf8>")))
          .collect::<Vec<_>>()
          .join("\n");

        // Take ownership of the decoded body bytes
        let body_bytes = payload;

        // Clone filename before moving it into the closure
        let filename_for_logging = filename.clone();

        tokio::task::spawn_blocking(move || {
          use std::io::Write;
          match std::fs::File::create(&filename) {
            Ok(mut f) => {
              let _ = writeln!(
                f,
                "Timestamp: {}\n\nHeaders:\n{}\n\nBody (URL-decoded):\n",
                ts, header_dump
              );
              let _ = f.write_all(&body_bytes);
            }
            Err(e) => {
              eprintln!("Failed to create payload file {}: {}", filename, e);
            }
          }
        });

        wlog(
          "info",
          &format!(
            "Push event with unparseable payload — dumped to {}",
            filename_for_logging
          ),
        );
      }
    }
    _ => {
      wlog(
        "info",
        &format!(
          "Received unhandled event: {} | Payload: {}",
          event,
          String::from_utf8_lossy(&payload)
        ),
      );
    }
  }

  StatusCode::OK
}

// Helper to run scripts
async fn run_script(script: &str, arg: &str) {
  let script = script.to_string();
  let arg = arg.to_string();
  tokio::spawn(async move {
    let _ = AsyncCommand::new(script).arg(arg).output().await;
  });
}

// GitHub can deliver webhooks as application/x-www-form-urlencoded, in which
// case the JSON arrives as a percent-encoded `payload` form field. Returns the
// decoded JSON bytes, or None when the body is plain JSON.
fn decode_form_payload(headers: &HeaderMap, body: &[u8]) -> Option<Vec<u8>> {
  let is_form = headers
    .get("content-type")
    .and_then(|v| v.to_str().ok())
    .is_some_and(|ct| ct.starts_with("application/x-www-form-urlencoded"));

  // Only sniff the body when it is not declared as JSON. A raw JSON body may
  // legitimately contain `&payload=` inside a string value, and parsing that
  // would silently replace the real payload.
  if !is_form && !body.starts_with(b"payload=") {
    return None;
  }

  form_urlencoded::parse(body)
    .find(|(key, _)| key == "payload")
    .map(|(_, value)| value.into_owned().into_bytes())
}

fn verify_signature(secret: &str, headers: &HeaderMap, body: &[u8]) -> bool {
  let signature = match headers.get("X-Hub-Signature-256") {
    Some(s) => s.to_str().unwrap_or(""),
    None => return false,
  };
  let signature = signature.strip_prefix("sha256=").unwrap_or("");
  let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC error");
  mac.update(body);
  hex::encode(mac.finalize().into_bytes()) == signature
}

#[cfg(test)]
mod tests {
  use super::*;
  use axum::http::HeaderValue;

  fn headers(content_type: &str) -> HeaderMap {
    let mut h = HeaderMap::new();
    h.insert("content-type", HeaderValue::from_str(content_type).unwrap());
    h
  }

  const FORM: &str = "application/x-www-form-urlencoded";

  // Trimmed from a real GitHub push delivery that was dumped to /tmp
  // undecoded: content-type form-urlencoded, event push, ref refs/heads/github.
  // Note "Update+YO%21" -- GitHub encodes spaces as '+', so a decoder that
  // only handles %XX would yield "Update+YO! to YO!".
  const REAL_ENCODED: &str = "payload=%7B%22ref%22%3A%22refs%2Fheads%2Fgithub%22%2C%22repository%22%3A%7B%22name%22%3A%22kiscal%22%7D%2C%22message%22%3A%22Update+YO%21%22%7D";

  #[test]
  fn decodes_real_form_encoded_push_into_parseable_json() {
    let out = decode_form_payload(&headers(FORM), REAL_ENCODED.as_bytes()).unwrap();
    let json = String::from_utf8(out).unwrap();
    assert_eq!(
      json,
      r#"{"ref":"refs/heads/github","repository":{"name":"kiscal"},"message":"Update YO!"}"#
    );

    // The decoded bytes must now satisfy the push parser, which is the whole
    // point: before the fix this failed and got dumped to /tmp instead.
    let parsed: PushEvent = serde_json::from_slice(json.as_bytes()).unwrap();
    assert_eq!(parsed.reference, "refs/heads/github");
    assert_eq!(parsed.repository.name, "kiscal");
  }

  #[test]
  fn plus_is_decoded_as_space() {
    let out = decode_form_payload(&headers(FORM), b"payload=a+b").unwrap();
    assert_eq!(out, b"a b");
  }

  #[test]
  fn leaves_plain_json_body_untouched() {
    let body = br#"{"ref":"refs/heads/main","repository":{"name":"webhook"}}"#;
    assert_eq!(
      decode_form_payload(&headers("application/json"), body),
      None
    );
  }

  #[test]
  fn does_not_extract_payload_from_inside_a_json_string() {
    // A JSON body may contain "&payload=" in a value; treating it as a form
    // field would silently swap the real payload for attacker-chosen data.
    let body = br#"{"ref":"refs/heads/main","repository":{"name":"x&payload=evil"},"more":1}"#;
    assert_eq!(
      decode_form_payload(&headers("application/json"), body),
      None
    );

    // A declared form content-type is authoritative: the body is read as a
    // form, so `payload` is whatever follows that key. This cannot be abused
    // because the signature is checked against the raw bytes first.
    let forced = decode_form_payload(&headers(FORM), body).unwrap();
    assert_eq!(String::from_utf8(forced).unwrap(), r#"evil"},"more":1}"#);
  }

  #[test]
  fn returns_none_when_form_body_has_no_payload_key() {
    assert_eq!(decode_form_payload(&headers(FORM), b"other=1"), None);
  }

  #[test]
  fn signature_is_verified_against_raw_encoded_bytes() {
    let secret = "Kokot1234x,";
    let mut h = HeaderMap::new();
    let sig = {
      let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).unwrap();
      mac.update(REAL_ENCODED.as_bytes());
      format!("sha256={}", hex::encode(mac.finalize().into_bytes()))
    };
    h.insert("X-Hub-Signature-256", HeaderValue::from_str(&sig).unwrap());

    // Signing the decoded body must not verify -- the signature covers the
    // raw wire bytes, so decoding must stay strictly after verification.
    assert!(verify_signature(secret, &h, REAL_ENCODED.as_bytes()));
    let decoded = decode_form_payload(&headers(FORM), REAL_ENCODED.as_bytes()).unwrap();
    assert!(!verify_signature(secret, &h, &decoded));
  }
}

#[tokio::main]
async fn main() {
  let formatter = Formatter3164 {
    facility: FACILITY,
    hostname: None,
    process: "github-webhook".into(),
    pid: 0,
  };

  // Connect logger to syslog
  let logger = syslog::unix(formatter).unwrap_or_else(|e| {
    eprintln!("Error: Could not connect to syslog: {}", e);
    process::exit(2);
  });

  // Install logger globally
  log::set_boxed_logger(Box::new(BasicLogger::new(logger))).expect("Could not set logger");
  log::set_max_level(LevelFilter::Debug);

  let secret = std::env::var("WEBHOOK_SECRET").expect("WEBHOOK_SECRET must be set");
  let shared_state = Arc::new(AppState {
    webhook_secret: secret,
  });

  let app = Router::new()
    .route("/webhook", post(webhook_handler))
    .with_state(shared_state);

  let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
  wlog("info", "Server listening on http://0.0.0.0:3000");
  axum::serve(listener, app).await.unwrap();
}
