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

  println!("DEBUG JSON: {}", String::from_utf8_lossy(&body));
  wlog("info", "Received a new request");

  // C. Parse JSON based on event
  match event {
    "push" => {
      // Parse the raw bytes into your struct
      if let Ok(payload) = serde_json::from_slice::<PushEvent>(&body) {
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
        wlog("info", "Unknown push event");
      }
    }
    _ => wlog("info", &format!("Received unhandled event: {}", event)),
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
