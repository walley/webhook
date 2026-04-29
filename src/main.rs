use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    routing::post,
    Router,
};
use hmac::{Hmac, Mac};
use sha2::Sha256;
//use std::process::Command;
use tokio::process::Command as AsyncCommand;

type HmacSha256 = Hmac<Sha256>;

struct AppState {
    webhook_secret: String,
}

#[tokio::main]
async fn main() {
    // Load your secret from an environment variable (Required for security!)
    let secret = std::env::var("WEBHOOK_SECRET").expect("WEBHOOK_SECRET must be set");
    let shared_state = std::sync::Arc::new(AppState { webhook_secret: secret });

    let app = Router::new()
        .route("/webhook", post(webhook_handler))
        .with_state(shared_state);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000").await.unwrap();
    println!("Server listening on http://0.0.0.0:3000");
    axum::serve(listener, app).await.unwrap();
}

async fn webhook_handler(
    headers: HeaderMap,
    State(state): State<std::sync::Arc<AppState>>,
    body: Bytes,
) -> StatusCode {
    // 1. Verify Signature
    if !verify_signature(&state.webhook_secret, &headers, &body) {
        return StatusCode::FORBIDDEN;
    }

    // 2. Identify Event Type and create an OWNED string
    // By calling .to_string(), we create a copy that can live inside the spawn block
    let event = headers.get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("unknown")
        .to_string(); 

    println!("Received event: {}", event);

    // 3. Map Event to Script
    let script_path = match event.as_str() {
        "push" => Some("/usr/local/bin/github-push.sh"),
        "pull_request" => Some("/usr/local/bin/github-pr.sh"),
        _ => None,
    };

    if let Some(script) = script_path {
        let script = script.to_string(); // Make script path owned too!
        
        // Run the script asynchronously
        tokio::spawn(async move {
            let output = AsyncCommand::new(script)
                .arg(&event) // Pass the owned string
                .output()
                .await;

            match output {
                Ok(out) => println!("Script executed. Status: {}", out.status),
                Err(e) => eprintln!("Failed to execute script: {}", e),
            }
        });
        StatusCode::OK
    } else {
        StatusCode::NO_CONTENT
    }
}

fn verify_signature(secret: &str, headers: &HeaderMap, body: &[u8]) -> bool {
    let signature = match headers.get("X-Hub-Signature-256") {
        Some(s) => s.to_str().unwrap_or(""),
        None => return false,
    };

    // GitHub sends signature as "sha256=..."
    let signature = signature.strip_prefix("sha256=").unwrap_or("");
    
    let mut mac = HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC can take key of any size");
    mac.update(body);
    
    let result = mac.finalize().into_bytes();
    let hex_result = hex::encode(result);

    hex_result == signature
}