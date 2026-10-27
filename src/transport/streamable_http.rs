use crate::transport::stdio::StdioProxy;
use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use std::sync::Arc;
use tracing::warn;

pub struct StreamableHttpServer {
    proxy: Arc<StdioProxy>,
    allowed_origins: Vec<String>,
}

impl StreamableHttpServer {
    pub fn new(proxy: Arc<StdioProxy>, allowed_origins: Vec<String>) -> Self {
        Self {
            proxy,
            allowed_origins,
        }
    }

    pub fn router(self: Arc<Self>) -> Router {
        Router::new()
            .route("/mcp", post(handle_mcp_post))
            .with_state(self)
    }

    /// Verifies the Origin header against allowed list to prevent DNS Rebinding attacks
    pub fn verify_origin(&self, headers: &HeaderMap) -> bool {
        if let Some(origin_val) = headers.get("origin") {
            if let Ok(origin_str) = origin_val.to_str() {
                let clean = origin_str.trim().to_lowercase();
                // Allow localhost / 127.0.0.1 variants and explicitly configured origins
                if clean.starts_with("http://localhost")
                    || clean.starts_with("http://127.0.0.1")
                    || clean.starts_with("vscode-webview://")
                    || clean.starts_with("cursor://")
                    || self
                        .allowed_origins
                        .iter()
                        .any(|o| clean == o.to_lowercase())
                {
                    return true;
                }
                warn!(
                    "DNS Rebinding Defense: Blocked unauthorized Origin: {}",
                    origin_str
                );
                return false;
            }
        }
        // If no Origin header (e.g. direct CLI / curl / local agent process), permit
        true
    }
}

async fn handle_mcp_post(
    State(server): State<Arc<StreamableHttpServer>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    // 1. DNS Rebinding origin verification
    if !server.verify_origin(&headers) {
        return (StatusCode::FORBIDDEN, "Forbidden: Invalid Origin header").into_response();
    }

    // 2. Decode body
    let raw_req = match String::from_utf8(body.to_vec()) {
        Ok(s) => s,
        Err(_) => return (StatusCode::BAD_REQUEST, "Invalid UTF-8 payload").into_response(),
    };

    // 3. Process request through mcp-lock proxy logic
    match server.proxy.handle_client_to_server(&raw_req).await {
        Ok(Some(resp_json)) => (
            StatusCode::OK,
            [("Content-Type", "application/json")],
            resp_json,
        )
            .into_response(),
        Ok(None) => (StatusCode::NO_CONTENT, "").into_response(),
        Err(e) => {
            warn!("Streamable HTTP Proxy error: {}", e);
            (
                StatusCode::BAD_REQUEST,
                [("Content-Type", "application/json")],
                serde_json::json!({
                    "jsonrpc": "2.0",
                    "error": {
                        "code": -32001,
                        "message": e.to_string()
                    }
                })
                .to_string(),
            )
                .into_response()
        }
    }
}
