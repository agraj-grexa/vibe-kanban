use axum::{
    Router, body::Bytes, extract::State, http::HeaderMap, response::IntoResponse, routing::post,
};
use db::models::{
    coding_agent_turn::CodingAgentTurn,
    execution_process::{ExecutionProcess, ExecutionProcessRunReason},
    merge::Merge,
    session::{CreateSession, Session},
    workspace::Workspace,
};
use deployment::Deployment;
use executors::{
    actions::{
        ExecutorAction, ExecutorActionType, coding_agent_follow_up::CodingAgentFollowUpRequest,
        coding_agent_initial::CodingAgentInitialRequest,
    },
    profile::ExecutorConfig,
};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use services::services::container::ContainerService;
use sha2::Sha256;
use uuid::Uuid;

use crate::DeploymentImpl;

pub fn router() -> Router<DeploymentImpl> {
    Router::new().route("/webhooks/github", post(handle_webhook))
}

// ── Payload types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct GhUser {
    login: String,
    #[serde(rename = "type", default)]
    user_type: String,
}

#[derive(Deserialize)]
struct GhRepo {
    name: String,
}

#[derive(Deserialize)]
struct GhPr {
    number: i64,
}

#[derive(Deserialize)]
struct ReviewCommentPayload {
    action: String,
    comment: ReviewComment,
    pull_request: GhPr,
    repository: GhRepo,
}

#[derive(Deserialize)]
struct ReviewComment {
    body: String,
    html_url: String,
    user: GhUser,
}

#[derive(Deserialize)]
struct PullRequestReviewPayload {
    action: String,
    review: PrReview,
    pull_request: GhPr,
    repository: GhRepo,
}

#[derive(Deserialize)]
struct PrReview {
    body: Option<String>,
    state: String,
    html_url: String,
    user: GhUser,
}

// ── HMAC verification ─────────────────────────────────────────────────────────

fn verify_signature(secret: &str, signature_header: &str, body: &[u8]) -> bool {
    let hex_sig = match signature_header.strip_prefix("sha256=") {
        Some(s) => s,
        None => return false,
    };
    let sig_bytes = match hex::decode(hex_sig) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let mut mac =
        Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("HMAC accepts any key size");
    mac.update(body);
    mac.verify_slice(&sig_bytes).is_ok()
}

// ── Main handler ──────────────────────────────────────────────────────────────

pub async fn handle_webhook(
    State(deployment): State<DeploymentImpl>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    if let Ok(secret) = std::env::var("GITHUB_WEBHOOK_SECRET") {
        let sig = headers
            .get("X-Hub-Signature-256")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        if !verify_signature(&secret, sig, &body) {
            tracing::warn!("GitHub webhook: invalid signature, rejecting");
            return axum::http::StatusCode::UNAUTHORIZED.into_response();
        }
    }

    let event = headers
        .get("X-GitHub-Event")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    match event {
        "pull_request_review_comment" => handle_review_comment(&deployment, &body).await,
        "pull_request_review" => handle_review_submitted(&deployment, &body).await,
        _ => tracing::debug!("GitHub webhook: ignoring event '{}'", event),
    }

    axum::http::StatusCode::OK.into_response()
}

// ── Event handlers ────────────────────────────────────────────────────────────

async fn handle_review_comment(deployment: &DeploymentImpl, body: &[u8]) {
    let payload: ReviewCommentPayload = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                "GitHub webhook: failed to parse review_comment payload: {}",
                e
            );
            return;
        }
    };

    if payload.action != "created" {
        return;
    }
    if payload.comment.user.user_type.eq_ignore_ascii_case("Bot") {
        return;
    }

    let prompt = format!(
        "A GitHub PR review comment was left on PR #{pr} in repository `{repo}` by @{user}.\n\n\
         Comment URL: {url}\n\nComment:\n{body}\n\n\
         Please address this review comment by making the necessary code changes, \
         then commit and push the changes.",
        pr = payload.pull_request.number,
        repo = payload.repository.name,
        user = payload.comment.user.login,
        url = payload.comment.html_url,
        body = payload.comment.body,
    );

    trigger_pr_comment_follow_up(
        deployment,
        payload.pull_request.number,
        &payload.repository.name,
        &prompt,
    )
    .await;
}

async fn handle_review_submitted(deployment: &DeploymentImpl, body: &[u8]) {
    let payload: PullRequestReviewPayload = match serde_json::from_slice(body) {
        Ok(p) => p,
        Err(e) => {
            tracing::warn!(
                "GitHub webhook: failed to parse pull_request_review payload: {}",
                e
            );
            return;
        }
    };

    if payload.action != "submitted" {
        return;
    }
    if payload.review.user.user_type.eq_ignore_ascii_case("Bot") {
        return;
    }

    let review_body = match payload
        .review
        .body
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    {
        Some(b) => b.to_string(),
        None => {
            tracing::debug!("GitHub webhook: ignoring review with empty body");
            return;
        }
    };

    let prompt = format!(
        "A GitHub PR review was submitted on PR #{pr} in repository `{repo}` by @{user} \
         (state: {state}).\n\nReview URL: {url}\n\nReview:\n{body}\n\n\
         Please address the feedback in this review by making the necessary code changes, \
         then commit and push the changes.",
        pr = payload.pull_request.number,
        repo = payload.repository.name,
        user = payload.review.user.login,
        state = payload.review.state,
        url = payload.review.html_url,
        body = review_body,
    );

    trigger_pr_comment_follow_up(
        deployment,
        payload.pull_request.number,
        &payload.repository.name,
        &prompt,
    )
    .await;
}

// ── Core trigger ──────────────────────────────────────────────────────────────

async fn trigger_pr_comment_follow_up(
    deployment: &DeploymentImpl,
    pr_number: i64,
    repo_name: &str,
    prompt: &str,
) {
    let pool = &deployment.db().pool;

    let workspace_id =
        match Merge::find_workspace_by_pr_number_and_repo_name(pool, pr_number, repo_name).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                tracing::info!(
                    "GitHub webhook: no open workspace for PR #{} in repo '{}'",
                    pr_number,
                    repo_name
                );
                return;
            }
            Err(e) => {
                tracing::error!("GitHub webhook: DB error finding workspace: {}", e);
                return;
            }
        };

    let workspace = match Workspace::find_by_id(pool, workspace_id).await {
        Ok(Some(w)) => w,
        Ok(None) => {
            tracing::warn!("GitHub webhook: workspace {} not found", workspace_id);
            return;
        }
        Err(e) => {
            tracing::error!("GitHub webhook: failed to load workspace: {}", e);
            return;
        }
    };

    let session = match Session::find_latest_by_workspace_id(pool, workspace.id).await {
        Ok(Some(s)) => s,
        Ok(None) => {
            match Session::create(
                pool,
                &CreateSession { executor: None },
                Uuid::new_v4(),
                workspace.id,
            )
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("GitHub webhook: failed to create session: {}", e);
                    return;
                }
            }
        }
        Err(e) => {
            tracing::error!("GitHub webhook: failed to load session: {}", e);
            return;
        }
    };

    let executor_profile_id =
        match ExecutionProcess::latest_executor_profile_for_session(pool, session.id).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                tracing::warn!(
                    "GitHub webhook: no executor profile for session {}, skipping",
                    session.id
                );
                return;
            }
            Err(e) => {
                tracing::error!("GitHub webhook: failed to get executor profile: {}", e);
                return;
            }
        };

    let latest_session_info =
        match CodingAgentTurn::find_latest_session_info(pool, session.id).await {
            Ok(info) => info,
            Err(e) => {
                tracing::error!("GitHub webhook: failed to get session info: {}", e);
                return;
            }
        };

    let working_dir = workspace
        .agent_working_dir
        .as_ref()
        .filter(|d| !d.is_empty())
        .cloned();

    let action_type = if let Some(info) = latest_session_info {
        ExecutorActionType::CodingAgentFollowUpRequest(CodingAgentFollowUpRequest {
            prompt: prompt.to_string(),
            session_id: info.session_id,
            reset_to_message_id: None,
            executor_config: ExecutorConfig::from(executor_profile_id),
            working_dir,
        })
    } else {
        ExecutorActionType::CodingAgentInitialRequest(CodingAgentInitialRequest {
            prompt: prompt.to_string(),
            executor_config: ExecutorConfig::from(executor_profile_id),
            working_dir,
        })
    };

    let action = ExecutorAction::new(action_type, None);

    match deployment
        .container()
        .start_execution(
            &workspace,
            &session,
            &action,
            &ExecutionProcessRunReason::CodingAgent,
        )
        .await
    {
        Ok(_) => tracing::info!(
            "GitHub webhook: triggered agent for PR #{} in workspace {}",
            pr_number,
            workspace_id
        ),
        Err(e) => tracing::error!("GitHub webhook: failed to start execution: {}", e),
    }
}
