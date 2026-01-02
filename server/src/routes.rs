use std::sync::Arc;

use admin::{add_challenge, remove_challenge};
use axum::{
    Router,
    routing::{delete, get, patch, post},
};
use challenge::{
    get_challenge, get_proof_of_work_challenge, process_accessibility_challenge, process_challenge,
    process_pre_analysis,
};
use console::{
    add_challenge_to_api_key_pool, create_console, delete_console, gen_api_key,
    get_api_key_challenge_pool, get_api_keys, get_consoles, remove_challenge_from_api_key_pool,
    revoke_api_key, update_api_key, update_console,
};
use middleware::{
    block_bot_agent, require_admin, require_auth, validate_api_key, validate_console_id,
};
use verification::site_verify;

use crate::{
    AppState,
    routes::{
        challenge::get_all_challenges,
        console::{get_challenge_preferences, update_challenge_preferences},
        middleware::validate_hostname,
    },
};

pub mod admin;
pub mod challenge;
pub mod console;
pub mod custom_headers;
mod errors;
pub mod extractors;
pub mod middleware;
pub mod verification;

/// Router for challenge endpoints.
pub fn challenge(state: &Arc<AppState>) -> Router {
    let state = Arc::clone(state);
    Router::new()
        .route("/", get(get_challenge))
        .route("/all", get(get_all_challenges))
        .route("/proof-of-work", get(get_proof_of_work_challenge))
        .merge(
            Router::new()
                .route("/process", post(process_challenge))
                .route("/process-pre-analysis", post(process_pre_analysis))
                .route(
                    "/process-accessibility",
                    post(process_accessibility_challenge),
                )
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&state),
                    validate_hostname,
                )),
        )
        .layer(axum::middleware::from_fn(block_bot_agent))
        .with_state(state)
}

/// Router for verification endpoints.
pub fn verification(state: &Arc<AppState>) -> Router {
    let state = Arc::clone(state);
    Router::new()
        .route("/siteverify", post(site_verify))
        .layer(axum::middleware::from_fn(block_bot_agent))
        .with_state(state)
}

/// Router for console endpoints.
pub fn console(state: &Arc<AppState>) -> Router {
    let state = Arc::clone(state);

    let challenge_pool = Router::new()
        .route("/", get(get_api_key_challenge_pool))
        .route("/", post(add_challenge_to_api_key_pool))
        .route("/", delete(remove_challenge_from_api_key_pool));

    let api_key = Router::new()
        .route("/", get(get_api_keys))
        .route("/", post(gen_api_key))
        .nest(
            "/{site_key}",
            Router::new()
                .route("/", patch(update_api_key))
                .route("/", delete(revoke_api_key))
                .nest("/challenge-pool", challenge_pool)
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&state),
                    validate_api_key,
                )),
        );

    let challenge_preferences = Router::new()
        .route("/", get(get_challenge_preferences))
        .route("/", patch(update_challenge_preferences));

    Router::new()
        .route("/", get(get_consoles))
        .route("/", post(create_console))
        .nest(
            "/{console_id}",
            Router::new()
                .route("/", patch(update_console))
                .route("/", delete(delete_console))
                .nest("/api-key", api_key)
                .nest("/challenge-preferences", challenge_preferences)
                .layer(axum::middleware::from_fn_with_state(
                    Arc::clone(&state),
                    validate_console_id,
                )),
        )
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state(state)
}

/// Router for admin endpoints.
pub fn admin(state: &Arc<AppState>) -> Router {
    let state = Arc::clone(state);
    Router::new()
        .route("/challenge", post(add_challenge))
        .route("/challenge", delete(remove_challenge))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            require_admin,
        ))
        .layer(axum::middleware::from_fn_with_state(
            Arc::clone(&state),
            require_auth,
        ))
        .with_state(state)
}
