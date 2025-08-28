use std::sync::Arc;
use warp::Filter;

use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::core::audit::{generate_report, AuditReport};

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl warp::Reply,)> {
    let state_filter = warp::any().map(move || Arc::clone(&state));

    let report = warp::path!("audit" / "report")
        .and(warp::get())
        .and(state_filter)
        .and_then(handle_report);

    report.boxed()
}

async fn handle_report(state: Arc<ServerState>) -> Result<impl warp::Reply, warp::Rejection> {
    let events = state.serials.read().await.audit_logs().await;
    let report: AuditReport = generate_report(&events);
    Ok(warp::reply::json(&ApiResponse::success(report)))
}


