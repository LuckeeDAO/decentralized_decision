use std::convert::Infallible;
use std::sync::Arc;
use warp::Filter;

use crate::state::ServerState;

pub fn with_state(state: Arc<ServerState>) -> impl Filter<Extract = (Arc<ServerState>,), Error = Infallible> + Clone {
    warp::any().map(move || Arc::clone(&state))
}

pub async fn push_audit(state: &Arc<ServerState>, action: String, address: String, details: String) {
    let mut audit_log = state.audit_logs.write().await;
    audit_log.push(crate::routes::sync::AuditEvent {
        timestamp: crate::types::now_secs(),
        action,
        address,
        details,
    });
}


