use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use crate::utils::{with_state, push_audit};
use crate::types::{ApiResponse, QualStatusSetRequest};
use crate::state::ServerState;
use crate::routes::sync::QualStatus;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
pub struct NftTransferEvent { 
    pub token_id: String, 
    pub from: String, 
    pub to: String 
}

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let qual_set_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "qualification" / "set")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: QualStatusSetRequest, state: Arc<ServerState>| async move {
                qual_set_impl(req, state).await
            })
            .boxed()
    };

    let qual_get_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "qualification" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|token_id: String, state: Arc<ServerState>| async move {
                qual_get_impl(token_id, state).await
            })
            .boxed()
    };

    let nft_transfer_event_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "transfer" / "event")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|ev: NftTransferEvent, state: Arc<ServerState>| async move {
                transfer_event_impl(ev, state).await
            })
            .boxed()
    };

    qual_set_route
        .or(qual_get_route)
        .or(nft_transfer_event_route)
        .boxed()
}

async fn qual_set_impl(req: QualStatusSetRequest, state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let mut q = state.qualifications.write().await;
    let status = match req.status.to_lowercase().as_str() {
        "eligible" => QualStatus::Eligible,
        "suspended" => QualStatus::Suspended,
        "revoked" => QualStatus::Revoked,
        _ => return Ok(warp::reply::json(&ApiResponse::<()>::error("Invalid status value".to_string()))),
    };
    q.insert(req.token_id, status);
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn qual_get_impl(token_id: String, state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let q = state.qualifications.read().await;
    let status = q.get(&token_id).copied().unwrap_or(QualStatus::Eligible);
    Ok(warp::reply::json(&ApiResponse::success(status)))
}

async fn transfer_event_impl(ev: NftTransferEvent, state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    {
        let mut owners = state.nft_owners.write().await;
        owners.insert(ev.token_id.clone(), ev.to.clone());
    }
    {
        let mut q = state.qualifications.write().await;
        q.insert(ev.token_id.clone(), QualStatus::Eligible);
    }
    push_audit(&state, "nft_transfer".to_string(), ev.to, format!("token_id={}, from={}", ev.token_id, ev.from)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}


