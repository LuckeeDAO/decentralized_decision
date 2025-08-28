use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use crate::core::serial_numbers::{SerialService};
use crate::types::{ApiResponse, SerialAllocReq, SerialRecycleReq};
use crate::utils::with_state;
use crate::state::ServerState;

async fn serial_allocate(state: Arc<ServerState>, req: SerialAllocReq) -> Result<impl Reply, Rejection> {
    let hex_len = req.hex_len.unwrap_or(24);
    let svc: SerialService = state.serials.read().await.clone();
    match svc.allocate(req.session_id, req.owner, hex_len).await {
        Ok(r) => Ok(warp::reply::json(&ApiResponse::success(r))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

async fn serial_get(state: Arc<ServerState>, serial: String) -> Result<impl Reply, Rejection> {
    let svc: SerialService = state.serials.read().await.clone();
    let rec = svc.get(&serial).await;
    Ok(warp::reply::json(&ApiResponse::success(rec)))
}

async fn serial_recycle(state: Arc<ServerState>, req: SerialRecycleReq) -> Result<impl Reply, Rejection> {
    let svc: SerialService = state.serials.read().await.clone();
    match svc.recycle(&req.serial).await {
        Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

async fn serial_list_session(state: Arc<ServerState>, session_id: String) -> Result<impl Reply, Rejection> {
    let svc: SerialService = state.serials.read().await.clone();
    let list = svc.list_by_session(&session_id).await;
    Ok(warp::reply::json(&ApiResponse::success(list)))
}

async fn serial_stats(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let svc: SerialService = state.serials.read().await.clone();
    let s = svc.stats().await;
    Ok(warp::reply::json(&ApiResponse::success(s)))
}

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let serial_allocate_route = {
        let state = Arc::clone(&state);
        warp::path!("serials" / "allocate")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: SerialAllocReq, state: Arc<ServerState>| async move { serial_allocate(state, req).await })
            .boxed()
    };
    let serial_get_route = {
        let state = Arc::clone(&state);
        warp::path!("serials" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|serial: String, state: Arc<ServerState>| async move { serial_get(state, serial).await })
            .boxed()
    };
    let serial_recycle_route = {
        let state = Arc::clone(&state);
        warp::path!("serials" / "recycle")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: SerialRecycleReq, state: Arc<ServerState>| async move { serial_recycle(state, req).await })
            .boxed()
    };
    let serial_list_session_route = {
        let state = Arc::clone(&state);
        warp::path!("serials" / "session" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { serial_list_session(state, session_id).await })
            .boxed()
    };
    let serial_stats_route = {
        let state = Arc::clone(&state);
        warp::path!("serials" / "stats")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|state: Arc<ServerState>| async move { serial_stats(state).await })
            .boxed()
    };

    serial_allocate_route
        .or(serial_get_route)
        .or(serial_recycle_route)
        .or(serial_list_session_route)
        .or(serial_stats_route)
        .boxed()
}


