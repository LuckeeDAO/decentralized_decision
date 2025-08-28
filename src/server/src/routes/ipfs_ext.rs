use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use base64::Engine;

use crate::types::ApiResponse;
use crate::state::ServerState;
use crate::utils::with_state;

#[derive(Debug, serde::Deserialize)]
struct IpfsCompressionReq { enabled: bool }
#[derive(Debug, serde::Deserialize)]
struct IpfsAddMirrorReq { url: String }
#[derive(Debug, serde::Deserialize)]
struct IpfsArchiveReq { path: String }
#[derive(Debug, serde::Deserialize)]
struct IpfsRestoreReq { path: String }
#[derive(Debug, serde::Deserialize)]
struct IpfsConsistencyReq { cid: String, data_b64: Option<String> }

async fn ipfs_set_compression(state: Arc<ServerState>, req: IpfsCompressionReq) -> Result<impl Reply, Rejection> {
    let mut ipfs = state.ipfs.write().await;
    ipfs.set_compression(req.enabled);
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn ipfs_add_mirror(state: Arc<ServerState>, req: IpfsAddMirrorReq) -> Result<impl Reply, Rejection> {
    let mut ipfs = state.ipfs.write().await;
    match ipfs.add_mirror(&req.url).await {
        Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

async fn ipfs_archive(state: Arc<ServerState>, req: IpfsArchiveReq) -> Result<impl Reply, Rejection> {
    let ipfs = state.ipfs.read().await;
    match ipfs.archive_to_file(&req.path) {
        Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

async fn ipfs_restore(state: Arc<ServerState>, req: IpfsRestoreReq) -> Result<impl Reply, Rejection> {
    let mut ipfs = state.ipfs.write().await;
    match ipfs.restore_from_file(&req.path) {
        Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

async fn ipfs_consistency(state: Arc<ServerState>, req: IpfsConsistencyReq) -> Result<impl Reply, Rejection> {
    let data_opt = match req.data_b64 {
        Some(b64) => base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).ok(),
        None => None,
    };
    let ipfs = state.ipfs.read().await;
    let map = ipfs.consistency_check(&req.cid, data_opt.as_deref()).await;
    Ok(warp::reply::json(&ApiResponse::success(map)))
}

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let ipfs_compress_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "compression")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: IpfsCompressionReq, state: Arc<ServerState>| async move { ipfs_set_compression(state, req).await })
            .boxed()
    };
    let ipfs_add_mirror_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "mirror")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: IpfsAddMirrorReq, state: Arc<ServerState>| async move { ipfs_add_mirror(state, req).await })
            .boxed()
    };
    let ipfs_archive_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "archive")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: IpfsArchiveReq, state: Arc<ServerState>| async move { ipfs_archive(state, req).await })
            .boxed()
    };
    let ipfs_restore_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "restore")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: IpfsRestoreReq, state: Arc<ServerState>| async move { ipfs_restore(state, req).await })
            .boxed()
    };
    let ipfs_consistency_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "consistency")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: IpfsConsistencyReq, state: Arc<ServerState>| async move { ipfs_consistency(state, req).await })
            .boxed()
    };

    ipfs_compress_route
        .or(ipfs_add_mirror_route)
        .or(ipfs_archive_route)
        .or(ipfs_restore_route)
        .or(ipfs_consistency_route)
        .boxed()
}


