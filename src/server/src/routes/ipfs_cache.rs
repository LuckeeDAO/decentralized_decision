use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use crate::types::{ApiResponse, ImportCacheRequest};
use crate::state::ServerState;
use luckee_voting_ipfs::{export_cache as ipfs_export_fn, import_cache as ipfs_import_fn};

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let export_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "cache" / "export")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|state: Arc<ServerState>| async move { export_cache(state).await })
            .boxed()
    };

    let import_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "cache" / "import")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|request: ImportCacheRequest, state: Arc<ServerState>| async move { import_cache(state, request).await })
            .boxed()
    };

    let stats_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "cache" / "stats")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|state: Arc<ServerState>| async move { cache_stats(state).await })
            .boxed()
    };

    let clear_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "cache" / "clear")
            .and(warp::post())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|state: Arc<ServerState>| async move { cache_clear(state).await })
            .boxed()
    };

    export_route
        .or(import_route)
        .or(stats_route)
        .or(clear_route)
        .boxed()
}

async fn export_cache(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let ipfs = state.ipfs.read().await;
    let items = ipfs_export_fn(&ipfs);
    Ok(warp::reply::json(&ApiResponse::success(items)))
}

async fn import_cache(state: Arc<ServerState>, req: ImportCacheRequest) -> Result<impl Reply, Rejection> {
    let mut ipfs = state.ipfs.write().await;
    match ipfs_import_fn(&mut ipfs, req.items) {
        Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

async fn cache_stats(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let ipfs = state.ipfs.read().await;
    let size = ipfs.cache_size();
    #[derive(serde::Serialize)]
    struct CacheStats { cache_size: usize }
    Ok(warp::reply::json(&ApiResponse::success(CacheStats { cache_size: size })))
}

async fn cache_clear(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let mut ipfs = state.ipfs.write().await;
    ipfs.clear_cache();
    Ok(warp::reply::json(&ApiResponse::success(())))
}


