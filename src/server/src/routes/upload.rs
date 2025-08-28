use crate::state::ServerState;
use crate::types::{ApiResponse, IpfsUploadRequest, IpfsUploadResponse, IpfsVerifyRequest, IpfsVerifyResponse, validate_basic_metadata, now_secs};
use crate::utils::with_state;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// 上传NFT元数据到IPFS
pub async fn ipfs_upload_metadata(state: Arc<ServerState>, req: IpfsUploadRequest) -> Result<impl Reply, Rejection> {
    if let Err(e) = validate_basic_metadata(&req.metadata) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error(e)));
    }
    let data = match serde_json::to_vec(&req.metadata) { 
        Ok(v) => v, 
        Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) 
    };
    let mut ipfs = state.ipfs.write().await;
    let res: Result<String, String> = ipfs.upload_data(&data).await.map_err(|e| e.to_string());
    match res {
        Ok(cid) => {
            if let Some(token_id) = req.token_id {
                let mut reg = state.metadata_versions.write().await;
                let entry = reg.entry(token_id).or_default();
                entry.push((cid.clone(), now_secs()));
            }
            Ok(warp::reply::json(&ApiResponse::success(IpfsUploadResponse { cid })))
        },
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

/// 验证NFT元数据与CID一致性
pub async fn ipfs_verify_metadata(state: Arc<ServerState>, req: IpfsVerifyRequest) -> Result<impl Reply, Rejection> {
    if let Err(e) = validate_basic_metadata(&req.metadata) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error(e)));
    }
    let data = match serde_json::to_vec(&req.metadata) { 
        Ok(v) => v, 
        Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) 
    };
    let ipfs = state.ipfs.read().await;
    let res: Result<bool, String> = ipfs.verify_data(&req.cid, &data).await.map_err(|e| e.to_string());
    match res {
        Ok(valid) => Ok(warp::reply::json(&ApiResponse::success(IpfsVerifyResponse { valid }))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

/// 读取NFT元数据
pub async fn ipfs_get_metadata(state: Arc<ServerState>, cid: String) -> Result<impl Reply, Rejection> {
    // 先读内存缓存
    if let Some((cached, _ts)) = state.metadata_cache.read().await.get(&cid).cloned() {
        return Ok(warp::reply::json(&ApiResponse::success(cached)));
    }
    
    let mut ipfs = state.ipfs.write().await;
    let res: Result<Vec<u8>, String> = ipfs.download_data(&cid).await.map_err(|e| e.to_string());
    match res {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => {
                // 写入缓存
                state.metadata_cache.write().await.insert(cid.clone(), (json.clone(), now_secs()));
                Ok(warp::reply::json(&ApiResponse::success(json)))
            },
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        },
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let ipfs_upload_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "metadata")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: IpfsUploadRequest, state: Arc<ServerState>| async move { 
                ipfs_upload_metadata(state, request).await 
            })
            .boxed()
    };

    let ipfs_verify_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "verify")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: IpfsVerifyRequest, state: Arc<ServerState>| async move { 
                ipfs_verify_metadata(state, request).await 
            })
            .boxed()
    };

    let ipfs_get_route = {
        let state = Arc::clone(&state);
        warp::path!("ipfs" / "metadata" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|cid: String, state: Arc<ServerState>| async move { 
                ipfs_get_metadata(state, cid).await 
            })
            .boxed()
    };

    ipfs_upload_route
        .or(ipfs_verify_route)
        .or(ipfs_get_route)
        .boxed()
}


