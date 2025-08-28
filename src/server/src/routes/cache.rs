use crate::state::ServerState;
use crate::types::{ApiResponse, now_secs};
use serde::Serialize;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// 缓存统计信息
#[derive(Serialize)]
struct CacheStats {
    memory_cache_size: usize,
    memory_cache_keys: Vec<String>,
}

/// 缓存预热结果
#[derive(Serialize)]
struct WarmupResult { 
    warmed_count: usize 
}

/// 缓存管理处理函数
pub async fn cache_management_handler(state: Arc<ServerState>, action: String) -> Result<impl Reply, Rejection> {
    match action.as_str() {
        "stats" => {
            let mem_cache = state.metadata_cache.read().await;
            let mem_size = mem_cache.len();
            let mem_keys: Vec<String> = mem_cache.keys().cloned().collect();
            
            Ok(warp::reply::json(&ApiResponse::success(CacheStats {
                memory_cache_size: mem_size,
                memory_cache_keys: mem_keys,
            })))
        },
        "clear" => {
            // 清空内存缓存
            state.metadata_cache.write().await.clear();
            
            Ok(warp::reply::json(&ApiResponse::success(())))
        },
        "warmup" => {
            // 缓存预热：从IPFS加载热门数据到缓存
            let popular_cids = vec![
                "bafy-popular-1".to_string(),
                "bafy-popular-2".to_string(),
            ];
            
            let mut warmed = 0;
            for cid in popular_cids {
                if let Ok(_) = ipfs_get_metadata(state.clone(), cid).await {
                    warmed += 1;
                }
            }
            
            Ok(warp::reply::json(&ApiResponse::success(WarmupResult { warmed_count: warmed })))
        },
        _ => Ok(warp::reply::json(&ApiResponse::<()>::error("未知的缓存操作".to_string()))),
    }
}

/// 读取NFT元数据（用于缓存预热）
async fn ipfs_get_metadata(state: Arc<ServerState>, cid: String) -> Result<impl Reply, Rejection> {
    // 先读内存缓存
    if let Some((cached, _ts)) = state.metadata_cache.read().await.get(&cid).cloned() {
        return Ok(warp::reply::json(&ApiResponse::success(cached)));
    }
    
    // 从IPFS读取
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

/// 创建缓存管理路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let cache_management_route = {
        let state = Arc::clone(&state);
        warp::path!("cache" / String)
            .and(warp::post())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|action: String, state: Arc<ServerState>| async move { 
                cache_management_handler(state, action).await 
            })
            .boxed()
    };

    cache_management_route
}
