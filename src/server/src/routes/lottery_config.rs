use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use crate::state::ServerState;
use crate::types::{ApiResponse, LotteryConfigStoreRequest, LotteryConfigRollbackRequest, LotteryConfigStoreResponse, LotteryConfigVersionsResponse, SchemaValidateResponse};
use crate::utils::with_state;
use jsonschema::{JSONSchema, Draft};

// 获取当前时间戳
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// 抽奖配置存储处理 - 完整版本
pub async fn lottery_config_store(
    state: Arc<ServerState>,
    req: LotteryConfigStoreRequest,
) -> Result<impl Reply, Rejection> {
    // 先按类型Schema校验
    {
        let reg = state.nft_types.read().await;
        let def = match reg.get(&req.type_id) { 
            Some(d) => d, 
            None => return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))) 
        };
        let schema = match def.versions.last() { 
            Some(v) => v.schema.clone(), 
            None => return Ok(warp::reply::json(&ApiResponse::<()>::error("类型未包含schema".to_string()))) 
        };
        match JSONSchema::options().with_draft(Draft::Draft7).compile(&schema) {
            Ok(compiled) => if let Err(errors) = compiled.validate(&req.config) {
                let errs = errors.map(|e| e.to_string()).collect::<Vec<_>>();
                return Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: errs })))
            },
            Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        }
    }
    
    // 插件钩子：进一步业务校验
    if let Some(plugin) = state.nft_type_plugins.read().await.get(&req.type_id) {
        if let Err(e) = plugin.on_before_store_config(&req.config) {
            return Ok(warp::reply::json(&ApiResponse::<()>::error(e)));
        }
    }
    
    let data = match serde_json::to_vec(&req.config) { 
        Ok(v) => v, 
        Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) 
    };
    
    let cid = {
        let mut ipfs = state.ipfs.write().await;
        match ipfs.upload_data(&data).await { 
            Ok(cid) => cid, 
            Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) 
        }
    };
    
    // 存储版本信息
    let version = {
        let mut configs = state.lottery_configs.write().await;
        let entry = configs.entry(req.config_id.clone()).or_default();
        let version = entry.len() as u32 + 1;
        entry.push((version, cid.clone(), now_secs()));
        version
    };
    
    Ok(warp::reply::json(&ApiResponse::success(LotteryConfigStoreResponse { cid, version })))
}

// 抽奖配置回滚处理
pub async fn lottery_config_rollback(
    state: Arc<ServerState>,
    config_id: String,
    req: LotteryConfigRollbackRequest,
) -> Result<impl Reply, Rejection> {
    let mut configs = state.lottery_configs.write().await;
    let entry = match configs.get_mut(&config_id) {
        Some(e) => e,
        None => return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到配置".to_string()))),
    };
    
    // 找到目标版本
    let target_index = entry.iter().position(|(v, _, _)| *v == req.version);
    match target_index {
        Some(idx) => {
            // 移除后续版本
            entry.truncate(idx + 1);
            Ok(warp::reply::json(&ApiResponse::success(())))
        },
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("未找到目标版本".to_string()))),
    }
}

// 抽奖配置版本列表
pub async fn lottery_config_versions(
    state: Arc<ServerState>,
    config_id: String,
) -> Result<impl Reply, Rejection> {
    let configs = state.lottery_configs.read().await;
    let versions = configs.get(&config_id).cloned().unwrap_or_default();
    Ok(warp::reply::json(&ApiResponse::success(LotteryConfigVersionsResponse { items: versions })))
}

// 抽奖配置获取
pub async fn lottery_config_get(
    state: Arc<ServerState>,
    config_id: String,
    version: Option<u32>,
) -> Result<impl Reply, Rejection> {
    let configs = state.lottery_configs.read().await;
    let versions = match configs.get(&config_id) {
        Some(v) => v,
        None => return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到配置".to_string()))),
    };
    
    let target_version = match version {
        Some(v) => versions.iter().find(|(ver, _, _)| *ver == v),
        None => versions.last(),
    };
    
    match target_version {
        Some((ver, cid, ts)) => {
            let config_data = {
                let mut ipfs = state.ipfs.write().await;
                match ipfs.download_data(cid).await {
                    Ok(data) => match serde_json::from_slice::<serde_json::Value>(&data) {
                        Ok(json) => json,
                        Err(_) => return Ok(warp::reply::json(&ApiResponse::<()>::error("配置数据格式错误".to_string()))),
                    },
                    Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
                }
            };
            
            #[derive(serde::Serialize)]
            struct ConfigResponse {
                version: u32,
                cid: String,
                timestamp: u64,
                config: serde_json::Value,
            }
            
            Ok(warp::reply::json(&ApiResponse::success(ConfigResponse {
                version: *ver,
                cid: cid.clone(),
                timestamp: *ts,
                config: config_data,
            })))
        },
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("未找到目标版本".to_string()))),
    }
}

// 创建抽奖配置路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let store_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "config" / "store")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: LotteryConfigStoreRequest, state: Arc<ServerState>| async move {
                lottery_config_store(state, req).await
            })
            .boxed()
    };

    let rollback_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "config" / String / "rollback")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|config_id: String, req: LotteryConfigRollbackRequest, state: Arc<ServerState>| async move {
                lottery_config_rollback(state, config_id, req).await
            })
            .boxed()
    };

    let versions_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "config" / String / "versions")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|config_id: String, state: Arc<ServerState>| async move {
                lottery_config_versions(state, config_id).await
            })
            .boxed()
    };

    let get_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "config" / String)
            .and(warp::get())
            .and(warp::query::<std::collections::HashMap<String, String>>())
            .and(with_state(state))
            .and_then(|config_id: String, q: std::collections::HashMap<String, String>, state: Arc<ServerState>| async move {
                let version = q.get("version").and_then(|v| v.parse::<u32>().ok());
                lottery_config_get(state, config_id, version).await
            })
            .boxed()
    };

    store_route
        .or(rollback_route)
        .or(versions_route)
        .or(get_route)
        .boxed()
}
