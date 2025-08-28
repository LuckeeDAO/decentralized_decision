use crate::state::ServerState;
use crate::types::ApiResponse;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// NFT 类型状态机请求
#[derive(Debug, Deserialize)]
pub struct NftTypeStateSetRequest { 
    pub type_id: String, 
    pub state: String 
}

/// NFT 类型状态机响应
#[derive(Debug, Serialize)]
pub struct NftTypeStateGetResponse { 
    pub type_id: String, 
    pub state: Option<String> 
}

/// NFT 全局状态请求
#[derive(Debug, Deserialize)]
pub struct NftGlobalStateSetRequest { 
    pub token_id: String, 
    pub state: String 
}

/// NFT 全局状态响应
#[derive(Debug, Serialize)]
pub struct NftGlobalStateGetResponse { 
    pub token_id: String, 
    pub state: Option<String> 
}

/// NFT 全局状态回滚请求
#[derive(Debug, Deserialize)]
pub struct NftGlobalStateRollbackReq { 
    pub to_index: usize 
}

/// 工具: 获取当前秒
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// NFT 类型状态设置
pub async fn nft_type_state_set(state: Arc<ServerState>, req: NftTypeStateSetRequest) -> Result<impl Reply, Rejection> {
    let exists = { state.nft_types.read().await.get(&req.type_id).is_some() };
    if !exists { return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))); }
    state.nft_type_states.write().await.insert(req.type_id.clone(), req.state.clone());
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// NFT 类型状态获取
pub async fn nft_type_state_get(state: Arc<ServerState>, type_id: String) -> Result<impl Reply, Rejection> {
    let st = state.nft_type_states.read().await.get(&type_id).cloned();
    Ok(warp::reply::json(&ApiResponse::success(NftTypeStateGetResponse { type_id, state: st })))
}

/// NFT 全局状态转换验证
fn nft_state_can_transition(from: &str, to: &str) -> bool {
    if from == to { return true; }
    match (from, to) {
        ("", "created") => true,
        ("created", "active") => true,
        ("active", "locked") => true,
        ("locked", "active") => true,
        ("active", "burned") => true,
        ("locked", "burned") => true,
        _ => false,
    }
}

/// NFT 全局状态设置
pub async fn nft_global_state_set(state: Arc<ServerState>, req: NftGlobalStateSetRequest) -> Result<impl Reply, Rejection> {
    let cur = state.nft_global_states.read().await.get(&req.token_id).cloned().unwrap_or_default();
    if !nft_state_can_transition(cur.as_str(), req.state.as_str()) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error("非法状态转换".to_string())));
    }
    state.nft_global_states.write().await.insert(req.token_id.clone(), req.state.clone());
    // 记录历史
    let mut hist = state.nft_global_state_history.write().await;
    let entry = hist.entry(req.token_id.clone()).or_default();
    entry.push((req.state.clone(), now_secs()));
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// NFT 全局状态获取
pub async fn nft_global_state_get(state: Arc<ServerState>, token_id: String) -> Result<impl Reply, Rejection> {
    let st = state.nft_global_states.read().await.get(&token_id).cloned();
    Ok(warp::reply::json(&ApiResponse::success(NftGlobalStateGetResponse { token_id, state: st })))
}

/// NFT 全局状态历史获取
pub async fn nft_global_state_history_get(state: Arc<ServerState>, token_id: String) -> Result<impl Reply, Rejection> {
    let hist = state.nft_global_state_history.read().await;
    let list = hist.get(&token_id).cloned().unwrap_or_default();
    #[derive(Serialize)]
    struct Resp { history: Vec<(String, u64)> }
    Ok(warp::reply::json(&ApiResponse::success(Resp { history: list })))
}

/// NFT 全局状态回滚
pub async fn nft_global_state_rollback(state: Arc<ServerState>, token_id: String, req: NftGlobalStateRollbackReq) -> Result<impl Reply, Rejection> {
    let mut hist = state.nft_global_state_history.write().await;
    match hist.get_mut(&token_id) {
        Some(list) => {
            if req.to_index >= list.len() { return Ok(warp::reply::json(&ApiResponse::<()>::error("索引越界".to_string()))); }
            let target_state = list[req.to_index].0.clone();
            list.truncate(req.to_index + 1);
            state.nft_global_states.write().await.insert(token_id.clone(), target_state);
            Ok(warp::reply::json(&ApiResponse::success(())))
        }
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("无历史可回滚".to_string()))),
    }
}

/// 创建NFT状态管理路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let nft_type_state_set_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "state")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|type_id: String, body: serde_json::Value, state: Arc<ServerState>| async move {
                let state_str = body.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
                nft_type_state_set(state, NftTypeStateSetRequest { type_id, state: state_str }).await
            })
            .boxed()
    };

    let nft_type_state_get_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "state")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|type_id: String, state: Arc<ServerState>| async move { nft_type_state_get(state, type_id).await })
            .boxed()
    };

    let nft_state_set_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|req: NftGlobalStateSetRequest, state: Arc<ServerState>| async move { nft_global_state_set(state, req).await })
            .boxed()
    };

    let nft_state_get_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String)
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|token_id: String, state: Arc<ServerState>| async move { nft_global_state_get(state, token_id).await })
            .boxed()
    };

    let nft_state_history_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String / "history")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|token_id: String, state: Arc<ServerState>| async move { nft_global_state_history_get(state, token_id).await })
            .boxed()
    };

    let nft_state_rollback_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String / "rollback")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|token_id: String, req: NftGlobalStateRollbackReq, state: Arc<ServerState>| async move { nft_global_state_rollback(state, token_id, req).await })
            .boxed()
    };

    nft_type_state_set_route
        .or(nft_type_state_get_route)
        .or(nft_state_set_route)
        .or(nft_state_get_route)
        .or(nft_state_history_route)
        .or(nft_state_rollback_route)
        .boxed()
}
