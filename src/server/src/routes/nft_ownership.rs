use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use serde::{Deserialize, Serialize};
use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::utils::with_state;


// 原有的简单 NFT 所有权请求结构
#[derive(Debug, Deserialize)]
pub struct NftRegisterOwnershipRequest {
    pub token_id: String,
    pub owner: String,
}

#[derive(Debug, Deserialize)]
pub struct NftCheckOwnershipRequest {
    pub token_id: String,
    pub address: String,
}

#[derive(Debug, Serialize)]
pub struct NftCheckOwnershipResponse {
    pub is_owner: bool,
    pub owner: Option<String>,
}

// NFT 注册请求
#[derive(Debug, Deserialize)]
pub struct NftRegisterRequest {
    pub nft_id: String,
    pub owner_address: String,
    #[allow(dead_code)]
    pub nft_type: String,
    #[allow(dead_code)]
    pub metadata: serde_json::Value,
}

// NFT 检查响应
#[derive(Debug, Serialize)]
pub struct NftCheckResponse {
    pub exists: bool,
    pub owner_address: Option<String>,
    pub nft_type: Option<String>,
    pub registration_time: Option<u64>,
}

// NFT 状态设置请求
#[derive(Debug, Deserialize)]
pub struct NftStateSetRequest {
    #[allow(dead_code)]
    pub nft_id: String,
    pub state: String,
    #[allow(dead_code)]
    pub metadata: Option<serde_json::Value>,
}

// NFT 状态获取响应
#[derive(Debug, Serialize)]
pub struct NftStateGetResponse {
    pub nft_id: String,
    pub state: String,
    pub metadata: Option<serde_json::Value>,
    pub last_updated: u64,
}

// NFT 状态历史响应
#[derive(Debug, Serialize)]
pub struct NftStateHistoryResponse {
    pub nft_id: String,
    pub history: Vec<NftStateHistoryItem>,
}

#[derive(Debug, Serialize)]
pub struct NftStateHistoryItem {
    pub state: String,
    pub metadata: Option<serde_json::Value>,
    pub timestamp: u64,
}

// NFT 状态回滚请求
#[derive(Debug, Deserialize)]
pub struct NftStateRollbackRequest {
    #[allow(dead_code)]
    pub nft_id: String,
    pub target_timestamp: u64,
}

// 获取当前时间戳
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

// 从请求头获取地址
fn header_address() -> Result<String, Rejection> {
    // 这里应该实现从请求头获取地址的逻辑
    // 暂时返回一个默认值
    Ok("default_address".to_string())
}

// 原有的简单 NFT 所有权注册函数
pub async fn nft_register_ownership(
    state: Arc<ServerState>,
    req: NftRegisterOwnershipRequest,
) -> Result<impl Reply, Rejection> {
    let mut owners = state.nft_owners.write().await;
    owners.insert(req.token_id.clone(), req.owner.clone());
    
    // 记录审计日志
    {
        let mut audit_log = state.audit_logs.write().await;
        audit_log.push(crate::routes::sync::AuditEvent {
            timestamp: now_secs(),
            action: "nft_register".to_string(),
            address: req.owner.clone(),
            details: format!("token_id={}", req.token_id),
        });
    }
    
    Ok(warp::reply::json(&ApiResponse::success(())))
}

// 原有的简单 NFT 所有权检查函数
pub async fn nft_check_ownership(
    state: Arc<ServerState>,
    req: NftCheckOwnershipRequest,
) -> Result<impl Reply, Rejection> {
    let owners = state.nft_owners.read().await;
    let owner = owners.get(&req.token_id).cloned();
    let is_owner = owner.as_deref() == Some(req.address.as_str());
    Ok(warp::reply::json(&ApiResponse::success(NftCheckOwnershipResponse { is_owner, owner })))
}

// NFT 注册处理
pub async fn nft_register(
    state: Arc<ServerState>,
    request: NftRegisterRequest,
) -> Result<impl Reply, Rejection> {
    let owner_address = header_address()?;
    
    // 检查权限 - 这里需要实现权限检查逻辑
    // 暂时跳过权限检查
    
    // 检查 NFT 是否已存在
    let nft_owners = state.nft_owners.read().await;
    if nft_owners.contains_key(&request.nft_id) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error("NFT 已存在".to_string())));
    }
    drop(nft_owners);
    
    // 注册 NFT
    {
        let mut nft_owners = state.nft_owners.write().await;
        nft_owners.insert(request.nft_id.clone(), request.owner_address.clone());
    }
    
    // 存储元数据版本
    {
        let mut metadata_versions = state.metadata_versions.write().await;
        let entry = metadata_versions.entry(request.nft_id.clone()).or_default();
        entry.push(("".to_string(), now_secs())); // 空的CID，实际应该存储到IPFS
    }
    
    // 记录审计日志
    {
        let mut audit_log = state.audit_logs.write().await;
        audit_log.push(crate::routes::sync::AuditEvent {
            timestamp: now_secs(),
            action: "nft.register".to_string(),
            address: owner_address,
            details: format!("注册 NFT: {}", request.nft_id),
        });
    }
    
    Ok(warp::reply::json(&ApiResponse::success(request.nft_id)))
}

// NFT 检查处理
pub async fn nft_check(
    state: Arc<ServerState>,
    nft_id: String,
) -> Result<impl Reply, Rejection> {
    let nft_owners = state.nft_owners.read().await;
    
    if let Some(owner_address) = nft_owners.get(&nft_id) {
        let metadata_versions = state.metadata_versions.read().await;
        
        let registration_time = metadata_versions.get(&nft_id)
            .and_then(|versions| versions.last())
            .map(|(_, timestamp)| *timestamp);
        
        Ok(warp::reply::json(&ApiResponse::success(NftCheckResponse {
            exists: true,
            owner_address: Some(owner_address.clone()),
            nft_type: None, // 暂时设为None，因为nft_types中没有按token_id存储
            registration_time,
        })))
    } else {
        Ok(warp::reply::json(&ApiResponse::success(NftCheckResponse {
            exists: false,
            owner_address: None,
            nft_type: None,
            registration_time: None,
        })))
    }
}

// NFT 状态设置处理
pub async fn nft_state_set(
    state: Arc<ServerState>,
    nft_id: String,
    request: NftStateSetRequest,
) -> Result<impl Reply, Rejection> {
    let owner_address = header_address()?;
    
    // 检查权限 - 这里需要实现权限检查逻辑
    // 暂时跳过权限检查
    
    // 检查 NFT 是否存在
    let nft_owners = state.nft_owners.read().await;
    if !nft_owners.contains_key(&nft_id) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error("NFT 不存在".to_string())));
    }
    drop(nft_owners);
    
    // 设置状态
    {
        let mut nft_global_states = state.nft_global_states.write().await;
        nft_global_states.insert(nft_id.clone(), request.state.clone());
    }
    
    // 记录状态历史
    {
        let mut nft_global_state_history = state.nft_global_state_history.write().await;
        let entry = nft_global_state_history.entry(nft_id.clone()).or_default();
        entry.push((request.state.clone(), now_secs()));
    }
    
    // 记录审计日志
    {
        let mut audit_log = state.audit_logs.write().await;
        audit_log.push(crate::routes::sync::AuditEvent {
            timestamp: now_secs(),
            action: "nft.state.set".to_string(),
            address: owner_address,
            details: format!("设置 NFT {} 状态为: {}", nft_id, request.state),
        });
    }
    
    Ok(warp::reply::json(&ApiResponse::success(nft_id)))
}

// NFT 状态获取处理
pub async fn nft_state_get(
    state: Arc<ServerState>,
    nft_id: String,
) -> Result<impl Reply, Rejection> {
    let nft_global_states = state.nft_global_states.read().await;
    
    if let Some(state_value) = nft_global_states.get(&nft_id) {
        let nft_global_state_history = state.nft_global_state_history.read().await;
        
        let last_updated = nft_global_state_history.get(&nft_id)
            .and_then(|history| history.last())
            .map(|(_, timestamp)| *timestamp)
            .unwrap_or(0);
        
        Ok(warp::reply::json(&ApiResponse::success(NftStateGetResponse {
            nft_id,
            state: state_value.clone(),
            metadata: None, // 暂时设为None，因为metadata没有单独存储
            last_updated,
        })))
    } else {
        Ok(warp::reply::json(&ApiResponse::<()>::error("NFT 状态不存在".to_string())))
    }
}

// NFT 状态历史处理
pub async fn nft_state_history(
    state: Arc<ServerState>,
    nft_id: String,
) -> Result<impl Reply, Rejection> {
    // 获取状态历史记录
    let nft_global_state_history = state.nft_global_state_history.read().await;
    
    let history = if let Some(history_entries) = nft_global_state_history.get(&nft_id) {
        history_entries.iter()
            .map(|(state_value, timestamp)| NftStateHistoryItem {
                state: state_value.clone(),
                metadata: None, // 暂时设为None，因为metadata没有单独存储
                timestamp: *timestamp,
            })
            .collect()
    } else {
        Vec::new()
    };
    
    Ok(warp::reply::json(&ApiResponse::success(NftStateHistoryResponse {
        nft_id,
        history,
    })))
}

// NFT 状态回滚处理
pub async fn nft_state_rollback(
    state: Arc<ServerState>,
    nft_id: String,
    request: NftStateRollbackRequest,
) -> Result<impl Reply, Rejection> {
    let owner_address = header_address()?;
    
    // 检查权限 - 这里需要实现权限检查逻辑
    // 暂时跳过权限检查
    
    // 这里应该实现状态回滚逻辑
    // 目前返回成功，需要扩展 ServerState 来支持状态历史
    
    // 记录审计日志
    {
        let mut audit_log = state.audit_logs.write().await;
        audit_log.push(crate::routes::sync::AuditEvent {
            timestamp: now_secs(),
            action: "nft.state.rollback".to_string(),
            address: owner_address,
            details: format!("回滚 NFT {} 状态到时间: {}", nft_id, request.target_timestamp),
        });
    }
    
    Ok(warp::reply::json(&ApiResponse::success(nft_id)))
}

// 创建 NFT 所有权相关路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    // 原有的简单 NFT 所有权路由
    let nft_register_ownership_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "ownership" / "register")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: NftRegisterOwnershipRequest, state: Arc<ServerState>| async move { nft_register_ownership(state, request).await })
            .boxed()
    };

    let nft_check_ownership_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "ownership" / "check")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: NftCheckOwnershipRequest, state: Arc<ServerState>| async move { nft_check_ownership(state, request).await })
            .boxed()
    };

    // 新的复杂 NFT 管理路由
    let nft_register_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "register")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: NftRegisterRequest, state: Arc<ServerState>| async move { nft_register(state, request).await })
            .boxed()
    };

    let nft_check_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "check" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|nft_id: String, state: Arc<ServerState>| async move { nft_check(state, nft_id).await })
            .boxed()
    };

    let nft_state_set_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|nft_id: String, request: NftStateSetRequest, state: Arc<ServerState>| async move { nft_state_set(state, nft_id, request).await })
            .boxed()
    };

    let nft_state_get_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|nft_id: String, state: Arc<ServerState>| async move { nft_state_get(state, nft_id).await })
            .boxed()
    };

    let nft_state_history_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String / "history")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|nft_id: String, state: Arc<ServerState>| async move { nft_state_history(state, nft_id).await })
            .boxed()
    };

    let nft_state_rollback_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "state" / String / "rollback")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|nft_id: String, request: NftStateRollbackRequest, state: Arc<ServerState>| async move { nft_state_rollback(state, nft_id, request).await })
            .boxed()
    };

    nft_register_ownership_route
        .or(nft_check_ownership_route)
        .or(nft_register_route)
        .or(nft_check_route)
        .or(nft_state_set_route)
        .or(nft_state_get_route)
        .or(nft_state_history_route)
        .or(nft_state_rollback_route)
        .boxed()
}
