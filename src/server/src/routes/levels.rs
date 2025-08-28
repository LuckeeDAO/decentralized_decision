use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use serde::{Deserialize, Serialize};
use crate::state::ServerState;
use crate::types::{ApiResponse, PermissionLevel, now_secs};
use crate::utils::with_state;
use crate::routes::sync::AuditEvent;
use crate::core::lottery_levels::{LotteryLevel as CoreLotteryLevel, LevelStatus as CoreLevelStatus, LevelParameters, LevelPermissions, SelectionAlgorithm};

// 抽奖等级
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LotteryLevel {
    pub id: String,
    pub name: String,
    pub description: Option<String>,
    pub min_balance: u128,
    pub max_balance: Option<u128>,
    pub weight: u32,
    pub status: LevelStatus,
    pub created_at: u64,
    pub updated_at: u64,
}

// 等级状态
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum LevelStatus {
    Active,
    Inactive,
    Suspended,
}

// 等级创建请求
#[derive(Debug, Deserialize)]
pub struct LevelCreateRequest {
    pub level: LotteryLevel,
}

// 等级更新请求
#[derive(Debug, Deserialize)]
pub struct LevelUpdateRequest {
    pub level: LotteryLevel,
}

// 等级状态更新请求
#[derive(Debug, Deserialize)]
pub struct LevelStatusUpdateRequest {
    pub status: LevelStatus,
}

// 等级列表响应
#[derive(Debug, Serialize)]
pub struct LevelListResponse {
    pub levels: Vec<LotteryLevel>,
}

// 参与者资格检查响应
#[derive(Debug, Serialize)]
pub struct ParticipantEligibilityResponse {
    pub address: String,
    pub eligible: bool,
    pub level: Option<String>,
    pub reason: Option<String>,
}



// 从字符串解析权限等级
#[allow(dead_code)]
fn level_from_str(level_str: &str) -> Option<PermissionLevel> {
    match level_str.to_lowercase().as_str() {
        "basic" => Some(PermissionLevel::Basic),
        "creator" => Some(PermissionLevel::Creator),
        "admin" => Some(PermissionLevel::Admin),
        _ => None,
    }
}

// 转换 LevelStatus 到 lottery_levels::LevelStatus
impl From<LevelStatus> for CoreLevelStatus {
    fn from(status: LevelStatus) -> Self {
        match status {
            LevelStatus::Active => CoreLevelStatus::Active,
            LevelStatus::Inactive => CoreLevelStatus::Draft,
            LevelStatus::Suspended => CoreLevelStatus::Paused,
        }
    }
}

// 转换 routes::LotteryLevel 到 lottery_levels::LotteryLevel
impl From<LotteryLevel> for CoreLotteryLevel {
    fn from(level: LotteryLevel) -> Self {
        CoreLotteryLevel {
            id: level.id,
            name: level.name,
            description: level.description.unwrap_or_default(),
            priority: 0, // Default priority
            weight: level.weight as f64,
            parameters: LevelParameters {
                min_participants: 1,
                max_participants: None,
                winner_count: 1,
                selection_algorithm: SelectionAlgorithm::Random,
                algorithm_params: std::collections::HashMap::new(),
                time_limit: None,
                cost_limit: None,
            },
            permissions: LevelPermissions {
                min_balance: level.min_balance,
                min_stake: 0,
                min_holding_time: 0,
                required_nft_types: vec![],
                required_permission_level: None,
                blacklisted_addresses: vec![],
                whitelisted_addresses: vec![],
            },
            status: level.status.into(),
            created_at: level.created_at,
            updated_at: level.updated_at,
        }
    }
}

// 检查最小权限
#[allow(dead_code)]
async fn ensure_min_permission(state: &Arc<ServerState>, address: &str, min_level: PermissionLevel) -> bool {
    let balances = state.balances.read().await;
    let delegations_to = state.delegations_to.read().await;
    let inheritance_parent = state.inheritance_parent.read().await;
    
    let (_effective_balance, effective_level) = compute_effective_balance_and_level(
        address, &balances, &delegations_to, &inheritance_parent
    ).await;
    
    effective_level >= min_level
}

// 计算有效余额和等级
async fn compute_effective_balance_and_level(
    address: &str,
    balances: &std::collections::HashMap<String, u128>,
    delegations_to: &std::collections::HashMap<String, Vec<String>>,
    inheritance_parent: &std::collections::HashMap<String, String>,
) -> (u128, PermissionLevel) {
    let mut total_balance = balances.get(address).cloned().unwrap_or(0);
    
    // 添加委托的余额
    if let Some(delegations) = delegations_to.get(address) {
        for delegator in delegations {
            if let Some(delegator_balance) = balances.get(delegator) {
                total_balance += delegator_balance;
            }
        }
    }
    
    // 继承的余额
    if let Some(parent) = inheritance_parent.get(address) {
        if let Some(parent_balance) = balances.get(parent) {
            total_balance += parent_balance;
        }
    }
    
    let level = determine_level(total_balance);
    (total_balance, level)
}

// 根据余额确定等级
fn determine_level(balance: u128) -> PermissionLevel {
    match balance {
        0..=100 => PermissionLevel::Basic,
        101..=1000 => PermissionLevel::Creator,
        _ => PermissionLevel::Admin,
    }
}

// 等级创建处理
pub async fn level_create(
    state: Arc<ServerState>,
    req: LevelCreateRequest,
) -> Result<impl Reply, Rejection> {
    let mut manager = state.level_manager.write().await;
    let mut level = req.level;
    
    // 设置时间戳
    let now = now_secs();
    level.created_at = now;
    level.updated_at = now;
    
    // 创建等级
    match manager.upsert_level(level.clone().into()) {
        Ok(_) => {
            // 记录审计日志
            {
                let mut audit_log = state.audit_logs.write().await;
                audit_log.push(AuditEvent {
                    timestamp: now,
                    action: "level.create".to_string(),
                    address: "system".to_string(),
                    details: format!("创建等级: {}", level.id),
                });
            }
            
            Ok(warp::reply::json(&ApiResponse::success(level)))
        }
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(format!("{:?}", e)))),
    }
}

// 等级更新处理
pub async fn level_update(
    state: Arc<ServerState>,
    req: LevelUpdateRequest,
) -> Result<impl Reply, Rejection> {
    let mut manager = state.level_manager.write().await;
    let mut level = req.level;
    
    // 更新时间戳
    level.updated_at = now_secs();
    
    // 更新等级
    match manager.upsert_level(level.clone().into()) {
        Ok(_) => {
            // 记录审计日志
            {
                let mut audit_log = state.audit_logs.write().await;
                audit_log.push(AuditEvent {
                    timestamp: now_secs(),
                    action: "level.update".to_string(),
                    address: "system".to_string(),
                    details: format!("更新等级: {}", level.id),
                });
            }
            
            Ok(warp::reply::json(&ApiResponse::success(level)))
        }
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(format!("{:?}", e)))),
    }
}

// 等级获取处理
pub async fn level_get(
    state: Arc<ServerState>,
    level_id: String,
) -> Result<impl Reply, Rejection> {
    let manager = state.level_manager.read().await;
    
    match manager.get_level(&level_id) {
        Some(level) => Ok(warp::reply::json(&ApiResponse::success(level))),
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("等级不存在".to_string()))),
    }
}

// 等级列表处理
pub async fn level_list(
    state: Arc<ServerState>,
) -> Result<impl Reply, Rejection> {
    let manager = state.level_manager.read().await;
    let levels: Vec<LotteryLevel> = manager.get_all_levels().into_iter().map(|l| LotteryLevel {
        id: l.id.clone(),
        name: l.name.clone(),
        description: Some(l.description.clone()),
        min_balance: l.permissions.min_balance,
        max_balance: None,
        weight: l.weight as u32,
        status: match l.status {
            CoreLevelStatus::Active => LevelStatus::Active,
            CoreLevelStatus::Draft => LevelStatus::Inactive,
            CoreLevelStatus::Paused => LevelStatus::Suspended,
            CoreLevelStatus::Deprecated => LevelStatus::Inactive,
        },
        created_at: l.created_at,
        updated_at: l.updated_at,
    }).collect();
    
    Ok(warp::reply::json(&ApiResponse::success(LevelListResponse { levels })))
}

// 活跃等级列表处理
pub async fn level_list_active(
    state: Arc<ServerState>,
) -> Result<impl Reply, Rejection> {
    let manager = state.level_manager.read().await;
    let levels: Vec<LotteryLevel> = manager.get_active_levels().into_iter().map(|l| LotteryLevel {
        id: l.id.clone(),
        name: l.name.clone(),
        description: Some(l.description.clone()),
        min_balance: l.permissions.min_balance,
        max_balance: None,
        weight: l.weight as u32,
        status: match l.status {
            CoreLevelStatus::Active => LevelStatus::Active,
            CoreLevelStatus::Draft => LevelStatus::Inactive,
            CoreLevelStatus::Paused => LevelStatus::Suspended,
            CoreLevelStatus::Deprecated => LevelStatus::Inactive,
        },
        created_at: l.created_at,
        updated_at: l.updated_at,
    }).collect();
    
    Ok(warp::reply::json(&ApiResponse::success(LevelListResponse { levels })))
}

// 等级删除处理
pub async fn level_delete(
    state: Arc<ServerState>,
    level_id: String,
) -> Result<impl Reply, Rejection> {
    let mut manager = state.level_manager.write().await;
    
    if manager.delete_level(&level_id) {
        // 记录审计日志
        {
            let mut audit_log = state.audit_logs.write().await;
            audit_log.push(AuditEvent {
                timestamp: now_secs(),
                action: "level.delete".to_string(),
                address: "system".to_string(),
                details: format!("删除等级: {}", level_id),
            });
        }
        
        Ok(warp::reply::json(&ApiResponse::success(())))
    } else {
        Ok(warp::reply::json(&ApiResponse::<()>::error("等级不存在".to_string())))
    }
}

// 等级状态更新处理
pub async fn level_status_update(
    state: Arc<ServerState>,
    level_id: String,
    req: LevelStatusUpdateRequest,
) -> Result<impl Reply, Rejection> {
    let mut manager = state.level_manager.write().await;
    
    match manager.update_level_status(&level_id, req.status.into()) {
        Ok(_) => {
            // 记录审计日志
            {
                let mut audit_log = state.audit_logs.write().await;
                audit_log.push(AuditEvent {
                    timestamp: now_secs(),
                    action: "level.status_update".to_string(),
                    address: "system".to_string(),
                    details: format!("更新等级 {} 状态为: {:?}", level_id, req.status),
                });
            }
            
            Ok(warp::reply::json(&ApiResponse::success(())))
        }
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

// 参与者资格检查处理
pub async fn participant_eligibility(
    state: Arc<ServerState>,
    address: String,
) -> Result<impl Reply, Rejection> {
    let balances = state.balances.read().await;
    let delegations_to = state.delegations_to.read().await;
    let inheritance_parent = state.inheritance_parent.read().await;
    
    let (effective_balance, _effective_level) = compute_effective_balance_and_level(
        &address, &balances, &delegations_to, &inheritance_parent
    ).await;
    
    let manager = state.level_manager.read().await;
    let eligible_level = manager.get_all_levels().into_iter().find(|level| {
        level.permissions.min_balance <= effective_balance && level.status == CoreLevelStatus::Active
    });
    
    let response = ParticipantEligibilityResponse {
        address: address.clone(),
        eligible: eligible_level.is_some(),
        level: eligible_level.map(|l| l.id.clone()),
        reason: if eligible_level.is_some() {
            None
        } else {
            Some("余额不足".to_string())
        },
    };
    
    Ok(warp::reply::json(&ApiResponse::success(response)))
}

// 创建抽奖等级管理路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let level_create_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: LevelCreateRequest, state: Arc<ServerState>| async move { level_create(state, request).await })
            .boxed()
    };

    let level_update_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels" / String)
            .and(warp::put())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|_level_id: String, request: LevelUpdateRequest, state: Arc<ServerState>| async move { level_update(state, request).await })
            .boxed()
    };

    let level_get_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|level_id: String, state: Arc<ServerState>| async move { level_get(state, level_id).await })
            .boxed()
    };

    let level_list_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|state: Arc<ServerState>| async move { level_list(state).await })
            .boxed()
    };

    let level_list_active_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels" / "active")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|state: Arc<ServerState>| async move { level_list_active(state).await })
            .boxed()
    };

    let level_delete_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels" / String)
            .and(warp::delete())
            .and(with_state(state))
            .and_then(|level_id: String, state: Arc<ServerState>| async move { level_delete(state, level_id).await })
            .boxed()
    };

    let level_status_update_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "levels" / String / "status")
            .and(warp::patch())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|level_id: String, request: LevelStatusUpdateRequest, state: Arc<ServerState>| async move { level_status_update(state, level_id, request).await })
            .boxed()
    };

    let participant_eligibility_route = {
        let state = Arc::clone(&state);
        warp::path!("lottery" / "participants" / String / "eligibility")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|address: String, state: Arc<ServerState>| async move { participant_eligibility(state, address).await })
            .boxed()
    };

    level_create_route
        .or(level_update_route)
        .or(level_get_route)
        .or(level_list_route)
        .or(level_list_active_route)
        .or(level_delete_route)
        .or(level_status_update_route)
        .or(participant_eligibility_route)
        .boxed()
}
