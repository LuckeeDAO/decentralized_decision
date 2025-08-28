use crate::state::ServerState;
use crate::types::{ApiResponse, PermissionLevel, UpdatePermissionRequest, RevokePermissionRequest, DelegatePermissionRequest, InheritPermissionRequest, UninheritPermissionRequest, PermissionLevelResponse, PermissionCheckRequest, PermissionCheckResponse};

use crate::utils::{with_state, push_audit};
use std::collections::HashMap;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// 计算权限等级
fn determine_level(balance: u128) -> PermissionLevel {
    let admin_threshold: u128 = std::env::var("PERM_ADMIN_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let creator_threshold: u128 = std::env::var("PERM_CREATOR_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000);
    if balance >= admin_threshold {
        PermissionLevel::Admin
    } else if balance >= creator_threshold {
        PermissionLevel::Creator
    } else {
        PermissionLevel::Basic
    }
}

/// 计算有效余额和等级（考虑委托与继承）
async fn compute_effective_balance_and_level(state: &Arc<ServerState>, address: &str) -> (u128, PermissionLevel) {
    let balances = state.balances.read().await;
    let delegations_to = state.delegations_to.read().await;
    let inheritance_parent = state.inheritance_parent.read().await;

    fn compute_inner(
        balances: &HashMap<String, u128>,
        delegations_to: &HashMap<String, Vec<String>>,
        inheritance_parent: &HashMap<String, String>,
        address: &str,
        visiting: &mut std::collections::HashSet<String>,
    ) -> (u128, PermissionLevel) {
        if !visiting.insert(address.to_string()) {
            // cycle detected, treat as basic
            return (0, PermissionLevel::Basic);
        }

        let mut balance = *balances.get(address).unwrap_or(&0);
        if let Some(from_list) = delegations_to.get(address) {
            for from in from_list {
                let (delegated_balance, _) = compute_inner(balances, delegations_to, inheritance_parent, from, visiting);
                balance = balance.saturating_add(delegated_balance);
            }
        }
        if let Some(parent) = inheritance_parent.get(address) {
            let (inherited_balance, _) = compute_inner(balances, delegations_to, inheritance_parent, parent, visiting);
            balance = balance.saturating_add(inherited_balance);
        }
        (balance, determine_level(balance))
    }

    let mut visiting = std::collections::HashSet::new();
    compute_inner(&balances, &delegations_to, &inheritance_parent, address, &mut visiting)
}

/// 更新权限
pub async fn update_permission(
    state: Arc<ServerState>,
    req: UpdatePermissionRequest,
) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.insert(req.address.clone(), req.balance);
    
    push_audit(&state, "update_permission".to_string(), req.address.clone(), format!("balance={}", req.balance)).await;
    
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 撤销权限
pub async fn revoke_permission(
    state: Arc<ServerState>,
    req: RevokePermissionRequest,
) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.remove(&req.address);
    
    push_audit(&state, "revoke_permission".to_string(), req.address.clone(), "permission revoked".to_string()).await;
    
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 委托权限
pub async fn delegate_permission(
    state: Arc<ServerState>,
    req: DelegatePermissionRequest,
) -> Result<impl Reply, Rejection> {
    let mut delegations_to = state.delegations_to.write().await;
    let entry = delegations_to.entry(req.to.clone()).or_default();
    if !entry.contains(&req.from) {
        entry.push(req.from.clone());
    }
    
    push_audit(&state, "delegate_permission".to_string(), req.from.clone(), format!("delegated to {}", req.to)).await;
    
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 继承权限
pub async fn inherit_permission(
    state: Arc<ServerState>,
    req: InheritPermissionRequest,
) -> Result<impl Reply, Rejection> {
    let mut inheritance_parent = state.inheritance_parent.write().await;
    inheritance_parent.insert(req.child.clone(), req.parent.clone());
    
    push_audit(&state, "inherit_permission".to_string(), req.child.clone(), format!("inherited from {}", req.parent)).await;
    
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 取消继承
pub async fn uninherit_permission(
    state: Arc<ServerState>,
    req: UninheritPermissionRequest,
) -> Result<impl Reply, Rejection> {
    let mut inheritance_parent = state.inheritance_parent.write().await;
    inheritance_parent.remove(&req.child);
    
    push_audit(&state, "uninherit_permission".to_string(), req.child.clone(), "inheritance removed".to_string()).await;
    
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 获取权限等级
pub async fn get_permission_level(
    state: Arc<ServerState>,
    address: String,
) -> Result<impl Reply, Rejection> {
    let (balance, level) = compute_effective_balance_and_level(&state, &address).await;
    
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse {
        level,
        balance,
    })))
}

/// 检查权限
pub async fn check_permission(
    state: Arc<ServerState>,
    req: PermissionCheckRequest,
) -> Result<impl Reply, Rejection> {
    let (balance, level) = compute_effective_balance_and_level(&state, &req.address).await;
    
    Ok(warp::reply::json(&ApiResponse::success(PermissionCheckResponse {
        allowed: level >= req.min_level,
        level,
        balance,
    })))
}

/// 创建权限管理路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let update_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "update")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: UpdatePermissionRequest, state: Arc<ServerState>| async move {
                update_permission(state, req).await
            })
            .boxed()
    };

    let revoke_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "revoke")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: RevokePermissionRequest, state: Arc<ServerState>| async move {
                revoke_permission(state, req).await
            })
            .boxed()
    };

    let delegate_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "delegate")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: DelegatePermissionRequest, state: Arc<ServerState>| async move {
                delegate_permission(state, req).await
            })
            .boxed()
    };

    let inherit_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "inherit")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: InheritPermissionRequest, state: Arc<ServerState>| async move {
                inherit_permission(state, req).await
            })
            .boxed()
    };

    let uninherit_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "uninherit")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: UninheritPermissionRequest, state: Arc<ServerState>| async move {
                uninherit_permission(state, req).await
            })
            .boxed()
    };

    let get_level_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "level" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|address: String, state: Arc<ServerState>| async move {
                get_permission_level(state, address).await
            })
            .boxed()
    };

    let check_route = {
        let state = Arc::clone(&state);
        warp::path!("permissions" / "check")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|req: PermissionCheckRequest, state: Arc<ServerState>| async move {
                check_permission(state, req).await
            })
            .boxed()
    };

    update_route
        .or(revoke_route)
        .or(delegate_route)
        .or(inherit_route)
        .or(uninherit_route)
        .or(get_level_route)
        .or(check_route)
        .boxed()
}


