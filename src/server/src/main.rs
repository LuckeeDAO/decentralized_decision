//! 基于比特承诺模型的去中心化投票系统 - 服务器主程序

use luckee_voting_wasm::{voting::VotingSystem, types::VotingSession};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use warp::{Filter, Rejection, Reply};
use tracing::{info, error};
use base64::Engine;

/// 服务器状态
#[derive(Clone)]
struct ServerState {
    voting_system: Arc<RwLock<VotingSystem>>,
    balances: Arc<RwLock<HashMap<String, u128>>>,
    // key: delegatee, value: list of delegator addresses
    delegations_to: Arc<RwLock<HashMap<String, Vec<String>>>>,
    // key: child, value: parent
    inheritance_parent: Arc<RwLock<HashMap<String, String>>>,
    // audit logs for permission actions
    audit_logs: Arc<RwLock<Vec<AuditEvent>>>,
}

/// API请求结构
#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    session_id: String,
    commit_deadline: u64,
    reveal_deadline: u64,
    participants: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitCommitmentRequest {
    session_id: String,
    user_id: String,
    // base64-encoded message from SDK
    message: String,
}

#[derive(Debug, Deserialize)]
struct SubmitRevealRequest {
    session_id: String,
    user_id: String,
    // base64-encoded message from SDK
    message: String,
    randomness: String,
}

/// API响应结构
#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

/// 权限等级
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum PermissionLevel {
    Basic,
    Creator,
    Admin,
}

#[derive(Debug, Deserialize)]
struct PermissionCheckRequest {
    address: String,
    min_level: PermissionLevel,
}

#[derive(Debug, Serialize)]
struct PermissionCheckResponse {
    allowed: bool,
    level: PermissionLevel,
    balance: u128,
}

#[derive(Debug, Serialize)]
struct PermissionLevelResponse {
    level: PermissionLevel,
    balance: u128,
}

#[derive(Debug, Serialize, Clone)]
struct AuditEvent {
    timestamp: u64,
    action: String,
    address: String,
    details: String,
}

#[derive(Debug, Deserialize)]
struct UpdatePermissionRequest {
    address: String,
    balance: u128,
}

#[derive(Debug, Deserialize)]
struct RevokePermissionRequest {
    address: String,
}

#[derive(Debug, Deserialize)]
struct DelegatePermissionRequest {
    from: String,
    to: String,
}

#[derive(Debug, Deserialize)]
struct InheritPermissionRequest {
    child: String,
    parent: String,
}

#[derive(Debug, Deserialize)]
struct UninheritPermissionRequest {
    child: String,
}

#[derive(Debug, Serialize)]
struct AuditListResponse {
    events: Vec<AuditEvent>,
}

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// 健康检查响应
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: u64,
    version: String,
}

/// 创建投票会话
async fn create_session(
    state: Arc<ServerState>,
    request: CreateSessionRequest,
) -> Result<impl Reply, Rejection> {
    let mut voting_system = state.voting_system.write().await;
    
    match voting_system.create_session(
        &request.session_id,
        request.commit_deadline,
        request.reveal_deadline,
        request.participants,
    ) {
        Ok(session) => {
            info!("创建投票会话成功: {}", request.session_id);
            Ok(warp::reply::json(&ApiResponse::success(session)))
        }
        Err(e) => {
            error!("创建投票会话失败: {}", e);
            Ok(warp::reply::json(&ApiResponse::<VotingSession>::error(e.to_string())))
        }
    }
}

/// 提交承诺
async fn submit_commitment(
    state: Arc<ServerState>,
    request: SubmitCommitmentRequest,
) -> Result<impl Reply, Rejection> {
    let mut voting_system = state.voting_system.write().await;
    
    // decode base64 message
    let message_bytes: Vec<u8> = match base64::engine::general_purpose::STANDARD.decode(request.message.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(warp::reply::json(&ApiResponse::<()>::error("无效的消息编码".to_string())));
        }
    };

    match voting_system.submit_commitment(
        &request.session_id,
        &request.user_id,
        &message_bytes,
    ) {
        Ok(commitment) => {
            info!("提交承诺成功: session={}, user={}", request.session_id, request.user_id);
            Ok(warp::reply::json(&ApiResponse::success(commitment)))
        }
        Err(e) => {
            error!("提交承诺失败: {}", e);
            Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string())))
        }
    }
}

/// 提交揭示
async fn submit_reveal(
    state: Arc<ServerState>,
    request: SubmitRevealRequest,
) -> Result<impl Reply, Rejection> {
    let mut voting_system = state.voting_system.write().await;
    
    // 解析随机数
    let randomness_bytes = match hex::decode(&request.randomness) {
        Ok(bytes) if bytes.len() == 32 => {
            let mut randomness = [0u8; 32];
            randomness.copy_from_slice(&bytes);
            randomness
        }
        _ => {
            return Ok(warp::reply::json(&ApiResponse::<()>::error("无效的随机数格式".to_string())));
        }
    };
    
    // decode base64 message
    let message_bytes: Vec<u8> = match base64::engine::general_purpose::STANDARD.decode(request.message.as_bytes()) {
        Ok(bytes) => bytes,
        Err(_) => {
            return Ok(warp::reply::json(&ApiResponse::<()>::error("无效的消息编码".to_string())));
        }
    };

    match voting_system.reveal_vote(
        &request.session_id,
        &request.user_id,
        &message_bytes,
        &randomness_bytes,
    ) {
        Ok(proof) => {
            info!("提交揭示成功: session={}, user={}", request.session_id, request.user_id);
            Ok(warp::reply::json(&ApiResponse::success(proof)))
        }
        Err(e) => {
            error!("提交揭示失败: {}", e);
            Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string())))
        }
    }
}

/// 获取会话信息
async fn get_session(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<impl Reply, Rejection> {
    let voting_system = state.voting_system.read().await;
    
    match voting_system.get_session(&session_id) {
        Some(session) => {
            Ok(warp::reply::json(&ApiResponse::success(session)))
        }
        None => {
            Ok(warp::reply::json(&ApiResponse::<()>::error("会话未找到".to_string())))
        }
    }
}

/// 计算投票结果
async fn calculate_results(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<impl Reply, Rejection> {
    let mut voting_system = state.voting_system.write().await;
    
    match voting_system.calculate_results(&session_id) {
        Ok(results) => {
            info!("计算投票结果成功: {}", session_id);
            Ok(warp::reply::json(&ApiResponse::success(results)))
        }
        Err(e) => {
            error!("计算投票结果失败: {}", e);
            Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string())))
        }
    }
}

/// 健康检查
async fn health_check() -> Result<impl Reply, Rejection> {
    let response = HealthResponse {
        status: "healthy".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    
    Ok(warp::reply::json(&response))
}

/// 指标端点
async fn metrics() -> Result<impl Reply, Rejection> {
    // 这里应该返回Prometheus格式的指标
    let metrics = "# HELP voting_sessions_total Total number of voting sessions\n\
                   # TYPE voting_sessions_total counter\n\
                   voting_sessions_total 0\n";
    
    Ok(warp::reply::with_header(metrics, "content-type", "text/plain; version=0.0.4; charset=utf-8"))
}

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

/// 查询地址权限等级
async fn get_permission_level(state: Arc<ServerState>, address: String) -> Result<impl Reply, Rejection> {
    let (eff_bal, level) = compute_effective_balance_and_level(&state, &address).await;
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: eff_bal })))
}

/// 检查权限
async fn check_permission(state: Arc<ServerState>, req: PermissionCheckRequest) -> Result<impl Reply, Rejection> {
    let (bal, level) = compute_effective_balance_and_level(&state, &req.address).await;
    let allowed = match (level, req.min_level) {
        (PermissionLevel::Admin, _) => true,
        (PermissionLevel::Creator, PermissionLevel::Basic) => true,
        (PermissionLevel::Creator, PermissionLevel::Creator) => true,
        (PermissionLevel::Creator, PermissionLevel::Admin) => false,
        (PermissionLevel::Basic, PermissionLevel::Basic) => true,
        (PermissionLevel::Basic, _) => false,
    };
    Ok(warp::reply::json(&ApiResponse::success(PermissionCheckResponse { allowed, level, balance: bal })))
}

/// 权限更新（设置余额，用于模拟/管理权限）
async fn update_permission(state: Arc<ServerState>, req: UpdatePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.insert(req.address.clone(), req.balance);
    let level = determine_level(req.balance);
    push_audit(&state, "update".to_string(), req.address.clone(), format!("balance={}", req.balance)).await;
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: req.balance })))
}

/// 权限撤销（将余额清零）
async fn revoke_permission(state: Arc<ServerState>, req: RevokePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.insert(req.address.clone(), 0);
    push_audit(&state, "revoke".to_string(), req.address.clone(), "balance=0".to_string()).await;
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level: PermissionLevel::Basic, balance: 0 })))
}

/// 权限委托（from -> to）
async fn delegate_permission(state: Arc<ServerState>, req: DelegatePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut delegations_to = state.delegations_to.write().await;
    let entry = delegations_to.entry(req.to.clone()).or_default();
    if !entry.contains(&req.from) {
        entry.push(req.from.clone());
    }
    push_audit(&state, "delegate".to_string(), req.to.clone(), format!("from={}", req.from)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 取消委托（from -> to）
async fn undelegate_permission(state: Arc<ServerState>, req: DelegatePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut delegations_to = state.delegations_to.write().await;
    if let Some(vec) = delegations_to.get_mut(&req.to) {
        vec.retain(|d| d != &req.from);
    }
    push_audit(&state, "undelegate".to_string(), req.to.clone(), format!("from={}", req.from)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 设置继承（child -> parent）
async fn inherit_permission(state: Arc<ServerState>, req: InheritPermissionRequest) -> Result<impl Reply, Rejection> {
    let mut inheritance_parent = state.inheritance_parent.write().await;
    inheritance_parent.insert(req.child.clone(), req.parent.clone());
    push_audit(&state, "inherit".to_string(), req.child.clone(), format!("parent={}", req.parent)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 取消继承（child）
async fn uninherit_permission(state: Arc<ServerState>, req: UninheritPermissionRequest) -> Result<impl Reply, Rejection> {
    let mut inheritance_parent = state.inheritance_parent.write().await;
    inheritance_parent.remove(&req.child);
    push_audit(&state, "uninherit".to_string(), req.child.clone(), String::new()).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 审计日志列表
async fn list_audit_logs(state: Arc<ServerState>, limit: Option<usize>) -> Result<impl Reply, Rejection> {
    let logs = state.audit_logs.read().await;
    let n = limit.unwrap_or(100);
    let start = logs.len().saturating_sub(n);
    let events = logs[start..].to_vec();
    Ok(warp::reply::json(&ApiResponse::success(AuditListResponse { events })))
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
        visiting: &mut HashSet<String>,
    ) -> (u128, PermissionLevel) {
        if !visiting.insert(address.to_string()) {
            // cycle detected, treat as basic
            return (0, PermissionLevel::Basic);
        }

        let mut balance = *balances.get(address).unwrap_or(&0);
        if let Some(from_list) = delegations_to.get(address) {
            for from in from_list.iter() {
                balance = balance.saturating_add(*balances.get(from).unwrap_or(&0));
            }
        }
        let mut level = determine_level(balance);
        if let Some(parent) = inheritance_parent.get(address) {
            let (_pb, parent_level) = compute_inner(balances, delegations_to, inheritance_parent, parent, visiting);
            level = match (level, parent_level) {
                (PermissionLevel::Admin, _) | (_, PermissionLevel::Admin) => PermissionLevel::Admin,
                (PermissionLevel::Creator, _) | (_, PermissionLevel::Creator) => PermissionLevel::Creator,
                _ => PermissionLevel::Basic,
            };
        }
        visiting.remove(address);
        (balance, level)
    }

    let mut visiting: HashSet<String> = HashSet::new();
    compute_inner(&balances, &delegations_to, &inheritance_parent, address, &mut visiting)
}

async fn push_audit(state: &Arc<ServerState>, action: String, address: String, details: String) {
    let mut logs = state.audit_logs.write().await;
    logs.push(AuditEvent {
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        action,
        address,
        details,
    });
}

/// 错误处理
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (warp::http::StatusCode::NOT_FOUND, "Not Found")
    } else if err.find::<warp::reject::PayloadTooLarge>().is_some() {
        (warp::http::StatusCode::BAD_REQUEST, "Payload too large")
    } else {
        error!("未处理的错误: {:?}", err);
        (warp::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    };
    
    let response = ApiResponse::<()>::error(message.to_string());
    Ok(warp::reply::with_status(warp::reply::json(&response), code))
}

/// 创建路由
fn create_routes(state: Arc<ServerState>) -> impl Filter<Extract = impl Reply> + Clone {
    let state_filter = warp::any().map(move || Arc::clone(&state));
    
    // 健康检查
    let health_route = warp::path("health")
        .and(warp::get())
        .and_then(health_check);
    
    // 指标端点
    let metrics_route = warp::path("metrics")
        .and(warp::get())
        .and_then(metrics);
    
    // 创建会话
    let create_session_route = warp::path("sessions")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: CreateSessionRequest, state: Arc<ServerState>| async move {
            create_session(state, request).await
        });

    // 权限等级查询
    let perm_level_route = warp::path!("permissions" / "level" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|address: String, state: Arc<ServerState>| async move { get_permission_level(state, address).await });

    // 权限检查
    let perm_check_route = warp::path!("permissions" / "check")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: PermissionCheckRequest, state: Arc<ServerState>| async move { check_permission(state, request).await });

    // 权限更新
    let perm_update_route = warp::path!("permissions" / "update")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: UpdatePermissionRequest, state: Arc<ServerState>| async move { update_permission(state, request).await });

    // 权限撤销
    let perm_revoke_route = warp::path!("permissions" / "revoke")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: RevokePermissionRequest, state: Arc<ServerState>| async move { revoke_permission(state, request).await });

    // 权限委托
    let perm_delegate_route = warp::path!("permissions" / "delegate")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: DelegatePermissionRequest, state: Arc<ServerState>| async move { delegate_permission(state, request).await });

    // 取消委托
    let perm_undelegate_route = warp::path!("permissions" / "undelegate")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: DelegatePermissionRequest, state: Arc<ServerState>| async move { undelegate_permission(state, request).await });

    // 设置继承
    let perm_inherit_route = warp::path!("permissions" / "inherit")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: InheritPermissionRequest, state: Arc<ServerState>| async move { inherit_permission(state, request).await });

    // 取消继承
    let perm_uninherit_route = warp::path!("permissions" / "uninherit")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: UninheritPermissionRequest, state: Arc<ServerState>| async move { uninherit_permission(state, request).await });

    // 审计日志
    let perm_audit_route = warp::path!("permissions" / "audit")
        .and(warp::get())
        .and(warp::query::<HashMap<String, String>>())
        .and(state_filter.clone())
        .and_then(|q: HashMap<String, String>, state: Arc<ServerState>| async move {
            let limit = q.get("limit").and_then(|v| v.parse::<usize>().ok());
            list_audit_logs(state, limit).await
        });
    
    // 获取会话
    let get_session_route = warp::path!("sessions" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|session_id: String, state: Arc<ServerState>| async move {
            get_session(state, session_id).await
        });
    
    // 提交承诺
    let submit_commitment_route = warp::path!("sessions" / String / "commitments")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|session_id: String, request: SubmitCommitmentRequest, state: Arc<ServerState>| async move {
            let mut req = request;
            req.session_id = session_id;
            submit_commitment(state, req).await
        });
    
    // 提交揭示
    let submit_reveal_route = warp::path!("sessions" / String / "reveals")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|session_id: String, request: SubmitRevealRequest, state: Arc<ServerState>| async move {
            let mut req = request;
            req.session_id = session_id;
            submit_reveal(state, req).await
        });
    
    // 计算结果
    let calculate_results_route = warp::path!("sessions" / String / "results")
        .and(warp::post())
        .and(state_filter.clone())
        .and_then(|session_id: String, state: Arc<ServerState>| async move {
            calculate_results(state, session_id).await
        });
    
    // 合并所有路由
    health_route
        .or(metrics_route)
        .or(create_session_route)
        .or(get_session_route)
        .or(submit_commitment_route)
        .or(submit_reveal_route)
        .or(calculate_results_route)
        .or(perm_level_route)
        .or(perm_check_route)
        .or(perm_update_route)
        .or(perm_revoke_route)
        .or(perm_delegate_route)
        .or(perm_undelegate_route)
        .or(perm_inherit_route)
        .or(perm_uninherit_route)
        .or(perm_audit_route)
        .recover(handle_rejection)
        .with(warp::cors().allow_any_origin())
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    info!("启动投票系统服务器...");
    
    // 创建服务器状态
    let state = Arc::new(ServerState {
        voting_system: Arc::new(RwLock::new(VotingSystem::new())),
        balances: Arc::new(RwLock::new(HashMap::new())),
        delegations_to: Arc::new(RwLock::new(HashMap::new())),
        inheritance_parent: Arc::new(RwLock::new(HashMap::new())),
        audit_logs: Arc::new(RwLock::new(Vec::new())),
    });
    
    // 创建路由
    let routes = create_routes(state);
    
    // 获取端口配置
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()?;
    
    info!("服务器启动在端口 {}", port);
    
    // 启动服务器
    warp::serve(routes)
        .run(([0, 0, 0, 0], port))
        .await;
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Reply;

    #[tokio::test]
    async fn test_health_check() {
        let _response = health_check().await.unwrap();
        // Simple test to ensure the function doesn't panic
        assert!(true);
    }

    #[tokio::test]
    async fn test_submit_commitment_decoding() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())) });

        // create a session first
        let create_req = CreateSessionRequest {
            session_id: "s1".to_string(),
            commit_deadline: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 3600,
            reveal_deadline: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs() + 7200,
            participants: vec!["u1".to_string()],
        };
        let _ = create_session(state.clone(), create_req).await.unwrap().into_response();

        // base64 message
        let msg_b64 = base64::engine::general_purpose::STANDARD.encode(b"hello");
        let req = SubmitCommitmentRequest {
            session_id: "s1".to_string(),
            user_id: "u1".to_string(),
            message: msg_b64,
        };
        let reply = submit_commitment(state.clone(), req).await.unwrap().into_response();
        assert_eq!(reply.status(), warp::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_permission_update_and_revoke() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())) });

        // update permission (balance)
        let up_req = UpdatePermissionRequest { address: "addr1".to_string(), balance: 1500 };
        let up_reply = update_permission(state.clone(), up_req).await.unwrap().into_response();
        assert_eq!(up_reply.status(), warp::http::StatusCode::OK);

        // check level should be Creator
        let check_req = PermissionCheckRequest { address: "addr1".to_string(), min_level: PermissionLevel::Creator };
        let check_reply = check_permission(state.clone(), check_req).await.unwrap().into_response();
        assert_eq!(check_reply.status(), warp::http::StatusCode::OK);

        // revoke permission (balance -> 0)
        let rv_req = RevokePermissionRequest { address: "addr1".to_string() };
        let rv_reply = revoke_permission(state.clone(), rv_req).await.unwrap().into_response();
        assert_eq!(rv_reply.status(), warp::http::StatusCode::OK);

        // check now only Basic allowed
        let check_req2 = PermissionCheckRequest { address: "addr1".to_string(), min_level: PermissionLevel::Basic };
        let check_reply2 = check_permission(state.clone(), check_req2).await.unwrap().into_response();
        assert_eq!(check_reply2.status(), warp::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn test_permission_delegation_and_inheritance() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())) });

        // set balances
        let _ = update_permission(state.clone(), UpdatePermissionRequest { address: "owner".into(), balance: 1200 }).await.unwrap();
        let _ = update_permission(state.clone(), UpdatePermissionRequest { address: "child".into(), balance: 10 }).await.unwrap();

        // delegate from owner -> addrA
        let _ = delegate_permission(state.clone(), DelegatePermissionRequest { from: "owner".into(), to: "addrA".into() }).await.unwrap();
        // addrA should reach Creator due to delegation
        let reply = get_permission_level(state.clone(), "addrA".into()).await.unwrap().into_response();
        assert_eq!(reply.status(), warp::http::StatusCode::OK);

        // inheritance: child inherits from addrA
        let _ = inherit_permission(state.clone(), InheritPermissionRequest { child: "child".into(), parent: "addrA".into() }).await.unwrap();
        let reply2 = get_permission_level(state.clone(), "child".into()).await.unwrap().into_response();
        assert_eq!(reply2.status(), warp::http::StatusCode::OK);

        // audit list available
        let resp = list_audit_logs(state.clone(), Some(10)).await.unwrap().into_response();
        assert_eq!(resp.status(), warp::http::StatusCode::OK);
    }
}
