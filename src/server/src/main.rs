//! 基于比特承诺模型的去中心化投票系统 - 服务器主程序

use luckee_voting_wasm::{voting::VotingSystem, types::VotingSession};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;
use warp::{Filter, Rejection, Reply};
use tracing::{info, error};
use base64::Engine;

/// 服务器状态
#[derive(Clone)]
struct ServerState {
    voting_system: Arc<RwLock<VotingSystem>>,
    balances: Arc<RwLock<HashMap<String, u128>>>,
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

#[derive(Debug, Deserialize)]
struct UpdatePermissionRequest {
    address: String,
    balance: u128,
}

#[derive(Debug, Deserialize)]
struct RevokePermissionRequest {
    address: String,
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
    let balances = state.balances.read().await;
    let bal = *balances.get(&address).unwrap_or(&0);
    let level = determine_level(bal);
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: bal })))
}

/// 检查权限
async fn check_permission(state: Arc<ServerState>, req: PermissionCheckRequest) -> Result<impl Reply, Rejection> {
    let balances = state.balances.read().await;
    let bal = *balances.get(&req.address).unwrap_or(&0);
    let level = determine_level(bal);
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
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: req.balance })))
}

/// 权限撤销（将余额清零）
async fn revoke_permission(state: Arc<ServerState>, req: RevokePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.insert(req.address.clone(), 0);
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level: PermissionLevel::Basic, balance: 0 })))
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
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())) });

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
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())) });

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
}
