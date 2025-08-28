use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::utils::with_state;
use serde::Deserialize;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use tracing::{info, error};
use base64::Engine;

/// API请求结构
#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub session_id: String,
    pub commit_deadline: u64,
    pub reveal_deadline: u64,
    pub participants: Vec<String>,
}

#[derive(Debug, Deserialize)]
pub struct SubmitCommitmentRequest {
    pub session_id: String,
    pub user_id: String,
    // base64-encoded message from SDK
    pub message: String,
}

#[derive(Debug, Deserialize)]
pub struct SubmitRevealRequest {
    pub session_id: String,
    pub user_id: String,
    // base64-encoded message from SDK
    pub message: String,
    pub randomness: String,
}

/// 创建投票会话
pub async fn create_session(
    state: Arc<ServerState>,
    request: CreateSessionRequest,
) -> Result<warp::reply::Json, Rejection> {
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
            Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string())))
        }
    }
}

/// 提交承诺
pub async fn submit_commitment(
    state: Arc<ServerState>,
    request: SubmitCommitmentRequest,
) -> Result<warp::reply::Json, Rejection> {
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
pub async fn submit_reveal(
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
pub async fn get_session(
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
pub async fn calculate_results(
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

/// 创建投票路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let create_session_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sessions")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: CreateSessionRequest, state: Arc<ServerState>| async move { create_session(state, request).await })
            .boxed()
    };

    let submit_commitment_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "commitments")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: SubmitCommitmentRequest, state: Arc<ServerState>| async move { submit_commitment(state, request).await })
            .boxed()
    };

    let submit_reveal_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "reveals")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: SubmitRevealRequest, state: Arc<ServerState>| async move { submit_reveal(state, request).await })
            .boxed()
    };

    let get_session_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sessions" / String)
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { get_session(state, session_id).await })
            .boxed()
    };

    let calculate_results_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sessions" / String / "results")
            .and(warp::post())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { calculate_results(state, session_id).await })
            .boxed()
    };

    create_session_route
        .or(submit_commitment_route)
        .or(submit_reveal_route)
        .or(get_session_route)
        .or(calculate_results_route)
        .boxed()
}
