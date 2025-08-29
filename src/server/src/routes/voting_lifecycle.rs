//! 投票生命周期管理API路由
//!
//! 实现第五阶段的投票流程管理接口

use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::utils::with_state;
use serde::Deserialize;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use tracing::{info, error};

use crate::core::voting_lifecycle::{
    CreateVotingFlowRequest, VotingPhaseConfig, VotingStatus
};

/// 创建投票流程请求
#[derive(Debug, Deserialize)]
pub struct CreateVotingFlowApiRequest {
    pub session_id: String,
    pub title: String,
    pub description: String,
    pub commit_start_time: u64,
    pub commit_end_time: u64,
    pub reveal_start_time: u64,
    pub reveal_end_time: u64,
    pub buffer_time: u64,
    pub min_participants: usize,
    pub max_participants: Option<usize>,
    pub participants: Vec<String>,
    pub creator: String,
    pub nft_type: String,
    pub metadata: serde_json::Value,
}

/// 创建投票流程
pub async fn create_voting_flow(
    state: Arc<ServerState>,
    request: CreateVotingFlowApiRequest,
) -> Result<warp::reply::Json, Rejection> {
    // 构建投票阶段配置
    let phase_config = VotingPhaseConfig {
        commit_start_time: request.commit_start_time,
        commit_end_time: request.commit_end_time,
        reveal_start_time: request.reveal_start_time,
        reveal_end_time: request.reveal_end_time,
        buffer_time: request.buffer_time,
        min_participants: request.min_participants,
        max_participants: request.max_participants,
    };
    
    // 构建创建请求
    let create_request = CreateVotingFlowRequest {
        session_id: request.session_id.clone(),
        title: request.title,
        description: request.description,
        phase_config,
        participants: request.participants,
        creator: request.creator,
        nft_type: request.nft_type,
        metadata: request.metadata,
    };
    
    // 从state中获取VotingFlowEngine实例并创建投票流程
    let flow_engine = state.voting_flow_engine.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match flow_engine.create_voting_flow(create_request).await {
        Ok(session) => {
            info!("创建投票流程成功: session_id={}", request.session_id);
            Ok(warp::reply::json(&ApiResponse::success(serde_json::json!({
                "session_id": session.session_id,
                "status": format!("{:?}", session.status),
                "message": "投票流程创建成功"
            }))))
        }
        Err(e) => {
            error!("创建投票流程失败: session_id={}, error={}", request.session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 获取投票流程状态
pub async fn get_voting_flow_status(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let flow_engine = state.voting_flow_engine.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match flow_engine.get_session(&session_id).await {
        Some(session) => {
            info!("获取投票流程状态成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": session.session_id,
                "status": format!("{:?}", session.status),
                "phase": format!("{:?}", session.status),
                "participant_count": session.participants.len(),
                "commitment_count": session.commitments.len(),
                "reveal_count": session.reveals.len(),
                "created_at": session.created_at,
                "updated_at": session.updated_at
            }))))
        }
        None => {
            error!("投票流程不存在: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error("投票流程不存在".to_string())))
        }
    }
}

/// 启动投票阶段
pub async fn start_voting_phase(
    state: Arc<ServerState>,
    session_id: String,
    phase: String,
) -> Result<warp::reply::Json, Rejection> {
    let flow_engine = state.voting_flow_engine.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    // 解析阶段
    let voting_phase = match phase.to_lowercase().as_str() {
        "commitment" => VotingStatus::CommitmentPhase,
        "reveal" => VotingStatus::RevealPhase,
        "counting" => VotingStatus::CountingPhase,
        "completed" => VotingStatus::Completed,
        _ => {
            return Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error("无效的投票阶段".to_string())))
        }
    };
    
    match flow_engine.start_voting_phase(&session_id, voting_phase.clone()).await {
        Ok(session) => {
            info!("启动投票阶段成功: session_id={}, phase={:?}", session_id, &voting_phase);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": session.session_id,
                "status": format!("{:?}", session.status),
                "message": "投票阶段启动成功"
            }))))
        }
        Err(e) => {
            error!("启动投票阶段失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 获取所有投票流程
pub async fn get_all_voting_flows(
    state: Arc<ServerState>,
) -> Result<warp::reply::Json, Rejection> {
    let flow_engine = state.voting_flow_engine.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    let sessions = flow_engine.get_all_sessions().await;
    
    let flows_data: Vec<serde_json::Value> = sessions.iter().map(|session| {
        serde_json::json!({
            "session_id": session.session_id,
            "title": session.title,
            "status": format!("{:?}", session.status),
            "participant_count": session.participants.len(),
            "commitment_count": session.commitments.len(),
            "reveal_count": session.reveals.len(),
            "created_at": session.created_at,
            "updated_at": session.updated_at
        })
    }).collect();
    
    info!("获取所有投票流程成功: count={}", flows_data.len());
    Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
        "flows": flows_data,
        "total_count": flows_data.len()
    }))))
}

/// 删除投票流程
pub async fn delete_voting_flow(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let flow_engine = state.voting_flow_engine.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match flow_engine.delete_session(&session_id).await {
        Ok(_) => {
            info!("删除投票流程成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": session_id,
                "message": "投票流程删除成功"
            }))))
        }
        Err(e) => {
            error!("删除投票流程失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 计算投票结果
pub async fn calculate_voting_results(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let flow_engine = state.voting_flow_engine.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match flow_engine.calculate_results(&session_id).await {
        Ok(results) => {
            info!("计算投票结果成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": session_id,
                "total_votes": results.total_votes,
                "valid_votes": results.valid_votes,
                "invalid_votes": results.invalid_votes,
                "winner_count": results.winner_count,
                "winners": results.winners,
                "calculation_proof": results.calculation_proof,
                "calculated_at": results.calculated_at
            }))))
        }
        Err(e) => {
            error!("计算投票结果失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 创建投票生命周期管理路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let create_flow_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "lifecycle" / "flows")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: CreateVotingFlowApiRequest, state: Arc<ServerState>| async move { 
                create_voting_flow(state, request).await 
            })
            .boxed()
    };

    let get_status_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "lifecycle" / "flows" / String / "status")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                get_voting_flow_status(state, session_id).await 
            })
            .boxed()
    };

    let start_phase_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "lifecycle" / "flows" / String / "phases" / String / "start")
            .and(warp::post())
            .and(with_state(state))
            .and_then(|session_id: String, phase: String, state: Arc<ServerState>| async move { 
                start_voting_phase(state, session_id, phase).await 
            })
            .boxed()
    };

    let list_flows_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "lifecycle" / "flows")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|state: Arc<ServerState>| async move { 
                get_all_voting_flows(state).await 
            })
            .boxed()
    };

    let delete_flow_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "lifecycle" / "flows" / String)
            .and(warp::delete())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                delete_voting_flow(state, session_id).await 
            })
            .boxed()
    };

    let calculate_results_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "lifecycle" / "flows" / String / "results")
            .and(warp::post())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                calculate_voting_results(state, session_id).await 
            })
            .boxed()
    };

    create_flow_route
        .or(get_status_route)
        .or(start_phase_route)
        .or(list_flows_route)
        .or(delete_flow_route)
        .or(calculate_results_route)
        .boxed()
}
