//! 投票SDK相关API路由
//!
//! 实现第五阶段的客户端SDK接口

use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::utils::with_state;
use serde::Deserialize;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use tracing::{info, error};

use crate::core::voting_sdk::NFTProof;

/// 提交投票承诺请求
#[derive(Debug, Deserialize)]
pub struct SubmitCommitmentApiRequest {
    pub session_id: String,
    pub user_id: String,
    pub preference_value: i32,
    pub nft_proof: NFTProof,
}

/// 提交投票揭示请求
#[derive(Debug, Deserialize)]
pub struct SubmitRevealApiRequest {
    pub session_id: String,
    pub user_id: String,
    pub preference_value: i32,
    pub randomness: String,
    pub nft_proof: NFTProof,
}

/// 生成比特承诺请求
#[derive(Debug, Deserialize)]
pub struct GenerateCommitmentApiRequest {
    pub message: String,
}

/// 验证比特承诺请求
#[derive(Debug, Deserialize)]
pub struct VerifyCommitmentApiRequest {
    pub message: String,
    pub randomness: String,
    pub commitment_hash: String,
}

/// 提交投票承诺
pub async fn submit_commitment(
    state: Arc<ServerState>,
    request: SubmitCommitmentApiRequest,
) -> Result<warp::reply::Json, Rejection> {
    let voting_submitter = state.voting_submitter.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match voting_submitter.submit_commitment(
        &request.session_id,
        &request.user_id,
        request.preference_value,
        request.nft_proof,
    ).await {
        Ok(commitment_hash) => {
            info!("提交投票承诺成功: session_id={}, user_id={}", request.session_id, request.user_id);
            Ok(warp::reply::json(&ApiResponse::success(serde_json::json!({
                "session_id": request.session_id,
                "user_id": request.user_id,
                "commitment_hash": commitment_hash,
                "status": "submitted",
                "message": "投票承诺提交成功"
            }))))
        }
        Err(e) => {
            error!("提交投票承诺失败: session_id={}, user_id={}, error={}", request.session_id, request.user_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 提交投票揭示
pub async fn submit_reveal(
    state: Arc<ServerState>,
    request: SubmitRevealApiRequest,
) -> Result<warp::reply::Json, Rejection> {
    let voting_submitter = state.voting_submitter.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match voting_submitter.submit_reveal(
        &request.session_id,
        &request.user_id,
        request.preference_value,
        &request.randomness,
        request.nft_proof,
    ).await {
        Ok(reveal_data) => {
            info!("提交投票揭示成功: session_id={}, user_id={}", request.session_id, request.user_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": request.session_id,
                "user_id": request.user_id,
                "reveal_data": reveal_data,
                "status": "submitted",
                "message": "投票揭示提交成功"
            }))))
        }
        Err(e) => {
            error!("提交投票揭示失败: session_id={}, user_id={}, error={}", request.session_id, request.user_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 验证会话完整性
pub async fn verify_session_integrity(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let voting_verifier = state.voting_verifier.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match voting_verifier.verify_session_integrity(&session_id).await {
        Ok(report) => {
            info!("验证会话完整性成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": report.session_id,
                "is_valid": report.is_valid,
                "issues": report.issues,
                "timestamp": report.timestamp
            }))))
        }
        Err(e) => {
            error!("验证会话完整性失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 验证投票结果
pub async fn verify_voting_results(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let voting_verifier = state.voting_verifier.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match voting_verifier.verify_voting_results(&session_id).await {
        Ok(report) => {
            info!("验证投票结果成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": report.session_id,
                "is_valid": report.is_valid,
                "issues": report.issues,
                "total_votes": report.total_votes,
                "valid_votes": report.valid_votes,
                "invalid_votes": report.invalid_votes,
                "winner_count": report.winner_count,
                "timestamp": report.timestamp
            }))))
        }
        Err(e) => {
            error!("验证投票结果失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 查询会话信息
pub async fn query_session_info(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let result_query = state.result_query.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match result_query.get_session_info(&session_id).await {
        Ok(Some(session)) => {
            info!("查询会话信息成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::success(serde_json::json!({
                "session_id": session.session_id,
                "title": session.title,
                "description": session.description,
                "status": format!("{:?}", session.status),
                "participant_count": session.participants.len(),
                "commitment_count": session.commitments.len(),
                "reveal_count": session.reveals.len(),
                "created_at": session.created_at,
                "updated_at": session.updated_at,
                "creator": session.creator,
                "nft_type": session.nft_type
            }))))
        }
        Ok(None) => {
            error!("会话不存在: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error("会话不存在".to_string())))
        }
        Err(e) => {
            error!("查询会话信息失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 查询会话状态
pub async fn query_session_status(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let result_query = state.result_query.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match result_query.get_session_status(&session_id).await {
        Ok(Some(status)) => {
            info!("查询会话状态成功: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
                "session_id": session_id,
                "status": format!("{:?}", status)
            }))))
        }
        Ok(None) => {
            error!("会话不存在: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error("会话不存在".to_string())))
        }
        Err(e) => {
            error!("查询会话状态失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 查询投票结果
pub async fn query_voting_results(
    state: Arc<ServerState>,
    session_id: String,
) -> Result<warp::reply::Json, Rejection> {
    let result_query = state.result_query.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    match result_query.get_voting_results(&session_id).await {
        Ok(Some(results)) => {
            info!("查询投票结果成功: session_id={}", session_id);
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
        Ok(None) => {
            error!("投票结果不存在: session_id={}", session_id);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error("投票结果不存在".to_string())))
        }
        Err(e) => {
            error!("查询投票结果失败: session_id={}, error={}", session_id, e);
            Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::error(e)))
        }
    }
}

/// 生成比特承诺
pub async fn generate_commitment(
    state: Arc<ServerState>,
    request: GenerateCommitmentApiRequest,
) -> Result<warp::reply::Json, Rejection> {
    let commitment_generator = state.commitment_generator.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    let (commitment_hash, randomness) = commitment_generator.generate_commitment(&request.message.as_bytes());
    
    info!("生成比特承诺成功: message_length={}", request.message.len());
    Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
        "commitment_hash": commitment_hash,
        "randomness": hex::encode(randomness),
        "message_length": request.message.len()
    }))))
}

/// 验证比特承诺
pub async fn verify_commitment(
    state: Arc<ServerState>,
    request: VerifyCommitmentApiRequest,
) -> Result<warp::reply::Json, Rejection> {
    let commitment_generator = state.commitment_generator.as_ref()
        .ok_or_else(|| warp::reject::custom(crate::errors::ServerError::ServiceUnavailable))?;
    
    let randomness_bytes = hex::decode(&request.randomness)
        .map_err(|_| warp::reject::custom(crate::errors::ServerError::BadRequest))?;
    
    let is_valid = commitment_generator.verify_commitment(
        &request.message.as_bytes(),
        &randomness_bytes,
        &request.commitment_hash,
    );
    
    info!("验证比特承诺: is_valid={}", is_valid);
    Ok(warp::reply::json(&ApiResponse::<serde_json::Value>::success(serde_json::json!({
        "is_valid": is_valid,
        "message_length": request.message.len()
    }))))
}

/// 创建投票SDK路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let submit_commitment_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "commitments")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: SubmitCommitmentApiRequest, state: Arc<ServerState>| async move { 
                submit_commitment(state, request).await 
            })
            .boxed()
    };

    let submit_reveal_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "reveals")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: SubmitRevealApiRequest, state: Arc<ServerState>| async move { 
                submit_reveal(state, request).await 
            })
            .boxed()
    };

    let verify_integrity_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "sessions" / String / "verify" / "integrity")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                verify_session_integrity(state, session_id).await 
            })
            .boxed()
    };

    let verify_results_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "sessions" / String / "verify" / "results")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                verify_voting_results(state, session_id).await 
            })
            .boxed()
    };

    let query_session_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "sessions" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                query_session_info(state, session_id).await 
            })
            .boxed()
    };

    let query_status_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "sessions" / String / "status")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                query_session_status(state, session_id).await 
            })
            .boxed()
    };

    let query_results_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "sessions" / String / "results")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|session_id: String, state: Arc<ServerState>| async move { 
                query_voting_results(state, session_id).await 
            })
            .boxed()
    };

    let generate_commitment_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "commitments" / "generate")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: GenerateCommitmentApiRequest, state: Arc<ServerState>| async move { 
                generate_commitment(state, request).await 
            })
            .boxed()
    };

    let verify_commitment_route = {
        let state = Arc::clone(&state);
        warp::path!("voting" / "sdk" / "commitments" / "verify")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: VerifyCommitmentApiRequest, state: Arc<ServerState>| async move { 
                verify_commitment(state, request).await 
            })
            .boxed()
    };

    submit_commitment_route
        .or(submit_reveal_route)
        .or(verify_integrity_route)
        .or(verify_results_route)
        .or(query_session_route)
        .or(query_status_route)
        .or(query_results_route)
        .or(generate_commitment_route)
        .or(verify_commitment_route)
        .boxed()
}
