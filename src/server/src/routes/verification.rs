use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::core::verification::{Verifier, CommitmentProof};
use crate::core::selection_algorithms::{SelectionResult, Participant};
use crate::core::lottery_config::LevelParameters;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[derive(Debug, Deserialize)]
struct CommitmentVerifyReq {
    commitment: String,
    message: String,
    randomness: String,
    // 可选："hex" 表示 message 和 randomness 使用十六进制编码
    encoding: Option<String>,
}

#[derive(Debug, Serialize)]
struct CommitmentVerifyResp { valid: bool }

#[derive(Debug, Deserialize)]
struct SelectionVerifyReq {
    results: HashMap<String, SelectionResult>,
    participants: Vec<Participant>,
    level_params: HashMap<String, LevelParameters>,
}

#[derive(Debug, Serialize)]
struct SelectionVerifyResp { valid: bool }

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let base = warp::path("verify");

    let state_filter = warp::any().map(move || Arc::clone(&state));

    let commitment = warp::post()
        .and(base.and(warp::path("commitment")).and(warp::path::end()))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(commitment_verify)
        .boxed();

    let commitment_generate = warp::post()
        .and(base.and(warp::path("commitment")).and(warp::path("generate")).and(warp::path::end()))
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(commitment_generate)
        .boxed();

    let selection = warp::post()
        .and(base.and(warp::path("selection")).and(warp::path::end()))
        .and(warp::body::json())
        .and(state_filter)
        .and_then(selection_verify)
        .boxed();

    commitment
        .or(commitment_generate)
        .or(selection)
        .boxed()
}

async fn commitment_verify(req: CommitmentVerifyReq, _state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let (msg_bytes, rand_bytes) = if req.encoding.as_deref() == Some("hex") {
        let m = hex::decode(&req.message).map_err(|_| warp::reject())?;
        let r = hex::decode(&req.randomness).map_err(|_| warp::reject())?;
        (m, r)
    } else {
        (req.message.into_bytes(), req.randomness.into_bytes())
    };
    let proof = CommitmentProof { commitment: req.commitment, message_hash: "".into() /* 未使用字段，函数内部重新计算 */ };
    let valid = Verifier::verify_commitment(&proof, &msg_bytes, &rand_bytes);
    let resp = ApiResponse::success(CommitmentVerifyResp { valid });
    Ok(warp::reply::json(&resp))
}

async fn selection_verify(req: SelectionVerifyReq, _state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let valid = Verifier::verify_selection(&req.results, &req.participants, &req.level_params)
        .map_err(|_| warp::reject())?;
    let resp = ApiResponse::success(SelectionVerifyResp { valid });
    Ok(warp::reply::json(&resp))
}

#[derive(Debug, Deserialize)]
struct CommitmentGenReq { message: String, randomness: String, encoding: Option<String> }

#[derive(Debug, Serialize)]
struct CommitmentGenResp { message_hash: String, commitment: String }

async fn commitment_generate(req: CommitmentGenReq, _state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    use sha2::{Digest, Sha256};
    let (msg_bytes, rand_bytes) = if req.encoding.as_deref() == Some("hex") {
        let m = hex::decode(&req.message).map_err(|_| warp::reject())?;
        let r = hex::decode(&req.randomness).map_err(|_| warp::reject())?;
        (m, r)
    } else {
        (req.message.into_bytes(), req.randomness.into_bytes())
    };
    let mut h1 = Sha256::new(); h1.update(&msg_bytes); let message_hash = format!("{:x}", h1.finalize());
    let mut h2 = Sha256::new(); h2.update(&msg_bytes); h2.update(&rand_bytes); let commitment = format!("{:x}", h2.finalize());
    let resp = ApiResponse::success(CommitmentGenResp { message_hash, commitment });
    Ok(warp::reply::json(&resp))
}


