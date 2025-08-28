use std::sync::Arc;
use warp::{Filter, Rejection, Reply};
use warp::http::HeaderMap;

use crate::utils::{with_state, push_audit};
use crate::types::{ApiResponse, StakingInfoResponse, now_secs, header_address, StakeEvent, StakeEventKind};
use crate::state::ServerState;
use crate::routes::sync::StakeRecord;

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let stake_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "stake")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and(warp::header::headers_cloned())
            .and_then(|req: crate::types::StakeRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
                stake_impl(req, state, headers).await
            })
            .boxed()
    };

    let unstake_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "unstake")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and(warp::header::headers_cloned())
            .and_then(|req: crate::types::UnstakeRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
                unstake_impl(req, state, headers).await
            })
            .boxed()
    };

    let lock_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "lock")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and(warp::header::headers_cloned())
            .and_then(|req: crate::types::LockRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
                lock_impl(req, state, headers).await
            })
            .boxed()
    };

    let unlock_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "unlock")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and(warp::header::headers_cloned())
            .and_then(|req: crate::types::UnlockRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
                unlock_impl(req, state, headers).await
            })
            .boxed()
    };

    let info_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "info")
            .and(warp::get())
            .and(with_state(state))
            .and(warp::header::headers_cloned())
            .and_then(|state: Arc<ServerState>, headers: HeaderMap| async move {
                info_impl(state, headers).await
            })
            .boxed()
    };

    stake_route
        .or(unstake_route)
        .or(lock_route)
        .or(unlock_route)
        .or(info_route)
        .boxed()
}

async fn stake_impl(req: crate::types::StakeRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
    let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
    let now = now_secs();
    let mut map = state.staking.write().await;
    let rec: &mut StakeRecord = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
    rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
    rec.staked_amount = rec.staked_amount.saturating_add(req.amount);
    push_audit(&state, "stake".to_string(), addr.clone(), format!("amount={}", req.amount)).await;
    {
        let mut evs = state.stake_events.write().await;
        evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Stake, amount: req.amount });
    }
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn unstake_impl(req: crate::types::UnstakeRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
    let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
    let now = now_secs();
    let mut map = state.staking.write().await;
    let rec: &mut StakeRecord = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
    rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
    if rec.staked_amount < req.amount { return Ok(warp::reply::json(&ApiResponse::<()>::error("可用质押不足".to_string()))); }
    rec.staked_amount -= req.amount;
    push_audit(&state, "unstake".to_string(), addr.clone(), format!("amount={}", req.amount)).await;
    {
        let mut evs = state.stake_events.write().await;
        evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Unstake, amount: req.amount });
    }
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn lock_impl(req: crate::types::LockRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
    let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
    let now = now_secs();
    let mut map = state.staking.write().await;
    let rec: &mut StakeRecord = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
    rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
    if rec.staked_amount < req.amount { return Ok(warp::reply::json(&ApiResponse::<()>::error("可锁定余额不足".to_string()))); }
    rec.staked_amount -= req.amount;
    rec.locked_amount = rec.locked_amount.saturating_add(req.amount);
    rec.unlock_after = rec.unlock_after.max(now + req.lock_duration);
    push_audit(&state, "lock".to_string(), addr.clone(), format!("amount={}", req.amount)).await;
    {
        let mut evs = state.stake_events.write().await;
        evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Lock, amount: req.amount });
    }
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn unlock_impl(req: crate::types::UnlockRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
    let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
    let now = now_secs();
    let mut map = state.staking.write().await;
    let rec: &mut StakeRecord = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
    rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
    if rec.locked_amount < req.amount { return Ok(warp::reply::json(&ApiResponse::<()>::error("可解锁余额不足".to_string()))); }
    if now < rec.unlock_after {
        return Ok(warp::reply::json(&ApiResponse::<()>::error("未满足时间锁条件".to_string())));
    }
    let cond_ok = {
        let conds = state.staking_conditions.read().await;
        *conds.get(&addr).unwrap_or(&false)
    };
    if !cond_ok { return Ok(warp::reply::json(&ApiResponse::<()>::error("未满足条件锁".to_string()))); }
    rec.locked_amount -= req.amount;
    rec.staked_amount = rec.staked_amount.saturating_add(req.amount);
    push_audit(&state, "unlock".to_string(), addr.clone(), format!("amount={}", req.amount)).await;
    {
        let mut evs = state.stake_events.write().await;
        evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Unlock, amount: req.amount });
    }
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn info_impl(state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
    let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
    let now = now_secs();
    let mut map = state.staking.write().await;
    let rec: &mut StakeRecord = map.entry(addr).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
    rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
    Ok(warp::reply::json(&ApiResponse::success(StakingInfoResponse { 
        staked: rec.staked_amount, 
        locked: rec.locked_amount, 
        available: rec.staked_amount.saturating_sub(rec.locked_amount),
        apr: std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500)
    })))
}


