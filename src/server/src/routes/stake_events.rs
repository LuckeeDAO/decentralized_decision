use crate::state::ServerState;
use crate::types::{ApiResponse, StakeEvent, StakeConditionSetReq};
use serde::Serialize;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// 质押事件列表响应
#[derive(Serialize)]
struct StakeEventsResponse { 
    events: Vec<StakeEvent> 
}

/// 质押事件列表查询
pub async fn stake_events_list(state: Arc<ServerState>, limit: Option<usize>) -> Result<impl Reply, Rejection> {
    let evs = state.stake_events.read().await;
    let n = limit.unwrap_or(100);
    let start = evs.len().saturating_sub(n);
    Ok(warp::reply::json(&ApiResponse::success(StakeEventsResponse { events: evs[start..].to_vec() })))
}

/// 设置条件锁是否满足（管理员接口）
pub async fn stake_condition_set(state: Arc<ServerState>, req: StakeConditionSetReq) -> Result<impl Reply, Rejection> {
    let mut conds = state.staking_conditions.write().await;
    conds.insert(req.address, req.satisfied);
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 创建质押事件管理路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let stake_events_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "events")
            .and(warp::get())
            .and(warp::query::<std::collections::HashMap<String, String>>())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|q: std::collections::HashMap<String, String>, state: Arc<ServerState>| async move {
                let limit = q.get("limit").and_then(|v| v.parse::<usize>().ok());
                stake_events_list(state, limit).await
            })
            .boxed()
    };

    let stake_cond_set_route = {
        let state = Arc::clone(&state);
        warp::path!("staking" / "condition" / "set")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|req: StakeConditionSetReq, state: Arc<ServerState>| async move { stake_condition_set(state, req).await })
            .boxed()
    };

    stake_events_route
        .or(stake_cond_set_route)
        .boxed()
}
