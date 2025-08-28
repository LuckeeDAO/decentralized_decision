use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::{Filter, Rejection, Reply};

use crate::types::ApiResponse;
use crate::state::ServerState;
use crate::utils::with_state;

#[derive(Debug, serde::Deserialize)]
struct AlertSetReq { key: String, threshold: u64 }
#[derive(Debug, serde::Serialize)]
struct AlertGetResp { breached: bool, current: u64, threshold: u64 }

async fn state_metric_inc(state: Arc<ServerState>, key: String, by: u64) -> Result<impl Reply, Rejection> {
    let mut sm = state.state_metrics.write().await;
    let v = sm.entry(key).or_insert(0);
    *v = v.saturating_add(by);
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn state_metric_get(state: Arc<ServerState>, key: String) -> Result<impl Reply, Rejection> {
    let sm = state.state_metrics.read().await;
    let v = *sm.get(&key).unwrap_or(&0);
    #[derive(serde::Serialize)]
    struct Resp { value: u64 }
    Ok(warp::reply::json(&ApiResponse::success(Resp { value: v })))
}

async fn alert_set(th: Arc<RwLock<HashMap<String, u64>>>, req: AlertSetReq) -> Result<impl Reply, Rejection> {
    th.write().await.insert(req.key, req.threshold);
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn alert_check(state: Arc<ServerState>, th: Arc<RwLock<HashMap<String, u64>>>, key: String) -> Result<impl Reply, Rejection> {
    let sm = state.state_metrics.read().await;
    let cur = *sm.get(&key).unwrap_or(&0);
    let thr = *th.read().await.get(&key).unwrap_or(&u64::MAX);
    Ok(warp::reply::json(&ApiResponse::success(AlertGetResp { breached: cur >= thr, current: cur, threshold: thr })))
}

pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    // 阈值内存存放
    let alert_thresholds: Arc<RwLock<HashMap<String, u64>>> = Arc::new(RwLock::new(HashMap::new()));
    let alert_thresholds_filter = warp::any().map(move || alert_thresholds.clone());

    let inc_route = {
        let state = Arc::clone(&state);
        warp::path!("state" / "metric" / String / u64)
            .and(warp::post())
            .and(with_state(state))
            .and_then(|key: String, by: u64, state: Arc<ServerState>| async move { state_metric_inc(state, key, by).await })
            .boxed()
    };

    let get_route = {
        let state = Arc::clone(&state);
        warp::path!("state" / "metric" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|key: String, state: Arc<ServerState>| async move { state_metric_get(state, key).await })
            .boxed()
    };

    let alert_set_route = warp::path!("state" / "alert")
        .and(warp::post())
        .and(warp::body::json())
        .and(alert_thresholds_filter.clone())
        .and_then(|req: AlertSetReq, th: Arc<RwLock<HashMap<String, u64>>>| async move { alert_set(th, req).await })
        .boxed();

    let alert_check_route = {
        let state = Arc::clone(&state);
        warp::path!("state" / "alert" / String)
            .and(warp::get())
            .and(with_state(state))
            .and(alert_thresholds_filter.clone())
            .and_then(|key: String, state: Arc<ServerState>, th: Arc<RwLock<HashMap<String, u64>>>| async move { alert_check(state, th, key).await })
            .boxed()
    };

    inc_route
        .or(get_route)
        .or(alert_set_route)
        .or(alert_check_route)
        .boxed()
}


