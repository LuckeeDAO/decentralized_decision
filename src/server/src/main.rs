#![recursion_limit = "1024"]
//! 基于比特承诺模型的去中心化投票系统 - 服务器主程序

use std::sync::Arc;
use warp::Filter;
use tracing::{info, error};

mod types;
mod utils;
mod errors;
mod state;
mod core;

use crate::errors::handle_rejection;
pub(crate) use crate::state::ServerState;

mod routes;

// 导入路由模块
use crate::routes::{
    health, state_metrics, ipfs_cache, ipfs_ext, upload, permissions, 
    staking, qualification, nft_types as routes_nft_types, 
    nft_ownership, lottery_config as routes_lottery_config, 
    levels, voting, sync, tools, cache, nft_state, stake_events, serials, benchmark, voting_lifecycle, voting_sdk
};

#[cfg(test)]
mod tests;

/// 创建主路由
fn create_routes(state: Arc<ServerState>) -> impl Filter<Extract = impl warp::Reply> + Clone {
    // 基础路由
    let health_routes = health::routes();
    let state_metrics_routes = state_metrics::routes(Arc::clone(&state));
    let ipfs_cache_routes = ipfs_cache::routes(Arc::clone(&state));
    let ipfs_ext_routes = ipfs_ext::routes(Arc::clone(&state));
    let upload_routes = upload::routes(Arc::clone(&state));
    let permissions_routes = permissions::routes(Arc::clone(&state));
    let staking_routes = staking::routes(Arc::clone(&state));
    let qualification_routes = qualification::routes(Arc::clone(&state));
    let nft_types_routes = routes_nft_types::routes(Arc::clone(&state));
    let nft_ownership_routes = nft_ownership::routes(Arc::clone(&state));
    let lottery_config_routes = routes_lottery_config::routes(Arc::clone(&state));
    let levels_routes = levels::routes(Arc::clone(&state));
    let voting_routes = voting::routes(Arc::clone(&state));
    let sync_routes = sync::routes(Arc::clone(&state));
    let tools_routes = tools::routes(Arc::clone(&state));
    let cache_routes = cache::routes(Arc::clone(&state));
    let nft_state_routes = nft_state::routes(Arc::clone(&state));
    let stake_events_routes = stake_events::routes(Arc::clone(&state));
    let serials_routes = serials::routes(Arc::clone(&state));
    let benchmark_routes = benchmark::routes(Arc::clone(&state));
    
    // 第五阶段新增路由
    let voting_lifecycle_routes = voting_lifecycle::routes(Arc::clone(&state));
    let voting_sdk_routes = voting_sdk::routes(Arc::clone(&state));

    // 组合所有路由
    health_routes
        .or(state_metrics_routes)
        .or(ipfs_cache_routes)
        .or(ipfs_ext_routes)
        .or(upload_routes)
        .or(permissions_routes)
        .or(staking_routes)
        .or(qualification_routes)
        .or(nft_types_routes)
        .or(nft_ownership_routes)
        .or(lottery_config_routes)
        .or(levels_routes)
        .or(voting_routes)
        .or(sync_routes)
        .or(tools_routes)
        .or(cache_routes)
        .or(nft_state_routes)
        .or(stake_events_routes)
        .or(serials_routes)
        .or(benchmark_routes)
        .or(voting_lifecycle_routes)
        .or(voting_sdk_routes)
        .boxed()
        .with(warp::cors().allow_any_origin())
        .recover(handle_rejection)
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    info!("启动投票系统服务器...");
    
    // 创建服务器状态
    let state = match ServerState::new().await {
        Ok(state) => Arc::new(state),
        Err(e) => {
            error!("初始化服务器状态失败: {}", e);
            std::process::exit(1);
        }
    };
    
    // 创建路由
    let routes = create_routes(state);
    
    // 获取端口配置
    let port = std::env::var("PORT")
        .unwrap_or_else(|_| "8080".to_string())
        .parse::<u16>()
        .unwrap_or_else(|e| {
            error!("端口解析失败: {}", e);
            std::process::exit(1);
        });
    
    info!("服务器启动在端口 {}", port);
    
    // 启动服务器
    warp::serve(routes).run(([0, 0, 0, 0], port)).await;
}
