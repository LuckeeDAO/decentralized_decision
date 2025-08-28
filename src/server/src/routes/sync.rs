use crate::state::ServerState;
use crate::types::ApiResponse;
use luckee_voting_ipfs::{export_cache as ipfs_export_fn, import_cache as ipfs_import_fn};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// 审计事件
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct AuditEvent {
    pub timestamp: u64,
    pub action: String,
    pub address: String,
    pub details: String,
}

/// 代币质押与锁定
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StakeRecord {
    pub staked_amount: u128,
    pub locked_amount: u128,
    pub reward_accrued: u128,
    pub last_update: u64,
    // 时间锁：在 unlock_after 之前不可解锁
    pub unlock_after: u64,
}

impl StakeRecord {
    pub fn touch_and_accrue(&mut self, now: u64, apr_bps: u32) {
        if now > self.last_update {
            let elapsed = now - self.last_update;
            let reward = (self.staked_amount as u64 * elapsed as u64 * apr_bps as u64) / (365 * 24 * 3600 * 10000);
            self.reward_accrued += reward as u128;
            self.last_update = now;
        }
    }
}

/// 资格状态机
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QualStatus { 
    Eligible, 
    Suspended, 
    Revoked 
}

/// 同步快照（链上链下状态同步的基础能力）
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncSnapshot {
    pub balances: HashMap<String, u128>,
    pub delegations_to: HashMap<String, Vec<String>>,
    pub inheritance_parent: HashMap<String, String>,
    pub audit_logs: Vec<AuditEvent>,
    pub metadata_versions: HashMap<String, Vec<(String, u64)>>,
    pub nft_owners: HashMap<String, String>,
    pub nft_type_states: HashMap<String, String>,
    pub lottery_configs: HashMap<String, Vec<(u32, String, u64)>>,
    pub staking: HashMap<String, StakeRecord>,
    pub qualifications: HashMap<String, QualStatus>,
    // IPFS本地缓存（cid -> data b64），使用库提供的导出格式
    pub ipfs_cache: Vec<(String, String)>,
}

/// 工具: 获取当前秒
#[allow(dead_code)]
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

/// 导出状态快照
pub async fn sync_export_snapshot(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let balances = state.balances.read().await.clone();
    let delegations_to = state.delegations_to.read().await.clone();
    let inheritance_parent = state.inheritance_parent.read().await.clone();
    let audit_logs = state.audit_logs.read().await.clone();
    let metadata_versions = state.metadata_versions.read().await.clone();
    let nft_owners = state.nft_owners.read().await.clone();
    let nft_type_states = state.nft_type_states.read().await.clone();
    let lottery_configs = state.lottery_configs.read().await.clone();
    let staking = state.staking.read().await.clone();
    let qualifications = state.qualifications.read().await.clone();
    let ipfs_cache = {
        let ipfs = state.ipfs.read().await;
        ipfs_export_fn(&ipfs)
    };

    let snapshot = SyncSnapshot { 
        balances, 
        delegations_to, 
        inheritance_parent, 
        audit_logs, 
        metadata_versions, 
        nft_owners, 
        nft_type_states, 
        lottery_configs, 
        staking, 
        qualifications, 
        ipfs_cache 
    };
    Ok(warp::reply::json(&ApiResponse::success(snapshot)))
}

/// 恢复状态快照
pub async fn sync_restore_snapshot(state: Arc<ServerState>, snapshot: SyncSnapshot) -> Result<impl Reply, Rejection> {
    // 先恢复IPFS缓存，避免后续业务依赖缺失
    {
        let mut ipfs = state.ipfs.write().await;
        if let Err(e) = ipfs_import_fn(&mut ipfs, snapshot.ipfs_cache.clone()) {
            return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string())));
        }
    }

    // 用快照替换内存态
    {
        *state.balances.write().await = snapshot.balances;
        *state.delegations_to.write().await = snapshot.delegations_to;
        *state.inheritance_parent.write().await = snapshot.inheritance_parent;
        *state.audit_logs.write().await = snapshot.audit_logs;
        *state.metadata_versions.write().await = snapshot.metadata_versions;
        *state.nft_owners.write().await = snapshot.nft_owners;
        *state.nft_type_states.write().await = snapshot.nft_type_states;
        *state.lottery_configs.write().await = snapshot.lottery_configs;
        *state.staking.write().await = snapshot.staking;
        *state.qualifications.write().await = snapshot.qualifications;
    }

    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 创建同步路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let sync_export_route = {
        let state = Arc::clone(&state);
        warp::path!("sync" / "export")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|state: Arc<ServerState>| async move { sync_export_snapshot(state).await })
            .boxed()
    };

    let sync_restore_route = {
        let state = Arc::clone(&state);
        warp::path!("sync" / "restore")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|snapshot: SyncSnapshot, state: Arc<ServerState>| async move { sync_restore_snapshot(state, snapshot).await })
            .boxed()
    };

    sync_export_route
        .or(sync_restore_route)
        .boxed()
}
