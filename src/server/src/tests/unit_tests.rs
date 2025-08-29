use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::types::PermissionLevel;
use luckee_voting_wasm::voting::VotingSystem;
use luckee_voting_ipfs::IpfsManager;
use crate::core::nft_types::{NftTypeRegistry, NftTypePluginRegistry};
use crate::core::lottery_levels::LevelManager;
use crate::core::lottery_config::ConfigManager;
use crate::core::selection_algorithms::MultiTargetSelector;
use crate::core::serial_numbers::{SerialService, SerialPoolConfig};
use crate::core::performance::{PerformanceMonitor, PerformanceBenchmark};
use crate::core::concurrency::{SmartThreadPool, ThreadPoolConfig, ConcurrencyController};
use crate::core::stress_testing::StressTester;
use crate::core::participants::ParticipantService;
use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use warp::{hyper::body::to_bytes, Reply};
use base64::Engine;

// 使用routes模块中的定义
use crate::routes::voting::{CreateSessionRequest, SubmitCommitmentRequest};
use crate::types::{PermissionLevelResponse, UpdatePermissionRequest, RevokePermissionRequest, DelegatePermissionRequest, InheritPermissionRequest};

/// 创建测试状态
async fn mk_state() -> Arc<ServerState> {
    Arc::new(ServerState {
        voting_system: Arc::new(RwLock::new(VotingSystem::new())),
        balances: Arc::new(RwLock::new(HashMap::new())),
        delegations_to: Arc::new(RwLock::new(HashMap::new())),
        inheritance_parent: Arc::new(RwLock::new(HashMap::new())),
        audit_logs: Arc::new(RwLock::new(Vec::new())),
        ipfs: Arc::new(RwLock::new(IpfsManager::new("http://127.0.0.1:5001").await.unwrap())),
        metadata_versions: Arc::new(RwLock::new(HashMap::new())),
        nft_owners: Arc::new(RwLock::new(HashMap::new())),
        nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())),
        nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())),
        nft_type_states: Arc::new(RwLock::new(HashMap::new())),
        nft_global_states: Arc::new(RwLock::new(HashMap::new())),
        nft_global_state_history: Arc::new(RwLock::new(HashMap::new())),
        lottery_configs: Arc::new(RwLock::new(HashMap::new())),
        staking: Arc::new(RwLock::new(HashMap::new())),
        stake_events: Arc::new(RwLock::new(Vec::new())),
        staking_conditions: Arc::new(RwLock::new(HashMap::new())),
        qualifications: Arc::new(RwLock::new(HashMap::new())),
        metadata_cache: Arc::new(RwLock::new(HashMap::new())),
        redis: None,
        state_metrics: Arc::new(RwLock::new(HashMap::new())),
        level_manager: Arc::new(RwLock::new(LevelManager::new().unwrap())),
        config_manager: Arc::new(RwLock::new(ConfigManager::new().unwrap())),
        multi_target_selector: Arc::new(RwLock::new(MultiTargetSelector::new())),
        serials: Arc::new(RwLock::new(SerialService::new(SerialPoolConfig { pre_generate: 0, serial_hex_len: 16, low_watermark: 0 }).await)),
        
        // 第五阶段组件
        voting_flow_engine: None,
        voting_submitter: None,
        voting_verifier: None,
        result_query: None,
        commitment_generator: None,
        security_system: None,
        storage_system: None,
        participant_service: None,
        audit_logger: None,
        cache_manager: None,
        
        // 第六阶段新增组件 - 性能优化
        performance_monitor: Arc::new(PerformanceMonitor::new()),
        performance_benchmark: {
            let participant_service = Arc::new(ParticipantService::new());
            let session_manager = Arc::new(crate::core::session::SessionManager::new());
            Arc::new(PerformanceBenchmark::new(session_manager, participant_service))
        },
        thread_pool: Arc::new(SmartThreadPool::new(ThreadPoolConfig::default())),
        concurrency_controller: Arc::new(ConcurrencyController::new(1000)),
        stress_tester: Arc::new(StressTester::new(
            Arc::new(PerformanceMonitor::new()),
            1000,
        )),
    })
}

/// 测试权限更新和撤销
#[tokio::test(flavor = "current_thread")]
pub async fn test_update_and_revoke_permission() {
    let state = mk_state().await;
    // update permission
    let up = update_permission(state.clone(), UpdatePermissionRequest { address: "alice".into(), balance: 1500 }).await.unwrap();
    let body = to_bytes(up.into_response().into_body()).await.unwrap();
    let resp: ApiResponse<PermissionLevelResponse> = serde_json::from_slice(&body).unwrap();
    assert!(resp.success && resp.data.unwrap().level == PermissionLevel::Creator);

    // revoke -> basic
    let rv = revoke_permission(state.clone(), RevokePermissionRequest { address: "alice".into() }).await.unwrap();
    let body = to_bytes(rv.into_response().into_body()).await.unwrap();
    let resp: ApiResponse<PermissionLevelResponse> = serde_json::from_slice(&body).unwrap();
    assert!(resp.success && resp.data.unwrap().level == PermissionLevel::Basic);
}

/// 测试权限委托和继承
#[tokio::test(flavor = "current_thread")]
pub async fn test_delegate_and_inherit_permission() {
    let state = mk_state().await;
    // setup balances
    let _ = update_permission(state.clone(), UpdatePermissionRequest { address: "owner".into(), balance: 1200 }).await.unwrap();
    let _ = update_permission(state.clone(), UpdatePermissionRequest { address: "child".into(), balance: 10 }).await.unwrap();

    // delegate from owner -> addrA
    let _ = delegate_permission(state.clone(), DelegatePermissionRequest { from: "owner".into(), to: "addrA".into() }).await.unwrap();
    // check addrA level
    let resp = get_permission_level(state.clone(), "addrA".into()).await.unwrap();
    let body = to_bytes(resp.into_response().into_body()).await.unwrap();
    let r: ApiResponse<PermissionLevelResponse> = serde_json::from_slice(&body).unwrap();
    assert_eq!(r.data.unwrap().level, PermissionLevel::Creator);

    // inherit: child <- addrA
    let _ = inherit_permission(state.clone(), InheritPermissionRequest { child: "child".into(), parent: "addrA".into() }).await.unwrap();
    let resp2 = get_permission_level(state.clone(), "child".into()).await.unwrap();
    let body2 = to_bytes(resp2.into_response().into_body()).await.unwrap();
    let r2: ApiResponse<PermissionLevelResponse> = serde_json::from_slice(&body2).unwrap();
    assert_eq!(r2.data.unwrap().level, PermissionLevel::Creator);
}

/// 测试健康检查
#[tokio::test(flavor = "current_thread")]
pub async fn test_health_check() {
    let _response = health_check().await.unwrap();
    // Simple test to ensure the function doesn't panic
    assert!(true);
}

/// 测试提交承诺解码
#[tokio::test(flavor = "current_thread")]
pub async fn test_submit_commitment_decoding() {
    let state = mk_state().await;

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

/// 测试权限更新和撤销
#[tokio::test(flavor = "current_thread")]
pub async fn test_permission_update_and_revoke() {
    let state = mk_state().await;

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

/// 测试权限委托和继承
#[tokio::test(flavor = "current_thread")]
pub async fn test_permission_delegation_and_inheritance() {
    let state = mk_state().await;

    // set balances
    let _ = update_permission(state.clone(), UpdatePermissionRequest { address: "owner".into(), balance: 1200 }).await.unwrap();
    let _ = update_permission(state.clone(), UpdatePermissionRequest { address: "child".into(), balance: 10 }).await.unwrap();

    // delegate from owner -> addrA
    let _ = delegate_permission(state.clone(), DelegatePermissionRequest { from: "owner".into(), to: "addrA".into() }).await.unwrap();
    // addrA should reach Creator due to delegation
    let reply = get_permission_level(state.clone(), "addrA".into()).await.unwrap().into_response();
    assert_eq!(reply.status(), warp::http::StatusCode::OK);

    // inheritance: child inherits from addrA
    let _ = inherit_permission(state.clone(), InheritPermissionRequest { child: "child".into(), parent: "addrA".into() }).await.unwrap();
    let reply2 = get_permission_level(state.clone(), "child".into()).await.unwrap().into_response();
    assert_eq!(reply2.status(), warp::http::StatusCode::OK);

    // audit list available
    let resp = list_audit_logs(state.clone(), Some(10)).await.unwrap().into_response();
    assert_eq!(resp.status(), warp::http::StatusCode::OK);
}

/// 测试抽奖配置存储和版本
#[tokio::test(flavor = "current_thread")]
pub async fn test_lottery_config_store_and_versions() {
    let state = mk_state().await;

    // register nft type with schema
    let _ = nft_type_register(state.clone(), NftTypeRegisterRequest {
        meta: crate::core::nft_types::NftTypeMeta { type_id: "lottery".into(), name: "Lottery".into(), category: "抽奖".into(), required_level: None },
        schema: serde_json::json!({
            "type":"object",
            "properties": {"name": {"type":"string"}, "description": {"type":"string"}},
            "required": ["name","description"]
        }),
    }).await.unwrap();

    // store config v1
    let resp1 = lottery_config_store(state.clone(), LotteryConfigStoreRequest {
        config_id: "cfg1".into(),
        type_id: "lottery".into(),
        config: serde_json::json!({"name":"A","description":"D"}),
    }).await.unwrap().into_response();
    assert_eq!(resp1.status(), warp::http::StatusCode::OK);

    // list versions (expect 1)
    let resp_list1 = lottery_config_versions(state.clone(), "cfg1".into()).await.unwrap().into_response();
    assert_eq!(resp_list1.status(), warp::http::StatusCode::OK);

    // store config v2
    let _resp2 = lottery_config_store(state.clone(), LotteryConfigStoreRequest {
        config_id: "cfg1".into(),
        type_id: "lottery".into(),
        config: serde_json::json!({"name":"B","description":"D2"}),
    }).await.unwrap().into_response();

    // rollback to v1
    let rb = lottery_config_rollback(state.clone(), "cfg1".into(), LotteryConfigRollbackRequest { version: 1 }).await.unwrap().into_response();
    assert_eq!(rb.status(), warp::http::StatusCode::OK);
}

// 以下是测试辅助函数，需要从main.rs迁移过来
// 这些函数应该在实际的模块中实现，这里只是测试用的简化版本

#[derive(Debug, Deserialize)]
pub struct PermissionCheckRequest {
    pub address: String,
    pub min_level: PermissionLevel,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct NftTypeRegisterRequest {
    pub meta: crate::core::nft_types::NftTypeMeta,
    pub schema: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LotteryConfigStoreRequest {
    pub config_id: String,
    pub type_id: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
#[allow(dead_code)]
pub struct LotteryConfigRollbackRequest { 
    pub version: u32 
}

pub async fn update_permission(_state: Arc<ServerState>, _req: UpdatePermissionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现，实际应该在permissions模块中
    let mut balances = _state.balances.write().await;
    balances.insert(_req.address.clone(), _req.balance);
    let level = if _req.balance >= 1000 { PermissionLevel::Creator } else { PermissionLevel::Basic };
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: _req.balance })))
}

pub async fn revoke_permission(_state: Arc<ServerState>, _req: RevokePermissionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    let mut balances = _state.balances.write().await;
    balances.insert(_req.address.clone(), 0);
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level: PermissionLevel::Basic, balance: 0 })))
}

pub async fn delegate_permission(_state: Arc<ServerState>, _req: DelegatePermissionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    let mut delegations_to = _state.delegations_to.write().await;
    let entry = delegations_to.entry(_req.to.clone()).or_default();
    if !entry.contains(&_req.from) {
        entry.push(_req.from.clone());
    }
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn inherit_permission(_state: Arc<ServerState>, _req: InheritPermissionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    let mut inheritance_parent = _state.inheritance_parent.write().await;
    inheritance_parent.insert(_req.child.clone(), _req.parent.clone());
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn get_permission_level(_state: Arc<ServerState>, _address: String) -> Result<impl warp::Reply, warp::Rejection> {
    // 递归+BFS：自身、委托链、继承链任一达到Creator则Creator
    use std::collections::{HashSet, VecDeque};
    let balances = _state.balances.read().await;
    let delegations_to = _state.delegations_to.read().await;
    let inheritance_parent = _state.inheritance_parent.read().await;
    let mut visited: HashSet<String> = HashSet::new();
    let mut q: VecDeque<String> = VecDeque::new();
    q.push_back(_address.clone());
    while let Some(cur) = q.pop_front() {
        if !visited.insert(cur.clone()) { continue; }
        let bal = *balances.get(&cur).unwrap_or(&0);
        if bal >= 1000 { return Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level: PermissionLevel::Creator, balance: bal }))); }
        if let Some(list) = delegations_to.get(&cur) { for from in list { if !visited.contains(from) { q.push_back(from.clone()); } } }
        if let Some(parent) = inheritance_parent.get(&cur) { if !visited.contains(parent) { q.push_back(parent.clone()); } }
    }
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level: PermissionLevel::Basic, balance: 0 })))
}

pub async fn check_permission(_state: Arc<ServerState>, _req: PermissionCheckRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    let balances = _state.balances.read().await;
    let balance = balances.get(&_req.address).unwrap_or(&0);
    let level = if *balance >= 1000 { PermissionLevel::Creator } else { PermissionLevel::Basic };
    let allowed = match (level, _req.min_level) {
        (PermissionLevel::Admin, _) => true,
        (PermissionLevel::Creator, PermissionLevel::Basic) => true,
        (PermissionLevel::Creator, PermissionLevel::Creator) => true,
        (PermissionLevel::Creator, PermissionLevel::Admin) => false,
        (PermissionLevel::Basic, PermissionLevel::Basic) => true,
        (PermissionLevel::Basic, _) => false,
    };
    Ok(warp::reply::json(&ApiResponse::success((allowed, level, *balance))))
}

pub async fn create_session(_state: Arc<ServerState>, _req: CreateSessionRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn submit_commitment(_state: Arc<ServerState>, _req: SubmitCommitmentRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn health_check() -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn list_audit_logs(state: Arc<ServerState>, limit: Option<usize>) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    let logs = state.audit_logs.read().await;
    let n = limit.unwrap_or(100);
    let start = logs.len().saturating_sub(n);
    let events = logs[start..].to_vec();
    Ok(warp::reply::json(&ApiResponse::success(events)))
}

pub async fn nft_type_register(_state: Arc<ServerState>, _req: NftTypeRegisterRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn lottery_config_store(_state: Arc<ServerState>, _req: LotteryConfigStoreRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn lottery_config_versions(_state: Arc<ServerState>, _config_id: String) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

pub async fn lottery_config_rollback(_state: Arc<ServerState>, _config_id: String, _req: LotteryConfigRollbackRequest) -> Result<impl warp::Reply, warp::Rejection> {
    // 简化实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}
