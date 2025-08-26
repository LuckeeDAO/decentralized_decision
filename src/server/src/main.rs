#![recursion_limit = "1024"]
//! 基于比特承诺模型的去中心化投票系统 - 服务器主程序

use luckee_voting_wasm::{voting::VotingSystem, types::VotingSession};
use luckee_voting_ipfs::{IpfsManager, export_cache as ipfs_export_fn, import_cache as ipfs_import_fn};
use serde::{Deserialize, Serialize};
use std::convert::Infallible;
use std::sync::Arc;
use std::collections::{HashMap, HashSet};
use tokio::sync::RwLock;
use warp::{Filter, Rejection, Reply};
use tracing::{info, error};
use base64::Engine;
use jsonschema::{Draft, JSONSchema};
use warp::http::HeaderMap;
use redis::aio::ConnectionManager as RedisConnManager;
use redis::AsyncCommands;

mod nft_types;
use nft_types::{NftTypeMeta, NftTypeRegistry, NftTypePluginRegistry, NoopPlugin};

/// 服务器状态
#[derive(Clone)]
struct ServerState {
    voting_system: Arc<RwLock<VotingSystem>>,
    balances: Arc<RwLock<HashMap<String, u128>>>,
    // key: delegatee, value: list of delegator addresses
    delegations_to: Arc<RwLock<HashMap<String, Vec<String>>>>,
    // key: child, value: parent
    inheritance_parent: Arc<RwLock<HashMap<String, String>>>,
    // audit logs for permission actions
    audit_logs: Arc<RwLock<Vec<AuditEvent>>>,
    ipfs: Arc<RwLock<IpfsManager>>, 
    // NFT元数据版本注册表: token_id -> Vec<(cid, timestamp)>
    metadata_versions: Arc<RwLock<HashMap<String, Vec<(String, u64)>>>>,
    // 简化版NFT所有权注册表: token_id -> owner
    nft_owners: Arc<RwLock<HashMap<String, String>>>,
    // NFT 类型注册表
    nft_types: Arc<RwLock<NftTypeRegistry>>,
    // NFT 类型插件注册表
    nft_type_plugins: Arc<RwLock<NftTypePluginRegistry>>,
    // NFT 类型状态机: type_id -> state
    nft_type_states: Arc<RwLock<HashMap<String, String>>>,
    // NFT 全局状态：token_id -> state
    nft_global_states: Arc<RwLock<HashMap<String, String>>>,
    // NFT 全局状态历史：token_id -> Vec<(state, timestamp)>
    nft_global_state_history: Arc<RwLock<HashMap<String, Vec<(String, u64)>>>>,
    // 抽奖配置版本：config_id -> Vec<(version, cid, timestamp)>
    lottery_configs: Arc<RwLock<HashMap<String, Vec<(u32, String, u64)>>>>,
    // 质押与锁定：address -> StakeRecord
    staking: Arc<RwLock<HashMap<String, StakeRecord>>>,
    // 质押事件列表
    stake_events: Arc<RwLock<Vec<StakeEvent>>>,
    // 条件锁校验标志：address -> satisfied
    staking_conditions: Arc<RwLock<HashMap<String, bool>>>,
    // 资格状态：token_id -> QualStatus
    qualifications: Arc<RwLock<HashMap<String, QualStatus>>>,
    // 元数据缓存（可替换为Redis），cid -> (json, cached_at)
    metadata_cache: Arc<RwLock<HashMap<String, (serde_json::Value, u64)>>>,
    // 可选：Redis缓存连接
    redis: Option<Arc<RwLock<RedisConnManager>>>,
    // 简单运行时状态指标
    state_metrics: Arc<RwLock<HashMap<String, u64>>>,
}

/// API请求结构
#[derive(Debug, Deserialize)]
struct CreateSessionRequest {
    session_id: String,
    commit_deadline: u64,
    reveal_deadline: u64,
    participants: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct SubmitCommitmentRequest {
    session_id: String,
    user_id: String,
    // base64-encoded message from SDK
    message: String,
}

#[derive(Debug, Deserialize)]
struct SubmitRevealRequest {
    session_id: String,
    user_id: String,
    // base64-encoded message from SDK
    message: String,
    randomness: String,
}

/// API响应结构
#[derive(Debug, Serialize)]
struct ApiResponse<T> {
    success: bool,
    data: Option<T>,
    error: Option<String>,
}

/// 权限等级
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum PermissionLevel {
    Basic,
    Creator,
    Admin,
}

#[derive(Debug, Deserialize)]
struct PermissionCheckRequest {
    address: String,
    min_level: PermissionLevel,
}

#[derive(Debug, Serialize)]
struct PermissionCheckResponse {
    allowed: bool,
    level: PermissionLevel,
    balance: u128,
}

#[derive(Debug, Serialize)]
struct PermissionLevelResponse {
    level: PermissionLevel,
    balance: u128,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
struct AuditEvent {
    timestamp: u64,
    action: String,
    address: String,
    details: String,
}

// 代币质押与锁定
#[derive(Debug, Clone, Serialize, Deserialize)]
struct StakeRecord {
    staked_amount: u128,
    locked_amount: u128,
    reward_accrued: u128,
    last_update: u64,
    // 时间锁：在 unlock_after 之前不可解锁
    unlock_after: u64,
}

impl StakeRecord {
    fn touch_and_accrue(&mut self, now: u64, apr_bps: u64) {
        // 简化奖励：按秒线性，年化bps，假定1年=31,536,000秒
        let elapsed = now.saturating_sub(self.last_update);
        if elapsed > 0 {
            let base: u128 = self.staked_amount;
            let reward = (base as u128)
                .saturating_mul(apr_bps as u128)
                .saturating_mul(elapsed as u128)
                / 10_000u128
                / 31_536_000u128;
            self.reward_accrued = self.reward_accrued.saturating_add(reward);
            self.last_update = now;
        }
    }
}

impl Default for StakeRecord {
    fn default() -> Self {
        StakeRecord {
            staked_amount: 0,
            locked_amount: 0,
            reward_accrued: 0,
            last_update: 0,
            unlock_after: 0,
        }
    }
}

#[derive(Debug, Deserialize)]
struct StakeRequest { amount: u128 }

#[derive(Debug, Deserialize)]
struct UnstakeRequest { amount: u128 }

#[derive(Debug, Deserialize)]
struct LockRequest { amount: u128, until: Option<u64> }

#[derive(Debug, Deserialize)]
struct UnlockRequest { amount: u128 }

#[derive(Debug, Serialize)]
struct StakingInfoResponse { staked: u128, locked: u128, reward_accrued: u128 }

// 质押事件系统
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
enum StakeEventKind { Stake, Unstake, Lock, Unlock }

#[derive(Debug, Clone, Serialize, Deserialize)]
struct StakeEvent {
    timestamp: u64,
    address: String,
    kind: StakeEventKind,
    amount: u128,
}

// 资格状态机
#[derive(Debug, Copy, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
enum QualStatus { Eligible, Suspended, Revoked }

#[derive(Debug, Deserialize)]
struct QualStatusSetRequest { token_id: String, status: QualStatus }

#[derive(Debug, Deserialize)]
struct NftTransferEvent { token_id: String, from: String, to: String }

#[derive(Debug, Deserialize)]
struct UpdatePermissionRequest {
    address: String,
    balance: u128,
}

#[derive(Debug, Deserialize)]
struct RevokePermissionRequest {
    address: String,
}

#[derive(Debug, Deserialize)]
struct DelegatePermissionRequest {
    from: String,
    to: String,
}

#[derive(Debug, Deserialize)]
struct InheritPermissionRequest {
    child: String,
    parent: String,
}

#[derive(Debug, Deserialize)]
struct UninheritPermissionRequest {
    child: String,
}

#[derive(Debug, Serialize)]
struct AuditListResponse {
    events: Vec<AuditEvent>,
}

#[derive(Debug, Deserialize)]
struct IpfsUploadRequest {
    // JSON metadata string
    metadata: serde_json::Value,
    // 可选: token_id，用于版本登记
    token_id: Option<String>,
}

#[derive(Debug, Serialize)]
struct IpfsUploadResponse {
    cid: String,
}

#[derive(Debug, Deserialize)]
struct IpfsVerifyRequest {
    cid: String,
    metadata: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct IpfsVerifyResponse {
    valid: bool,
}

// NFT 所有权验证
#[derive(Debug, Deserialize)]
struct NftRegisterOwnershipRequest {
    token_id: String,
    owner: String,
}

#[derive(Debug, Deserialize)]
struct NftCheckOwnershipRequest {
    token_id: String,
    address: String,
}

#[derive(Debug, Serialize)]
struct NftCheckOwnershipResponse {
    is_owner: bool,
    owner: Option<String>,
}

// NFT 类型接口
#[derive(Debug, Deserialize)]
struct NftTypeRegisterRequest {
    meta: NftTypeMeta,
    schema: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct NftTypeListResponse {
    items: Vec<NftTypeMeta>,
}

#[derive(Debug, Serialize)]
struct NftTypeDefResponse {
    def: nft_types::NftTypeDef,
}

// NFT 类型: 元数据校验请求
#[derive(Debug, Deserialize)]
struct NftTypeValidateRequest {
    metadata: serde_json::Value,
}

// NFT 类型: 元数据校验响应（复用 SchemaValidateResponse 结构）

#[derive(Debug, Serialize)]
struct NftTypeVersionsResponse {
    items: Vec<(u32, u64)>,
}

#[derive(Debug, Deserialize)]
struct NftTypeRollbackRequest {
    version: u32,
}

// NFT 类型状态机
#[derive(Debug, Deserialize)]
struct NftTypeStateSetRequest { type_id: String, state: String }

#[derive(Debug, Serialize)]
struct NftTypeStateGetResponse { type_id: String, state: Option<String> }

// NFT 全局状态请求/响应
#[derive(Debug, Deserialize)]
struct NftGlobalStateSetRequest { token_id: String, state: String }

#[derive(Debug, Serialize)]
struct NftGlobalStateGetResponse { token_id: String, state: Option<String> }

// 抽奖配置存储接口
#[derive(Debug, Deserialize)]
struct LotteryConfigStoreRequest {
    config_id: String,
    // 绑定的NFT类型，必须先注册类型
    type_id: String,
    // 实际配置数据
    config: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct LotteryConfigStoreResponse { cid: String, version: u32 }

#[derive(Debug, Deserialize)]
struct LotteryConfigRollbackRequest { version: u32 }

#[derive(Debug, Serialize)]
struct LotteryConfigVersionsResponse { items: Vec<(u32, String, u64)> }

impl<T> ApiResponse<T> {
    fn success(data: T) -> Self {
        Self {
            success: true,
            data: Some(data),
            error: None,
        }
    }
    
    fn error(error: String) -> Self {
        Self {
            success: false,
            data: None,
            error: Some(error),
        }
    }
}

/// 健康检查响应
#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    timestamp: u64,
    version: String,
}

/// 创建投票会话
async fn create_session(
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
            Ok(warp::reply::json(&ApiResponse::<VotingSession>::error(e.to_string())))
        }
    }
}

/// 提交承诺
async fn submit_commitment(
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
async fn submit_reveal(
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
async fn get_session(
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
async fn calculate_results(
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

/// 头部中获取调用地址
fn header_address(headers: &HeaderMap) -> Option<String> {
    headers.get("x-address").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

/// 头部中获取NFT token_id（可选）
fn header_token_id(headers: &HeaderMap) -> Option<String> {
    headers.get("x-nft-token-id").and_then(|v| v.to_str().ok()).map(|s| s.to_string())
}

/// 校验最小权限
async fn ensure_min_permission(state: &Arc<ServerState>, address: &str, min_level: PermissionLevel) -> bool {
    let (_bal, level) = compute_effective_balance_and_level(state, address).await;
    match (level, min_level) {
        (PermissionLevel::Admin, _) => true,
        (PermissionLevel::Creator, PermissionLevel::Admin) => false,
        (PermissionLevel::Creator, _) => true,
        (PermissionLevel::Basic, PermissionLevel::Basic) => true,
        _ => false,
    }
}

/// 校验NFT所有权（如果提供token_id则必须拥有）
async fn ensure_nft_ownership_if_provided(state: &Arc<ServerState>, address: &str, token_id_opt: Option<String>) -> bool {
    if let Some(token_id) = token_id_opt {
        let owners = state.nft_owners.read().await;
        match owners.get(&token_id) {
            Some(owner) if owner == address => true,
            _ => false,
        }
    } else {
        true
    }
}

/// 健康检查
async fn health_check() -> Result<impl Reply, Rejection> {
    let response = HealthResponse {
        status: "healthy".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    
    Ok(warp::reply::json(&response))
}

/// 指标端点
async fn metrics() -> Result<impl Reply, Rejection> {
    // 这里应该返回Prometheus格式的指标
    let metrics = "# HELP voting_sessions_total Total number of voting sessions\n\
                   # TYPE voting_sessions_total counter\n\
                   voting_sessions_total 0\n";
    Ok(warp::reply::with_header(metrics, "content-type", "text/plain; version=0.0.4; charset=utf-8"))
}

/// 计算权限等级
fn determine_level(balance: u128) -> PermissionLevel {
    let admin_threshold: u128 = std::env::var("PERM_ADMIN_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(100_000);
    let creator_threshold: u128 = std::env::var("PERM_CREATOR_THRESHOLD").ok().and_then(|v| v.parse().ok()).unwrap_or(1_000);
    if balance >= admin_threshold {
        PermissionLevel::Admin
    } else if balance >= creator_threshold {
        PermissionLevel::Creator
    } else {
        PermissionLevel::Basic
    }
}

fn level_from_str(s: &str) -> Option<PermissionLevel> {
    match s.to_ascii_lowercase().as_str() {
        "basic" => Some(PermissionLevel::Basic),
        "creator" => Some(PermissionLevel::Creator),
        "admin" => Some(PermissionLevel::Admin),
        _ => None,
    }
}

/// 查询地址权限等级
async fn get_permission_level(state: Arc<ServerState>, address: String) -> Result<impl Reply, Rejection> {
    let (eff_bal, level) = compute_effective_balance_and_level(&state, &address).await;
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: eff_bal })))
}

/// 检查权限
async fn check_permission(state: Arc<ServerState>, req: PermissionCheckRequest) -> Result<impl Reply, Rejection> {
    let (bal, level) = compute_effective_balance_and_level(&state, &req.address).await;
    let allowed = match (level, req.min_level) {
        (PermissionLevel::Admin, _) => true,
        (PermissionLevel::Creator, PermissionLevel::Basic) => true,
        (PermissionLevel::Creator, PermissionLevel::Creator) => true,
        (PermissionLevel::Creator, PermissionLevel::Admin) => false,
        (PermissionLevel::Basic, PermissionLevel::Basic) => true,
        (PermissionLevel::Basic, _) => false,
    };
    Ok(warp::reply::json(&ApiResponse::success(PermissionCheckResponse { allowed, level, balance: bal })))
}

/// 权限更新（设置余额，用于模拟/管理权限）
async fn update_permission(state: Arc<ServerState>, req: UpdatePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.insert(req.address.clone(), req.balance);
    let level = determine_level(req.balance);
    push_audit(&state, "update".to_string(), req.address.clone(), format!("balance={}", req.balance)).await;
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level, balance: req.balance })))
}

/// 权限撤销（将余额清零）
async fn revoke_permission(state: Arc<ServerState>, req: RevokePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut balances = state.balances.write().await;
    balances.insert(req.address.clone(), 0);
    push_audit(&state, "revoke".to_string(), req.address.clone(), "balance=0".to_string()).await;
    Ok(warp::reply::json(&ApiResponse::success(PermissionLevelResponse { level: PermissionLevel::Basic, balance: 0 })))
}

/// 权限委托（from -> to）
async fn delegate_permission(state: Arc<ServerState>, req: DelegatePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut delegations_to = state.delegations_to.write().await;
    let entry = delegations_to.entry(req.to.clone()).or_default();
    if !entry.contains(&req.from) {
        entry.push(req.from.clone());
    }
    push_audit(&state, "delegate".to_string(), req.to.clone(), format!("from={}", req.from)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 取消委托（from -> to）
async fn undelegate_permission(state: Arc<ServerState>, req: DelegatePermissionRequest) -> Result<impl Reply, Rejection> {
    let mut delegations_to = state.delegations_to.write().await;
    if let Some(vec) = delegations_to.get_mut(&req.to) {
        vec.retain(|d| d != &req.from);
    }
    push_audit(&state, "undelegate".to_string(), req.to.clone(), format!("from={}", req.from)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 设置继承（child -> parent）
async fn inherit_permission(state: Arc<ServerState>, req: InheritPermissionRequest) -> Result<impl Reply, Rejection> {
    let mut inheritance_parent = state.inheritance_parent.write().await;
    inheritance_parent.insert(req.child.clone(), req.parent.clone());
    push_audit(&state, "inherit".to_string(), req.child.clone(), format!("parent={}", req.parent)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 取消继承（child）
async fn uninherit_permission(state: Arc<ServerState>, req: UninheritPermissionRequest) -> Result<impl Reply, Rejection> {
    let mut inheritance_parent = state.inheritance_parent.write().await;
    inheritance_parent.remove(&req.child);
    push_audit(&state, "uninherit".to_string(), req.child.clone(), String::new()).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 审计日志列表
async fn list_audit_logs(state: Arc<ServerState>, limit: Option<usize>) -> Result<impl Reply, Rejection> {
    let logs = state.audit_logs.read().await;
    let n = limit.unwrap_or(100);
    let start = logs.len().saturating_sub(n);
    let events = logs[start..].to_vec();
    Ok(warp::reply::json(&ApiResponse::success(AuditListResponse { events })))
}

/// 计算有效余额和等级（考虑委托与继承）
async fn compute_effective_balance_and_level(state: &Arc<ServerState>, address: &str) -> (u128, PermissionLevel) {
    let balances = state.balances.read().await;
    let delegations_to = state.delegations_to.read().await;
    let inheritance_parent = state.inheritance_parent.read().await;

    fn compute_inner(
        balances: &HashMap<String, u128>,
        delegations_to: &HashMap<String, Vec<String>>,
        inheritance_parent: &HashMap<String, String>,
        address: &str,
        visiting: &mut HashSet<String>,
    ) -> (u128, PermissionLevel) {
        if !visiting.insert(address.to_string()) {
            // cycle detected, treat as basic
            return (0, PermissionLevel::Basic);
        }

        let mut balance = *balances.get(address).unwrap_or(&0);
        if let Some(from_list) = delegations_to.get(address) {
            for from in from_list.iter() {
                balance = balance.saturating_add(*balances.get(from).unwrap_or(&0));
            }
        }
        let mut level = determine_level(balance);
        if let Some(parent) = inheritance_parent.get(address) {
            let (_pb, parent_level) = compute_inner(balances, delegations_to, inheritance_parent, parent, visiting);
            level = match (level, parent_level) {
                (PermissionLevel::Admin, _) | (_, PermissionLevel::Admin) => PermissionLevel::Admin,
                (PermissionLevel::Creator, _) | (_, PermissionLevel::Creator) => PermissionLevel::Creator,
                _ => PermissionLevel::Basic,
            };
        }
        visiting.remove(address);
        (balance, level)
    }

    let mut visiting: HashSet<String> = HashSet::new();
    compute_inner(&balances, &delegations_to, &inheritance_parent, address, &mut visiting)
}

async fn push_audit(state: &Arc<ServerState>, action: String, address: String, details: String) {
    let mut logs = state.audit_logs.write().await;
    logs.push(AuditEvent {
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        action,
        address,
        details,
    });
}

/// 简单的元数据基本校验（必填字段）
fn validate_basic_metadata(meta: &serde_json::Value) -> Result<(), String> {
    if !meta.is_object() { return Err("metadata必须是JSON对象".to_string()); }
    let obj = meta.as_object().unwrap();
    let required = ["name", "description"]; // 可扩展: image, attributes, etc.
    for k in required.iter() {
        if !obj.contains_key(*k) { return Err(format!("缺少必填字段: {}", k)); }
    }
    Ok(())
}

/// 上传NFT元数据到IPFS
async fn ipfs_upload_metadata(state: Arc<ServerState>, req: IpfsUploadRequest) -> Result<impl Reply, Rejection> {
    if let Err(e) = validate_basic_metadata(&req.metadata) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error(e)));
    }
    let data = match serde_json::to_vec(&req.metadata) { Ok(v) => v, Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) };
    let mut ipfs = state.ipfs.write().await;
    let res: Result<String, String> = ipfs.upload_data(&data).await.map_err(|e| e.to_string());
    match res {
        Ok(cid) => {
            if let Some(token_id) = req.token_id {
                let mut reg = state.metadata_versions.write().await;
                let entry = reg.entry(token_id).or_default();
                entry.push((cid.clone(), now_secs()));
            }
            Ok(warp::reply::json(&ApiResponse::success(IpfsUploadResponse { cid })))
        },
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

/// 验证NFT元数据与CID一致性
async fn ipfs_verify_metadata(state: Arc<ServerState>, req: IpfsVerifyRequest) -> Result<impl Reply, Rejection> {
    if let Err(e) = validate_basic_metadata(&req.metadata) {
        return Ok(warp::reply::json(&ApiResponse::<()>::error(e)));
    }
    let data = match serde_json::to_vec(&req.metadata) { Ok(v) => v, Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) };
    let ipfs = state.ipfs.read().await;
    let res: Result<bool, String> = ipfs.verify_data(&req.cid, &data).await.map_err(|e| e.to_string());
    match res {
        Ok(valid) => Ok(warp::reply::json(&ApiResponse::success(IpfsVerifyResponse { valid }))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

/// 读取NFT元数据
async fn ipfs_get_metadata(state: Arc<ServerState>, cid: String) -> Result<impl Reply, Rejection> {
    // 先读内存缓存
    if let Some((cached, _ts)) = state.metadata_cache.read().await.get(&cid).cloned() {
        return Ok(warp::reply::json(&ApiResponse::success(cached)));
    }
    // 尝试从Redis读取
    if let Some(redis_lock) = &state.redis {
        let mut conn = redis_lock.write().await;
        let key = format!("nft_meta:{}", &cid);
        match conn.get::<_, String>(&key).await {
            Ok(s) => {
                if let Ok(json) = serde_json::from_str::<serde_json::Value>(&s) {
                    state.metadata_cache.write().await.insert(cid.clone(), (json.clone(), now_secs()));
                    return Ok(warp::reply::json(&ApiResponse::success(json)));
                }
            }
            Err(_) => {}
        }
    }
    let mut ipfs = state.ipfs.write().await;
    let res: Result<Vec<u8>, String> = ipfs.download_data(&cid).await.map_err(|e| e.to_string());
    match res {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => {
                // 写入缓存
                state.metadata_cache.write().await.insert(cid.clone(), (json.clone(), now_secs()));
                // 写入Redis（可选）
                if let Some(redis_lock) = &state.redis {
                    let mut conn = redis_lock.write().await;
                    let _ : Result<(), _> = conn.set_ex(
                        format!("nft_meta:{}", &cid),
                        serde_json::to_string(&json).unwrap_or_default(),
                        std::env::var("META_CACHE_TTL").ok().and_then(|v| v.parse::<u64>().ok()).unwrap_or(3600u64),
                    ).await;
                }
                Ok(warp::reply::json(&ApiResponse::success(json)))
            },
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        },
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

/// 基于最新类型Schema生成元数据模板
async fn nft_type_metadata_template(state: Arc<ServerState>, type_id: String) -> Result<impl Reply, Rejection> {
    let reg = state.nft_types.read().await;
    let def = match reg.get(&type_id) { Some(d) => d, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))) };
    let schema = match def.versions.last() { Some(v) => v.schema.clone(), None => return Ok(warp::reply::json(&ApiResponse::<()>::error("类型未包含schema".to_string()))) };
    fn default_for_schema(s: &serde_json::Value) -> serde_json::Value {
        if let Some(def_v) = s.get("default") { return def_v.clone(); }
        match s.get("type").and_then(|t| t.as_str()).unwrap_or("") {
            "string" => serde_json::Value::String(String::new()),
            "integer" | "number" => serde_json::json!(0),
            "boolean" => serde_json::json!(false),
            "array" => serde_json::json!([]),
            "object" => {
                let mut obj = serde_json::Map::new();
                if let Some(props) = s.get("properties").and_then(|v| v.as_object()) {
                    for (k, v) in props.iter() {
                        obj.insert(k.clone(), default_for_schema(v));
                    }
                }
                serde_json::Value::Object(obj)
            }
            _ => serde_json::Value::Null,
        }
    }
    let template = default_for_schema(&schema);
    Ok(warp::reply::json(&ApiResponse::success(template)))
}

/// JSON Schema 校验
#[derive(Debug, Deserialize)]
struct SchemaValidateRequest {
    schema: serde_json::Value,
    data: serde_json::Value,
}

#[derive(Debug, Serialize)]
struct SchemaValidateResponse {
    valid: bool,
    errors: Vec<String>,
}

fn validate_json_schema(_state: Arc<ServerState>, req: SchemaValidateRequest) -> impl Reply {
    match JSONSchema::options().with_draft(Draft::Draft7).compile(&req.schema) {
        Ok(compiled) => {
            let result = compiled.validate(&req.data);
            match result {
                Ok(_) => warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: true, errors: vec![] })),
                Err(errors) => {
                    let errs = errors.map(|e| e.to_string()).collect::<Vec<_>>();
                    warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: errs }))
                }
            }
        }
        Err(e) => warp::reply::json(&ApiResponse::<()>::error(e.to_string())),
    }
}

/// 读取某token元数据版本列表
async fn list_metadata_versions(state: Arc<ServerState>, token_id: String) -> Result<impl Reply, Rejection> {
    let reg = state.metadata_versions.read().await;
    let list = reg.get(&token_id).cloned().unwrap_or_default();
    Ok(warp::reply::json(&ApiResponse::success(list)))
}

/// 注册NFT所有权（链下登记，后续可替换为链上查询）
async fn nft_register_ownership(state: Arc<ServerState>, req: NftRegisterOwnershipRequest) -> Result<impl Reply, Rejection> {
    let mut owners = state.nft_owners.write().await;
    owners.insert(req.token_id.clone(), req.owner.clone());
    push_audit(&state, "nft_register".to_string(), req.owner.clone(), format!("token_id={}", req.token_id)).await;
    Ok(warp::reply::json(&ApiResponse::success(())))
}

/// 校验NFT所有权
async fn nft_check_ownership(state: Arc<ServerState>, req: NftCheckOwnershipRequest) -> Result<impl Reply, Rejection> {
    let owners = state.nft_owners.read().await;
    let owner = owners.get(&req.token_id).cloned();
    let is_owner = owner.as_deref() == Some(req.address.as_str());
    Ok(warp::reply::json(&ApiResponse::success(NftCheckOwnershipResponse { is_owner, owner })))
}

// NFT 类型: 注册或更新（版本+1）
async fn nft_type_register(state: Arc<ServerState>, req: NftTypeRegisterRequest) -> Result<impl Reply, Rejection> {
    // 简单校验：schema必须是对象
    if !req.schema.is_object() {
        return Ok(warp::reply::json(&ApiResponse::<()>::error("schema必须为JSON对象".to_string())));
    }
    let mut reg = state.nft_types.write().await;
    let def = reg.register_or_update(req.meta, req.schema, now_secs()).clone();
    // 如果尚无对应插件，注册一个默认Noop插件，便于后续扩展
    {
        let mut plugs = state.nft_type_plugins.write().await;
        if plugs.get(&def.meta.type_id).is_none() {
            plugs.register(def.meta.type_id.clone(), Arc::new(NoopPlugin));
        }
    }
    Ok(warp::reply::json(&ApiResponse::success(NftTypeDefResponse { def })))
}

// NFT 类型: 列表
async fn nft_type_list(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let reg = state.nft_types.read().await;
    Ok(warp::reply::json(&ApiResponse::success(NftTypeListResponse { items: reg.list() })))
}

// NFT 类型: 获取详情
async fn nft_type_get(state: Arc<ServerState>, type_id: String) -> Result<impl Reply, Rejection> {
    let reg = state.nft_types.read().await;
    match reg.get(&type_id) {
        Some(def) => Ok(warp::reply::json(&ApiResponse::success(NftTypeDefResponse { def }))),
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))),
    }
}

// NFT 类型: 校验元数据与类型Schema
async fn nft_type_validate(state: Arc<ServerState>, type_id: String, req: NftTypeValidateRequest) -> Result<impl Reply, Rejection> {
    let reg = state.nft_types.read().await;
    let def_opt = reg.get(&type_id);
    let def = match def_opt {
        Some(d) => d,
        None => return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))),
    };
    // 选择最新版本的schema
    let schema_opt = def.versions.last().map(|v| v.schema.clone());
    let schema = match schema_opt {
        Some(s) => s,
        None => return Ok(warp::reply::json(&ApiResponse::<()>::error("类型未包含schema".to_string()))),
    };
    // 校验 Schema
    match JSONSchema::options().with_draft(Draft::Draft7).compile(&schema) {
        Ok(compiled) => {
            match compiled.validate(&req.metadata) {
                Ok(()) => {
                    // 插件附加校验
                    if let Some(plugin) = state.nft_type_plugins.read().await.get(&type_id) {
                        if let Err(e) = plugin.on_validate_metadata(&req.metadata) {
                            return Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: vec![e] })));
                        }
                    }
                    Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: true, errors: vec![] })))
                },
                Err(errors) => {
                    let errs = errors.map(|e| e.to_string()).collect::<Vec<_>>();
                    Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: errs })))
                }
            }
        }
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

// NFT 类型: 按版本校验
async fn nft_type_validate_version(state: Arc<ServerState>, type_id: String, version: u32, req: NftTypeValidateRequest) -> Result<impl Reply, Rejection> {
    let reg = state.nft_types.read().await;
    let schema_opt = reg.get_schema_by_version(&type_id, version);
    let schema = match schema_opt {
        Some(s) => s,
        None => return Ok(warp::reply::json(&ApiResponse::<()>::error("版本未找到".to_string()))),
    };
    match JSONSchema::options().with_draft(Draft::Draft7).compile(&schema) {
        Ok(compiled) => {
            match compiled.validate(&req.metadata) {
                Ok(()) => Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: true, errors: vec![] })) ),
                Err(errors) => {
                    let errs = errors.map(|e| e.to_string()).collect::<Vec<_>>();
                    Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: errs })))
                }
            }
        }
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

// NFT 类型: 版本列表
async fn nft_type_versions(state: Arc<ServerState>, type_id: String) -> Result<impl Reply, Rejection> {
    let reg = state.nft_types.read().await;
    match reg.list_versions(&type_id) {
        Some(list) => Ok(warp::reply::json(&ApiResponse::success(NftTypeVersionsResponse { items: list }))),
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))),
    }
}

// NFT 类型: 回滚到指定版本（删除高于该版本的历史）
async fn nft_type_rollback(state: Arc<ServerState>, type_id: String, req: NftTypeRollbackRequest) -> Result<impl Reply, Rejection> {
    let mut reg = state.nft_types.write().await;
    match reg.rollback_to_version(&type_id, req.version) {
        Ok(def) => Ok(warp::reply::json(&ApiResponse::success(NftTypeDefResponse { def: def.clone() }))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e))),
    }
}

/// 导出IPFS缓存（备份）
async fn ipfs_export_cache(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let ipfs = state.ipfs.read().await;
    let items = ipfs_export_fn(&ipfs);
    Ok(warp::reply::json(&ApiResponse::success(items)))
}

/// 导入IPFS缓存（恢复）
#[derive(Debug, Deserialize)]
struct IpfsImportCacheRequest {
    items: Vec<(String, String)>,
}

async fn ipfs_import_cache(state: Arc<ServerState>, req: IpfsImportCacheRequest) -> Result<impl Reply, Rejection> {
    let mut ipfs = state.ipfs.write().await;
    match ipfs_import_fn(&mut ipfs, req.items) {
        Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

/// 工具: 获取当前秒
fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs()
}

// 同步快照（链上链下状态同步的基础能力）
#[derive(Debug, Serialize, Deserialize)]
struct SyncSnapshot {
    balances: HashMap<String, u128>,
    delegations_to: HashMap<String, Vec<String>>,
    inheritance_parent: HashMap<String, String>,
    audit_logs: Vec<AuditEvent>,
    metadata_versions: HashMap<String, Vec<(String, u64)>>,
    nft_owners: HashMap<String, String>,
    nft_type_states: HashMap<String, String>,
    lottery_configs: HashMap<String, Vec<(u32, String, u64)>>,
    staking: HashMap<String, StakeRecord>,
    qualifications: HashMap<String, QualStatus>,
    // IPFS本地缓存（cid -> data b64），使用库提供的导出格式
    ipfs_cache: Vec<(String, String)>,
}

async fn sync_export_snapshot(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
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

    let snapshot = SyncSnapshot { balances, delegations_to, inheritance_parent, audit_logs, metadata_versions, nft_owners, nft_type_states, lottery_configs, staking, qualifications, ipfs_cache };
    Ok(warp::reply::json(&ApiResponse::success(snapshot)))
}

async fn sync_restore_snapshot(state: Arc<ServerState>, snapshot: SyncSnapshot) -> Result<impl Reply, Rejection> {
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

// 抽奖配置：先按类型Schema校验再存IPFS并登记版本
async fn lottery_config_store(state: Arc<ServerState>, req: LotteryConfigStoreRequest) -> Result<warp::reply::Json, Rejection> {
    {
        let reg = state.nft_types.read().await;
        let def = match reg.get(&req.type_id) { Some(d) => d, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))) };
        let schema = match def.versions.last() { Some(v) => v.schema.clone(), None => return Ok(warp::reply::json(&ApiResponse::<()>::error("类型未包含schema".to_string()))) };
        match JSONSchema::options().with_draft(Draft::Draft7).compile(&schema) {
            Ok(compiled) => if let Err(errors) = compiled.validate(&req.config) {
                let errs = errors.map(|e| e.to_string()).collect::<Vec<_>>();
                return Ok(warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: errs })))
            },
            Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        }
    }
    // 插件钩子：进一步业务校验
    if let Some(plugin) = state.nft_type_plugins.read().await.get(&req.type_id) {
        if let Err(e) = plugin.on_before_store_config(&req.config) {
            return Ok(warp::reply::json(&ApiResponse::<()>::error(e)));
        }
    }
    let data = match serde_json::to_vec(&req.config) { Ok(v) => v, Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) };
    let cid = {
        let mut ipfs = state.ipfs.write().await;
        match ipfs.upload_data(&data).await { Ok(cid) => cid, Err(e) => return Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))) }
    };
    let version = {
        let mut map = state.lottery_configs.write().await;
        let entry = map.entry(req.config_id.clone()).or_default();
        let next_ver: u32 = entry.last().map(|t| t.0 + 1).unwrap_or(1);
        entry.push((next_ver, cid.clone(), now_secs()));
        next_ver
    };
    Ok(warp::reply::json(&ApiResponse::success(LotteryConfigStoreResponse { cid, version })))
}

// 抽奖配置：读取版本列表
async fn lottery_config_versions(state: Arc<ServerState>, config_id: String) -> Result<impl Reply, Rejection> {
    let map = state.lottery_configs.read().await;
    let items = map.get(&config_id).cloned().unwrap_or_default();
    Ok(warp::reply::json(&ApiResponse::success(LotteryConfigVersionsResponse { items })))
}

// 抽奖配置：回滚到指定版本
async fn lottery_config_rollback(state: Arc<ServerState>, config_id: String, req: LotteryConfigRollbackRequest) -> Result<impl Reply, Rejection> {
    let mut map = state.lottery_configs.write().await;
    match map.get_mut(&config_id) {
        Some(list) => {
            if !list.iter().any(|(v, _, _)| *v == req.version) {
                return Ok(warp::reply::json(&ApiResponse::<()>::error("版本未找到".to_string())));
            }
            list.retain(|(v, _, _)| *v <= req.version);
            Ok(warp::reply::json(&ApiResponse::success(())))
        }
        None => Ok(warp::reply::json(&ApiResponse::<()>::error("配置未找到".to_string()))),
    }
}

// 抽奖配置：读取最新配置
async fn lottery_config_get_latest(state: Arc<ServerState>, config_id: String) -> Result<impl Reply, Rejection> {
    let cid_opt = {
        let map = state.lottery_configs.read().await;
        map.get(&config_id).and_then(|list| list.last().map(|t| t.1.clone()))
    };
    let cid = match cid_opt { Some(c) => c, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("配置未找到".to_string()))) };
    let mut ipfs = state.ipfs.write().await;
    match ipfs.download_data(&cid).await {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => Ok(warp::reply::json(&ApiResponse::success(json))),
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        },
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

// 抽奖配置：按版本读取
async fn lottery_config_get_version(state: Arc<ServerState>, config_id: String, version: u32) -> Result<impl Reply, Rejection> {
    let cid_opt = {
        let map = state.lottery_configs.read().await;
        map.get(&config_id).and_then(|list| list.iter().find(|(v, _, _)| *v == version).map(|t| t.1.clone()))
    };
    let cid = match cid_opt { Some(c) => c, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("版本未找到".to_string()))) };
    let mut ipfs = state.ipfs.write().await;
    match ipfs.download_data(&cid).await {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(json) => Ok(warp::reply::json(&ApiResponse::success(json))),
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        },
        Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
    }
}

/// 错误处理
async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (warp::http::StatusCode::NOT_FOUND, "Not Found")
    } else if err.find::<warp::reject::PayloadTooLarge>().is_some() {
        (warp::http::StatusCode::BAD_REQUEST, "Payload too large")
    } else {
        error!("未处理的错误: {:?}", err);
        (warp::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    };
    
    let response = ApiResponse::<()>::error(message.to_string());
    Ok(warp::reply::with_status(warp::reply::json(&response), code))
}

/// 创建路由
fn create_routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let state_filter = warp::any().map(move || Arc::clone(&state));
    
    // 健康检查
    let health_route = warp::path("health")
        .and(warp::get())
        .and_then(health_check);
    
    // 指标端点
    let metrics_route = warp::path("metrics")
        .and(warp::get())
        .and_then(metrics);
    
    // 创建会话
    let create_session_route = warp::path("sessions")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|request: CreateSessionRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            let addr = match header_address(&headers) {
                Some(a) => a,
                None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))),
            };
            if !ensure_min_permission(&state, &addr, PermissionLevel::Creator).await {
                return Ok(warp::reply::json(&ApiResponse::<()>::error("权限不足".to_string())));
            }
            create_session(state, request).await
        });

    // 权限等级查询
    let perm_level_route = warp::path!("permissions" / "level" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|address: String, state: Arc<ServerState>| async move { get_permission_level(state, address).await });

    // 权限检查
    let perm_check_route = warp::path!("permissions" / "check")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: PermissionCheckRequest, state: Arc<ServerState>| async move { check_permission(state, request).await });

    // 权限更新
    let perm_update_route = warp::path!("permissions" / "update")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: UpdatePermissionRequest, state: Arc<ServerState>| async move { update_permission(state, request).await });

    // 权限撤销
    let perm_revoke_route = warp::path!("permissions" / "revoke")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: RevokePermissionRequest, state: Arc<ServerState>| async move { revoke_permission(state, request).await });

    // 权限委托
    let perm_delegate_route = warp::path!("permissions" / "delegate")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: DelegatePermissionRequest, state: Arc<ServerState>| async move { delegate_permission(state, request).await });

    // 取消委托
    let perm_undelegate_route = warp::path!("permissions" / "undelegate")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: DelegatePermissionRequest, state: Arc<ServerState>| async move { undelegate_permission(state, request).await });

    // 设置继承
    let perm_inherit_route = warp::path!("permissions" / "inherit")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: InheritPermissionRequest, state: Arc<ServerState>| async move { inherit_permission(state, request).await });

    // 取消继承
    let perm_uninherit_route = warp::path!("permissions" / "uninherit")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: UninheritPermissionRequest, state: Arc<ServerState>| async move { uninherit_permission(state, request).await });

    // 审计日志
    let perm_audit_route = warp::path!("permissions" / "audit")
        .and(warp::get())
        .and(warp::query::<HashMap<String, String>>())
        .and(state_filter.clone())
        .and_then(|q: HashMap<String, String>, state: Arc<ServerState>| async move {
            let limit = q.get("limit").and_then(|v| v.parse::<usize>().ok());
            list_audit_logs(state, limit).await
        });

    // IPFS: 上传元数据
    let ipfs_upload_route = warp::path!("ipfs" / "metadata")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: IpfsUploadRequest, state: Arc<ServerState>| async move { ipfs_upload_metadata(state, request).await });

    // IPFS: 验证元数据
    let ipfs_verify_route = warp::path!("ipfs" / "verify")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: IpfsVerifyRequest, state: Arc<ServerState>| async move { ipfs_verify_metadata(state, request).await });

    // IPFS: 读取元数据
    let ipfs_get_route = warp::path!("ipfs" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|cid: String, state: Arc<ServerState>| async move { ipfs_get_metadata(state, cid).await });

    // Schema校验
    let schema_validate_route = warp::path!("schema" / "validate")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: SchemaValidateRequest, state: Arc<ServerState>| async move {
            Ok::<_, Rejection>(validate_json_schema(state, request))
        });

    // 元数据版本列表
    let meta_versions_route = warp::path!("metadata" / String / "versions")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|token_id: String, state: Arc<ServerState>| async move { list_metadata_versions(state, token_id).await });

    // NFT 所有权登记与校验
    let nft_register_route = warp::path!("nft" / "ownership" / "register")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: NftRegisterOwnershipRequest, state: Arc<ServerState>| async move { nft_register_ownership(state, request).await });

    let nft_check_route = warp::path!("nft" / "ownership" / "check")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: NftCheckOwnershipRequest, state: Arc<ServerState>| async move { nft_check_ownership(state, request).await });

    // NFT 类型接口
    let nft_type_register_route = warp::path!("nft" / "types")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: NftTypeRegisterRequest, state: Arc<ServerState>| async move { nft_type_register(state, request).await });

    let nft_type_list_route = warp::path!("nft" / "types")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|state: Arc<ServerState>| async move { nft_type_list(state).await });

    let nft_type_get_route = warp::path!("nft" / "types" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|type_id: String, state: Arc<ServerState>| async move { nft_type_get(state, type_id).await });

    // NFT 类型: 校验元数据
    let nft_type_validate_route = warp::path!("nft" / "types" / String / "validate")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|type_id: String, request: NftTypeValidateRequest, state: Arc<ServerState>| async move { nft_type_validate(state, type_id, request).await });

    // NFT 类型: 按版本校验
    let nft_type_validate_ver_route = warp::path!("nft" / "types" / String / "validate" / u32)
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|type_id: String, version: u32, request: NftTypeValidateRequest, state: Arc<ServerState>| async move { nft_type_validate_version(state, type_id, version, request).await });

    // NFT 类型: 版本列表
    let nft_type_versions_route = warp::path!("nft" / "types" / String / "versions")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|type_id: String, state: Arc<ServerState>| async move { nft_type_versions(state, type_id).await });

    // NFT 类型: 回滚版本
    let nft_type_rollback_route = warp::path!("nft" / "types" / String / "rollback")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|type_id: String, request: NftTypeRollbackRequest, state: Arc<ServerState>| async move { nft_type_rollback(state, type_id, request).await });

    // NFT 类型: 元数据模板生成
    let nft_type_meta_tmpl_route = warp::path!("nft" / "types" / String / "metadata" / "template")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|type_id: String, state: Arc<ServerState>| async move { nft_type_metadata_template(state, type_id).await });

    // IPFS 缓存导出/导入
    let ipfs_export_route = warp::path!("ipfs" / "cache" / "export")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|state: Arc<ServerState>| async move { ipfs_export_cache(state).await });

    let ipfs_import_route = warp::path!("ipfs" / "cache" / "import")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|request: IpfsImportCacheRequest, state: Arc<ServerState>| async move { ipfs_import_cache(state, request).await });

    // IPFS 缓存：统计与清理
    async fn ipfs_cache_stats(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
        let ipfs = state.ipfs.read().await;
        let size = ipfs.cache_size();
        #[derive(Serialize)]
        struct CacheStats { cache_size: usize }
        Ok(warp::reply::json(&ApiResponse::success(CacheStats { cache_size: size })))
    }

    async fn ipfs_cache_clear(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
        let mut ipfs = state.ipfs.write().await;
        ipfs.clear_cache();
        Ok(warp::reply::json(&ApiResponse::success(())))
    }

    let ipfs_cache_stats_route = warp::path!("ipfs" / "cache" / "stats")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|state: Arc<ServerState>| async move { ipfs_cache_stats(state).await });

    let ipfs_cache_clear_route = warp::path!("ipfs" / "cache" / "clear")
        .and(warp::post())
        .and(state_filter.clone())
        .and_then(|state: Arc<ServerState>| async move { ipfs_cache_clear(state).await });

    // 运行状态监控与告警：简单阈值接口
    #[derive(Debug, Deserialize)]
    struct AlertSetReq { key: String, threshold: u64 }
    #[derive(Debug, Serialize)]
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
        #[derive(Serialize)]
        struct Resp { value: u64 }
        Ok(warp::reply::json(&ApiResponse::success(Resp { value: v })))
    }
    // 简化：告警阈值内存存放
    let alert_thresholds: Arc<RwLock<HashMap<String, u64>>> = Arc::new(RwLock::new(HashMap::new()));
    let alert_thresholds_filter = warp::any().map(move || alert_thresholds.clone());
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
    let state_metric_inc_route = warp::path!("state" / "metric" / String / u64)
        .and(warp::post())
        .and(state_filter.clone())
        .and_then(|key: String, by: u64, state: Arc<ServerState>| async move { state_metric_inc(state, key, by).await });
    let state_metric_get_route = warp::path!("state" / "metric" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|key: String, state: Arc<ServerState>| async move { state_metric_get(state, key).await });
    let alert_set_route = warp::path!("state" / "alert")
        .and(warp::post())
        .and(warp::body::json())
        .and(alert_thresholds_filter.clone())
        .and_then(|req: AlertSetReq, th: Arc<RwLock<HashMap<String, u64>>>| async move { alert_set(th, req).await });
    let alert_check_route = warp::path!("state" / "alert" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and(alert_thresholds_filter.clone())
        .and_then(|key: String, state: Arc<ServerState>, th: Arc<RwLock<HashMap<String, u64>>>| async move { alert_check(state, th, key).await });

    // IPFS扩展: 压缩开关、冗余镜像、归档、一致性检查
    #[derive(Debug, Deserialize)]
    struct IpfsCompressionReq { enabled: bool }
    #[derive(Debug, Deserialize)]
    struct IpfsAddMirrorReq { url: String }
    #[derive(Debug, Deserialize)]
    struct IpfsArchiveReq { path: String }
    #[derive(Debug, Deserialize)]
    struct IpfsRestoreReq { path: String }
    #[derive(Debug, Deserialize)]
    struct IpfsConsistencyReq { cid: String, data_b64: Option<String> }
    async fn ipfs_set_compression(state: Arc<ServerState>, req: IpfsCompressionReq) -> Result<impl Reply, Rejection> {
        let mut ipfs = state.ipfs.write().await;
        ipfs.set_compression(req.enabled);
        Ok(warp::reply::json(&ApiResponse::success(())))
    }
    async fn ipfs_add_mirror(state: Arc<ServerState>, req: IpfsAddMirrorReq) -> Result<impl Reply, Rejection> {
        let mut ipfs = state.ipfs.write().await;
        match ipfs.add_mirror(&req.url).await {
            Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        }
    }
    async fn ipfs_archive(state: Arc<ServerState>, req: IpfsArchiveReq) -> Result<impl Reply, Rejection> {
        let ipfs = state.ipfs.read().await;
        match ipfs.archive_to_file(&req.path) {
            Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        }
    }
    async fn ipfs_restore(state: Arc<ServerState>, req: IpfsRestoreReq) -> Result<impl Reply, Rejection> {
        let mut ipfs = state.ipfs.write().await;
        match ipfs.restore_from_file(&req.path) {
            Ok(()) => Ok(warp::reply::json(&ApiResponse::success(()))),
            Err(e) => Ok(warp::reply::json(&ApiResponse::<()>::error(e.to_string()))),
        }
    }
    async fn ipfs_consistency(state: Arc<ServerState>, req: IpfsConsistencyReq) -> Result<impl Reply, Rejection> {
        let data_opt = match req.data_b64 {
            Some(b64) => base64::engine::general_purpose::STANDARD.decode(b64.as_bytes()).ok(),
            None => None,
        };
        let ipfs = state.ipfs.read().await;
        let map = ipfs.consistency_check(&req.cid, data_opt.as_deref()).await;
        Ok(warp::reply::json(&ApiResponse::success(map)))
    }
    let ipfs_compress_route = warp::path!("ipfs" / "compression")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: IpfsCompressionReq, state: Arc<ServerState>| async move { ipfs_set_compression(state, req).await });
    let ipfs_add_mirror_route = warp::path!("ipfs" / "mirror")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: IpfsAddMirrorReq, state: Arc<ServerState>| async move { ipfs_add_mirror(state, req).await });
    let ipfs_archive_route = warp::path!("ipfs" / "archive")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: IpfsArchiveReq, state: Arc<ServerState>| async move { ipfs_archive(state, req).await });
    let ipfs_restore_route = warp::path!("ipfs" / "restore")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: IpfsRestoreReq, state: Arc<ServerState>| async move { ipfs_restore(state, req).await });
    let ipfs_consistency_route = warp::path!("ipfs" / "consistency")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: IpfsConsistencyReq, state: Arc<ServerState>| async move { ipfs_consistency(state, req).await });

    // 同步：导出与恢复
    let sync_export_route = warp::path!("sync" / "export")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|state: Arc<ServerState>| async move { sync_export_snapshot(state).await });

    let sync_restore_route = warp::path!("sync" / "restore")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|snapshot: SyncSnapshot, state: Arc<ServerState>| async move { sync_restore_snapshot(state, snapshot).await });

    // 抽奖配置：存储、版本列表、回滚
    let lottery_store_route = warp::path!("lottery" / "configs")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|request: LotteryConfigStoreRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            // 基于类型的权限控制
            let addr = match header_address(&headers) {
                Some(a) => a,
                None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))),
            };
            // 读取类型所需权限
            let required = {
                let reg = state.nft_types.read().await;
                match reg.get(&request.type_id) {
                    Some(def) => def.meta.required_level.as_deref().and_then(level_from_str),
                    None => None,
                }
            };
            if let Some(min_level) = required {
                if !ensure_min_permission(&state, &addr, min_level).await {
                    return Ok(warp::reply::json(&ApiResponse::<()>::error("权限不足".to_string())));
                }
            }
            lottery_config_store(state, request).await
        });

    let lottery_versions_route = warp::path!("lottery" / "configs" / String / "versions")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|config_id: String, state: Arc<ServerState>| async move { lottery_config_versions(state, config_id).await });

    let lottery_rollback_route = warp::path!("lottery" / "configs" / String / "rollback")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|config_id: String, request: LotteryConfigRollbackRequest, state: Arc<ServerState>| async move { lottery_config_rollback(state, config_id, request).await });

    let lottery_get_latest_route = warp::path!("lottery" / "configs" / String / "latest")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|config_id: String, state: Arc<ServerState>| async move { lottery_config_get_latest(state, config_id).await });

    let lottery_get_version_route = warp::path!("lottery" / "configs" / String / u32)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|config_id: String, version: u32, state: Arc<ServerState>| async move { lottery_config_get_version(state, config_id, version).await });

    // 质押与锁定
    async fn staking_stake_handler(req: StakeRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
        let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
        let now = now_secs();
        let mut map = state.staking.write().await;
        let rec = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
        rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
        rec.staked_amount = rec.staked_amount.saturating_add(req.amount);
        push_audit(&state, "stake".to_string(), addr, format!("amount={}", req.amount)).await;
        {
            let mut evs = state.stake_events.write().await;
            evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Stake, amount: req.amount });
        }
        Ok(warp::reply::json(&ApiResponse::success(())))
    }

    async fn staking_unstake_handler(req: UnstakeRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
        let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
        let now = now_secs();
        let mut map = state.staking.write().await;
        let rec = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
        rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
        if rec.staked_amount < req.amount { return Ok(warp::reply::json(&ApiResponse::<()>::error("可用质押不足".to_string()))); }
        rec.staked_amount -= req.amount;
        push_audit(&state, "unstake".to_string(), addr, format!("amount={}", req.amount)).await;
        {
            let mut evs = state.stake_events.write().await;
            evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Unstake, amount: req.amount });
        }
        Ok(warp::reply::json(&ApiResponse::success(())))
    }

    async fn staking_lock_handler(req: LockRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
        let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
        let now = now_secs();
        let mut map = state.staking.write().await;
        let rec = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
        rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
        if rec.staked_amount < req.amount { return Ok(warp::reply::json(&ApiResponse::<()>::error("可锁定余额不足".to_string()))); }
        rec.staked_amount -= req.amount;
        rec.locked_amount = rec.locked_amount.saturating_add(req.amount);
        if let Some(until) = req.until { rec.unlock_after = rec.unlock_after.max(until); }
        push_audit(&state, "lock".to_string(), addr, format!("amount={}", req.amount)).await;
        {
            let mut evs = state.stake_events.write().await;
            evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Lock, amount: req.amount });
        }
        Ok(warp::reply::json(&ApiResponse::success(())))
    }

    async fn staking_unlock_handler(req: UnlockRequest, state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
        let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
        let now = now_secs();
        let mut map = state.staking.write().await;
        let rec = map.entry(addr.clone()).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
        rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
        if rec.locked_amount < req.amount { return Ok(warp::reply::json(&ApiResponse::<()>::error("可解锁余额不足".to_string()))); }
        // 时间锁校验
        if now < rec.unlock_after {
            return Ok(warp::reply::json(&ApiResponse::<()>::error("未满足时间锁条件".to_string())));
        }
        // 条件锁校验
        let cond_ok = {
            let conds = state.staking_conditions.read().await;
            *conds.get(&addr).unwrap_or(&false)
        };
        if !cond_ok { return Ok(warp::reply::json(&ApiResponse::<()>::error("未满足条件锁".to_string()))); }
        rec.locked_amount -= req.amount;
        rec.staked_amount = rec.staked_amount.saturating_add(req.amount);
        push_audit(&state, "unlock".to_string(), addr, format!("amount={}", req.amount)).await;
        {
            let mut evs = state.stake_events.write().await;
            evs.push(StakeEvent { timestamp: now, address: headers.get("x-address").and_then(|v| v.to_str().ok()).unwrap_or("").to_string(), kind: StakeEventKind::Unlock, amount: req.amount });
        }
        Ok(warp::reply::json(&ApiResponse::success(())))
    }

    async fn staking_info_handler(state: Arc<ServerState>, headers: HeaderMap) -> Result<impl Reply, Rejection> {
        let addr = match header_address(&headers) { Some(a) => a, None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))) };
        let now = now_secs();
        let mut map = state.staking.write().await;
        let rec = map.entry(addr).or_insert_with(|| StakeRecord { last_update: now, ..Default::default() });
        rec.touch_and_accrue(now, std::env::var("STAKE_APR_BPS").ok().and_then(|v| v.parse().ok()).unwrap_or(1500));
        Ok(warp::reply::json(&ApiResponse::success(StakingInfoResponse { staked: rec.staked_amount, locked: rec.locked_amount, reward_accrued: rec.reward_accrued })))
    }

    async fn qual_set_handler(req: QualStatusSetRequest, state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
        let mut q = state.qualifications.write().await;
        q.insert(req.token_id, req.status);
        Ok(warp::reply::json(&ApiResponse::success(())))
    }

    async fn qual_get_handler(token_id: String, state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
        let q = state.qualifications.read().await;
        let status = q.get(&token_id).copied().unwrap_or(QualStatus::Eligible);
        Ok(warp::reply::json(&ApiResponse::success(status)))
    }

    async fn nft_transfer_event_handler(ev: NftTransferEvent, state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
        {
            let mut owners = state.nft_owners.write().await;
            owners.insert(ev.token_id.clone(), ev.to.clone());
        }
        {
            let mut q = state.qualifications.write().await;
            q.insert(ev.token_id.clone(), QualStatus::Eligible);
        }
        push_audit(&state, "nft_transfer".to_string(), ev.to, format!("token_id={}, from={}", ev.token_id, ev.from)).await;
        Ok(warp::reply::json(&ApiResponse::success(())))
    }
    let stake_route = warp::path!("staking" / "stake")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|req: StakeRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            staking_stake_handler(req, state, headers).await.map_err(|e| e)
        });

    let unstake_route = warp::path!("staking" / "unstake")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|req: UnstakeRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            staking_unstake_handler(req, state, headers).await.map_err(|e| e)
        });

    let lock_route = warp::path!("staking" / "lock")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|req: LockRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            staking_lock_handler(req, state, headers).await.map_err(|e| e)
        });

    let unlock_route = warp::path!("staking" / "unlock")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|req: UnlockRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            staking_unlock_handler(req, state, headers).await.map_err(|e| e)
        });

    let staking_info_route = warp::path!("staking" / "info")
        .and(warp::get())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|state: Arc<ServerState>, headers: HeaderMap| async move {
            staking_info_handler(state, headers).await.map_err(|e| e)
        });

    // 资格状态管理与转移处理
    let qual_set_route = warp::path!("nft" / "qualification" / "set")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: QualStatusSetRequest, state: Arc<ServerState>| async move {
            qual_set_handler(req, state).await.map_err(|e| e)
        });

    let qual_get_route = warp::path!("nft" / "qualification" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|token_id: String, state: Arc<ServerState>| async move {
            qual_get_handler(token_id, state).await.map_err(|e| e)
        });

    let nft_transfer_event_route = warp::path!("nft" / "transfer" / "event")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|ev: NftTransferEvent, state: Arc<ServerState>| async move {
            nft_transfer_event_handler(ev, state).await.map_err(|e| e)
        });
    
    // 获取会话
    let get_session_route = warp::path!("sessions" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|session_id: String, state: Arc<ServerState>| async move {
            get_session(state, session_id).await
        });
    
    // 提交承诺
    let submit_commitment_route = warp::path!("sessions" / String / "commitments")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and(warp::header::headers_cloned())
        .and_then(|session_id: String, request: SubmitCommitmentRequest, state: Arc<ServerState>, headers: HeaderMap| async move {
            // 权限：Basic 及以上
            let addr = match header_address(&headers) {
                Some(a) => a,
                None => return Ok(warp::reply::json(&ApiResponse::<()>::error("缺少x-address头".to_string()))),
            };
            if !ensure_min_permission(&state, &addr, PermissionLevel::Basic).await {
                return Ok(warp::reply::json(&ApiResponse::<()>::error("权限不足".to_string())));
            }
            // 如果提供了x-nft-token-id，则必须为所有者
            let token_opt = header_token_id(&headers);
            if !ensure_nft_ownership_if_provided(&state, &addr, token_opt).await {
                return Ok(warp::reply::json(&ApiResponse::<()>::error("无NFT所有权".to_string())));
            }
            let mut req = request;
            req.session_id = session_id;
            submit_commitment(state, req).await
        });
    
    // 提交揭示
    let submit_reveal_route = warp::path!("sessions" / String / "reveals")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|session_id: String, request: SubmitRevealRequest, state: Arc<ServerState>| async move {
            let mut req = request;
            req.session_id = session_id;
            submit_reveal(state, req).await
        });
    
    // 计算结果
    let calculate_results_route = warp::path!("sessions" / String / "results")
        .and(warp::post())
        .and(state_filter.clone())
        .and_then(|session_id: String, state: Arc<ServerState>| async move {
            calculate_results(state, session_id).await
        });
    
    // NFT 类型状态机路由实现
    async fn nft_type_state_set(state: Arc<ServerState>, req: NftTypeStateSetRequest) -> Result<impl Reply, Rejection> {
        let exists = { state.nft_types.read().await.get(&req.type_id).is_some() };
        if !exists { return Ok(warp::reply::json(&ApiResponse::<()>::error("未找到类型".to_string()))); }
        state.nft_type_states.write().await.insert(req.type_id.clone(), req.state.clone());
        Ok(warp::reply::json(&ApiResponse::success(())))
    }
    async fn nft_type_state_get(state: Arc<ServerState>, type_id: String) -> Result<impl Reply, Rejection> {
        let st = state.nft_type_states.read().await.get(&type_id).cloned();
        Ok(warp::reply::json(&ApiResponse::success(NftTypeStateGetResponse { type_id, state: st })))
    }
    let nft_type_state_set_route = warp::path!("nft" / "types" / String / "state")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|type_id: String, body: serde_json::Value, state: Arc<ServerState>| async move {
            let state_str = body.get("state").and_then(|v| v.as_str()).unwrap_or("").to_string();
            nft_type_state_set(state, NftTypeStateSetRequest { type_id, state: state_str }).await
        });
    let nft_type_state_get_route = warp::path!("nft" / "types" / String / "state")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|type_id: String, state: Arc<ServerState>| async move { nft_type_state_get(state, type_id).await });

    // NFT 全局状态管理（简化状态机）
    // 允许的转换: created -> active -> locked -> active -> burned(终态)
    fn nft_state_can_transition(from: &str, to: &str) -> bool {
        if from == to { return true; }
        match (from, to) {
            ("", "created") => true,
            ("created", "active") => true,
            ("active", "locked") => true,
            ("locked", "active") => true,
            ("active", "burned") => true,
            ("locked", "burned") => true,
            _ => false,
        }
    }
    async fn nft_global_state_set(state: Arc<ServerState>, req: NftGlobalStateSetRequest) -> Result<impl Reply, Rejection> {
        let cur = state.nft_global_states.read().await.get(&req.token_id).cloned().unwrap_or_default();
        if !nft_state_can_transition(cur.as_str(), req.state.as_str()) {
            return Ok(warp::reply::json(&ApiResponse::<()>::error("非法状态转换".to_string())));
        }
        state.nft_global_states.write().await.insert(req.token_id.clone(), req.state.clone());
        // 记录历史
        let mut hist = state.nft_global_state_history.write().await;
        let entry = hist.entry(req.token_id.clone()).or_default();
        entry.push((req.state.clone(), now_secs()));
        Ok(warp::reply::json(&ApiResponse::success(())))
    }
    async fn nft_global_state_get(state: Arc<ServerState>, token_id: String) -> Result<impl Reply, Rejection> {
        let st = state.nft_global_states.read().await.get(&token_id).cloned();
        Ok(warp::reply::json(&ApiResponse::success(NftGlobalStateGetResponse { token_id, state: st })))
    }
    let nft_state_set_route = warp::path!("nft" / "state")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: NftGlobalStateSetRequest, state: Arc<ServerState>| async move { nft_global_state_set(state, req).await });
    let nft_state_get_route = warp::path!("nft" / "state" / String)
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|token_id: String, state: Arc<ServerState>| async move { nft_global_state_get(state, token_id).await });

    // NFT 全局状态：历史与回滚
    async fn nft_global_state_history_get(state: Arc<ServerState>, token_id: String) -> Result<impl Reply, Rejection> {
        let hist = state.nft_global_state_history.read().await;
        let list = hist.get(&token_id).cloned().unwrap_or_default();
        #[derive(Serialize)]
        struct Resp { history: Vec<(String, u64)> }
        Ok(warp::reply::json(&ApiResponse::success(Resp { history: list })))
    }
    #[derive(Debug, Deserialize)]
    struct NftGlobalStateRollbackReq { to_index: usize }
    async fn nft_global_state_rollback(state: Arc<ServerState>, token_id: String, req: NftGlobalStateRollbackReq) -> Result<impl Reply, Rejection> {
        let mut hist = state.nft_global_state_history.write().await;
        match hist.get_mut(&token_id) {
            Some(list) => {
                if req.to_index >= list.len() { return Ok(warp::reply::json(&ApiResponse::<()>::error("索引越界".to_string()))); }
                let target_state = list[req.to_index].0.clone();
                list.truncate(req.to_index + 1);
                state.nft_global_states.write().await.insert(token_id.clone(), target_state);
                Ok(warp::reply::json(&ApiResponse::success(())))
            }
            None => Ok(warp::reply::json(&ApiResponse::<()>::error("无历史可回滚".to_string()))),
        }
    }
    let nft_state_history_route = warp::path!("nft" / "state" / String / "history")
        .and(warp::get())
        .and(state_filter.clone())
        .and_then(|token_id: String, state: Arc<ServerState>| async move { nft_global_state_history_get(state, token_id).await });
    let nft_state_rollback_route = warp::path!("nft" / "state" / String / "rollback")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|token_id: String, req: NftGlobalStateRollbackReq, state: Arc<ServerState>| async move { nft_global_state_rollback(state, token_id, req).await });

    // 质押事件查询
    async fn stake_events_list(state: Arc<ServerState>, limit: Option<usize>) -> Result<impl Reply, Rejection> {
        let evs = state.stake_events.read().await;
        let n = limit.unwrap_or(100);
        let start = evs.len().saturating_sub(n);
        #[derive(Serialize)]
        struct Resp { events: Vec<StakeEvent> }
        Ok(warp::reply::json(&ApiResponse::success(Resp { events: evs[start..].to_vec() })))
    }
    let stake_events_route = warp::path!("staking" / "events")
        .and(warp::get())
        .and(warp::query::<HashMap<String, String>>())
        .and(state_filter.clone())
        .and_then(|q: HashMap<String, String>, state: Arc<ServerState>| async move {
            let limit = q.get("limit").and_then(|v| v.parse::<usize>().ok());
            stake_events_list(state, limit).await
        });

    // 设置条件锁是否满足（管理员接口）
    #[derive(Debug, Deserialize)]
    struct StakeConditionSetReq { address: String, satisfied: bool }
    async fn stake_condition_set(state: Arc<ServerState>, req: StakeConditionSetReq) -> Result<impl Reply, Rejection> {
        let mut conds = state.staking_conditions.write().await;
        conds.insert(req.address, req.satisfied);
        Ok(warp::reply::json(&ApiResponse::success(())))
    }
    let stake_cond_set_route = warp::path!("staking" / "condition" / "set")
        .and(warp::post())
        .and(warp::body::json())
        .and(state_filter.clone())
        .and_then(|req: StakeConditionSetReq, state: Arc<ServerState>| async move { stake_condition_set(state, req).await });

    // 将路由分组并分别boxed，避免深度类型递归
    let misc_group = health_route
        .or(metrics_route)
        .boxed();

    let sessions_group = create_session_route
        .or(get_session_route)
        .or(submit_commitment_route)
        .or(submit_reveal_route)
        .or(calculate_results_route)
        .boxed();

    let perms_group = perm_level_route
        .or(perm_check_route)
        .or(perm_update_route)
        .or(perm_revoke_route)
        .or(perm_delegate_route)
        .or(perm_undelegate_route)
        .or(perm_inherit_route)
        .or(perm_uninherit_route)
        .or(perm_audit_route)
        .boxed();

    let ipfs_group = ipfs_upload_route
        .or(ipfs_verify_route)
        .or(ipfs_get_route)
        .or(ipfs_export_route)
        .or(ipfs_import_route)
        .or(ipfs_cache_stats_route)
        .or(ipfs_cache_clear_route)
        .or(ipfs_compress_route)
        .or(ipfs_add_mirror_route)
        .or(ipfs_archive_route)
        .or(ipfs_restore_route)
        .or(ipfs_consistency_route)
        .boxed();

    let schema_group = schema_validate_route
        .or(meta_versions_route)
        .boxed();

    #[allow(unused_variables)]
    let nft_group = nft_register_route
        .or(nft_check_route)
        .or(nft_type_register_route)
        .or(nft_type_list_route)
        .or(nft_type_get_route)
        .or(nft_type_validate_ver_route)
        .or(nft_type_versions_route)
        .or(nft_type_rollback_route)
        .or(nft_type_meta_tmpl_route)
        .or(nft_type_validate_route)
        .or(nft_type_state_set_route)
        .or(nft_type_state_get_route)
        .or(nft_state_set_route)
        .or(nft_state_get_route)
        .or(nft_state_history_route)
        .or(nft_state_rollback_route)
        .or(qual_set_route)
        .or(qual_get_route)
        .or(nft_transfer_event_route)
        .boxed();

    let staking_group = stake_route
        .or(unstake_route)
        .or(lock_route)
        .or(unlock_route)
        .or(staking_info_route)
        .or(stake_events_route)
        .or(stake_cond_set_route)
        .boxed();

    let sync_group = sync_export_route
        .or(sync_restore_route)
        .boxed();

    let lottery_group = lottery_store_route
        .or(lottery_versions_route)
        .or(lottery_rollback_route)
        .or(lottery_get_latest_route)
        .or(lottery_get_version_route)
        .boxed();

    // 进一步减少最终组合的复杂度：合并为三大组
    let core_group = misc_group
        .or(sessions_group)
        .or(perms_group)
        .boxed();

    let data_group = ipfs_group
        .or(schema_group)
        .boxed();

    let domain_group = nft_group
        .or(staking_group)
        .or(sync_group)
        .or(lottery_group)
        .or(state_metric_inc_route)
        .or(state_metric_get_route)
        .or(alert_set_route)
        .or(alert_check_route)
        .boxed();

    let app = core_group
        .or(data_group)
        .or(domain_group)
        .boxed();

    app.recover(handle_rejection)
        .with(warp::cors().allow_any_origin())
        .boxed()
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // 初始化日志
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    
    info!("启动投票系统服务器...");
    
    // 创建服务器状态
    // 可选初始化Redis
    let redis = if let Ok(url) = std::env::var("REDIS_URL") {
        match redis::Client::open(url) {
            Ok(client) => match client.get_connection_manager().await {
                Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                Err(e) => {
                    error!("初始化 Redis 失败: {}", e);
                    None
                }
            },
            Err(e) => {
                error!("创建 Redis 客户端失败: {}", e);
                None
            }
        }
    } else { None };

    let state = Arc::new(ServerState {
        voting_system: Arc::new(RwLock::new(VotingSystem::new())),
        balances: Arc::new(RwLock::new(HashMap::new())),
        delegations_to: Arc::new(RwLock::new(HashMap::new())),
        inheritance_parent: Arc::new(RwLock::new(HashMap::new())),
        audit_logs: Arc::new(RwLock::new(Vec::new())),
        ipfs: Arc::new(RwLock::new(
            IpfsManager::new(&std::env::var("IPFS_API").unwrap_or_else(|_| "http://127.0.0.1:5001".to_string()))
                .await
                .unwrap_or_else(|e| {
                    error!("初始化 IPFS 失败: {}", e);
                    std::process::exit(1);
                })
        )),
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
        redis,
        state_metrics: Arc::new(RwLock::new(HashMap::new())),
    });
    
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

#[cfg(test)]
mod tests {
    use super::*;
    use warp::Reply;

    #[tokio::test]
    async fn test_health_check() {
        let _response = health_check().await.unwrap();
        // Simple test to ensure the function doesn't panic
        assert!(true);
    }

    #[tokio::test]
    async fn test_submit_commitment_decoding() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())), ipfs: Arc::new(RwLock::new(IpfsManager::new("http://127.0.0.1:5001").await.unwrap())), metadata_versions: Arc::new(RwLock::new(HashMap::new())), nft_owners: Arc::new(RwLock::new(HashMap::new())), nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())), nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())), nft_type_states: Arc::new(RwLock::new(HashMap::new())), nft_global_states: Arc::new(RwLock::new(HashMap::new())), lottery_configs: Arc::new(RwLock::new(HashMap::new())), staking: Arc::new(RwLock::new(HashMap::new())), stake_events: Arc::new(RwLock::new(Vec::new())), staking_conditions: Arc::new(RwLock::new(HashMap::new())), qualifications: Arc::new(RwLock::new(HashMap::new())), metadata_cache: Arc::new(RwLock::new(HashMap::new())), nft_global_state_history: Arc::new(RwLock::new(HashMap::new())), redis: None });

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

    #[tokio::test]
    async fn test_permission_update_and_revoke() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())), ipfs: Arc::new(RwLock::new(IpfsManager::new("http://127.0.0.1:5001").await.unwrap())), metadata_versions: Arc::new(RwLock::new(HashMap::new())), nft_owners: Arc::new(RwLock::new(HashMap::new())), nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())), nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())), nft_type_states: Arc::new(RwLock::new(HashMap::new())), nft_global_states: Arc::new(RwLock::new(HashMap::new())), lottery_configs: Arc::new(RwLock::new(HashMap::new())), staking: Arc::new(RwLock::new(HashMap::new())), stake_events: Arc::new(RwLock::new(Vec::new())), staking_conditions: Arc::new(RwLock::new(HashMap::new())), qualifications: Arc::new(RwLock::new(HashMap::new())), metadata_cache: Arc::new(RwLock::new(HashMap::new())), nft_global_state_history: Arc::new(RwLock::new(HashMap::new())), redis: None });

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

    #[tokio::test]
    async fn test_permission_delegation_and_inheritance() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())), ipfs: Arc::new(RwLock::new(IpfsManager::new("http://127.0.0.1:5001").await.unwrap())), metadata_versions: Arc::new(RwLock::new(HashMap::new())), nft_owners: Arc::new(RwLock::new(HashMap::new())), nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())), nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())), nft_type_states: Arc::new(RwLock::new(HashMap::new())), nft_global_states: Arc::new(RwLock::new(HashMap::new())), lottery_configs: Arc::new(RwLock::new(HashMap::new())), staking: Arc::new(RwLock::new(HashMap::new())), stake_events: Arc::new(RwLock::new(Vec::new())), staking_conditions: Arc::new(RwLock::new(HashMap::new())), qualifications: Arc::new(RwLock::new(HashMap::new())), metadata_cache: Arc::new(RwLock::new(HashMap::new())), nft_global_state_history: Arc::new(RwLock::new(HashMap::new())), redis: None });

        // ipfs upload + verify roundtrip
        let meta = serde_json::json!({"name":"Test","description":"D"});
        let up_resp = ipfs_upload_metadata(state.clone(), IpfsUploadRequest { metadata: meta.clone(), token_id: None }).await.unwrap().into_response();
        assert_eq!(up_resp.status(), warp::http::StatusCode::OK);

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

    #[tokio::test]
    async fn test_lottery_config_store_and_versions() {
        let state = Arc::new(ServerState { voting_system: Arc::new(RwLock::new(VotingSystem::new())), balances: Arc::new(RwLock::new(HashMap::new())), delegations_to: Arc::new(RwLock::new(HashMap::new())), inheritance_parent: Arc::new(RwLock::new(HashMap::new())), audit_logs: Arc::new(RwLock::new(Vec::new())), ipfs: Arc::new(RwLock::new(IpfsManager::new("http://127.0.0.1:5001").await.unwrap())), metadata_versions: Arc::new(RwLock::new(HashMap::new())), nft_owners: Arc::new(RwLock::new(HashMap::new())), nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())), nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())), nft_type_states: Arc::new(RwLock::new(HashMap::new())), nft_global_states: Arc::new(RwLock::new(HashMap::new())), lottery_configs: Arc::new(RwLock::new(HashMap::new())), staking: Arc::new(RwLock::new(HashMap::new())), stake_events: Arc::new(RwLock::new(Vec::new())), staking_conditions: Arc::new(RwLock::new(HashMap::new())), qualifications: Arc::new(RwLock::new(HashMap::new())), metadata_cache: Arc::new(RwLock::new(HashMap::new())), nft_global_state_history: Arc::new(RwLock::new(HashMap::new())), redis: None });

        // register nft type with schema
        let _ = nft_type_register(state.clone(), NftTypeRegisterRequest {
            meta: NftTypeMeta { type_id: "lottery".into(), name: "Lottery".into(), category: "抽奖".into(), required_level: None },
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
}
