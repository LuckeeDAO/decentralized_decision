use serde::{Serialize, Deserialize};
use warp::http::HeaderMap;

#[derive(Debug, Serialize, Deserialize)]
pub struct ApiResponse<T> {
    pub success: bool,
    pub data: Option<T>,
    pub error: Option<String>,
}

impl<T> ApiResponse<T> {
    pub fn success(data: T) -> Self {
        Self { success: true, data: Some(data), error: None }
    }
    pub fn error(err: String) -> Self {
        Self { success: false, data: None, error: Some(err) }
    }
}

// 质押相关类型
#[derive(Debug, Serialize, Deserialize)]
pub struct StakeRequest {
    pub amount: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnstakeRequest {
    pub amount: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct LockRequest {
    pub amount: u128,
    pub lock_duration: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct UnlockRequest {
    pub amount: u128,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StakingInfoResponse {
    pub staked: u128,
    pub locked: u128,
    pub available: u128,
    pub apr: u32,
}

// 资格相关类型
#[derive(Debug, Serialize, Deserialize)]
pub struct QualStatusSetRequest {
    pub token_id: String,
    pub status: String,
    pub metadata: Option<serde_json::Value>,
}

// NFT 类型相关
#[derive(Debug, Serialize, Deserialize)]
pub struct NftTypeRegisterRequest {
    pub type_id: String,
    pub name: String,
    pub description: String,
    pub metadata_schema: serde_json::Value,
    pub version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NftTypeValidateRequest {
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NftTypeRollbackRequest {
    pub version: u32,
}

// IPFS 相关类型
#[derive(Debug, Deserialize)]
pub struct IpfsUploadRequest {
    pub metadata: serde_json::Value,
    pub token_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct IpfsUploadResponse {
    pub cid: String,
}

#[derive(Debug, Deserialize)]
pub struct IpfsVerifyRequest {
    pub cid: String,
    pub metadata: serde_json::Value,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct IpfsVerifyResponse {
    pub valid: bool,
}

#[derive(Debug, Deserialize)]
pub struct ImportCacheRequest { 
    pub items: Vec<(String, String)> 
}

// 抽奖配置相关类型
#[derive(Debug, Deserialize)]
pub struct LotteryConfigStoreRequest {
    pub config_id: String,
    pub type_id: String,
    pub config: serde_json::Value,
}

#[derive(Debug, Deserialize)]
pub struct LotteryConfigRollbackRequest {
    pub version: u32,
}

#[derive(Debug, Serialize)]
pub struct LotteryConfigStoreResponse {
    pub cid: String,
    pub version: u32,
}

#[derive(Debug, Serialize)]
pub struct LotteryConfigVersion {
    pub version: u32,
    pub cid: String,
    pub timestamp: u64,
}

#[derive(Debug, Serialize)]
pub struct LotteryConfigVersionsResponse {
    pub items: Vec<(u32, String, u64)>,
}

#[derive(Debug, Serialize)]
pub struct SchemaValidateResponse {
    pub valid: bool,
    pub errors: Vec<String>,
}

// 序号相关类型
#[derive(Debug, Deserialize)]
pub struct SerialAllocReq { 
    pub session_id: Option<String>, 
    pub owner: Option<String>, 
    pub hex_len: Option<usize> 
}

#[derive(Debug, Deserialize)]
pub struct SerialRecycleReq { 
    pub serial: String 
}

// 质押事件相关类型
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum StakeEventKind { 
    Stake, 
    Unstake, 
    Lock, 
    Unlock 
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeEvent {
    pub timestamp: u64,
    pub address: String,
    pub kind: StakeEventKind,
    pub amount: u128,
}

#[derive(Debug, Deserialize)]
pub struct StakeConditionSetReq { 
    pub address: String, 
    pub satisfied: bool 
}

// 权限相关类型
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "lowercase")]
pub enum PermissionLevel {
    Basic,
    Creator,
    Admin,
}

#[derive(Debug, Deserialize)]
pub struct UpdatePermissionRequest {
    pub address: String,
    pub balance: u128,
}

#[derive(Debug, Deserialize)]
pub struct RevokePermissionRequest {
    pub address: String,
}

#[derive(Debug, Deserialize)]
pub struct DelegatePermissionRequest {
    pub from: String,
    pub to: String,
}

#[derive(Debug, Deserialize)]
pub struct InheritPermissionRequest {
    pub child: String,
    pub parent: String,
}

#[derive(Debug, Deserialize)]
pub struct UninheritPermissionRequest {
    pub child: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PermissionLevelResponse {
    pub level: PermissionLevel,
    pub balance: u128,
}

#[derive(Debug, Deserialize)]
pub struct PermissionCheckRequest {
    pub address: String,
    pub min_level: PermissionLevel,
}

#[derive(Debug, Serialize)]
pub struct PermissionCheckResponse {
    pub allowed: bool,
    pub level: PermissionLevel,
    pub balance: u128,
}

// 工具函数
#[allow(dead_code)]
pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[allow(dead_code)]
pub fn header_address(headers: &HeaderMap) -> Option<String> {
    headers
        .get("X-User-Address")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

// 简单的元数据基本校验（必填字段）
#[allow(dead_code)]
pub fn validate_basic_metadata(meta: &serde_json::Value) -> Result<(), String> {
    if !meta.is_object() { return Err("metadata必须是JSON对象".to_string()); }
    let obj = meta.as_object().unwrap();
    let required = ["name", "description"]; // 可扩展: image, attributes, etc.
    for k in required.iter() {
        if !obj.contains_key(*k) { return Err(format!("缺少必填字段: {}", k)); }
    }
    Ok(())
}


