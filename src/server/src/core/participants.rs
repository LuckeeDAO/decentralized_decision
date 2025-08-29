//! 参与者注册与管理服务
//!
//! - 身份验证占位
//! - 注册/查询/状态/黑白名单/缓存

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use tokio::sync::RwLock;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ParticipantStatus { Registered, Suspended, Banned }

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantRecord {
    pub address: String,
    pub metadata: serde_json::Value,
    pub status: ParticipantStatus,
    pub registered_at: u64,
    pub updated_at: u64,
}

impl ParticipantRecord {
    #[allow(dead_code)]
    fn new(address: String, metadata: serde_json::Value) -> Self {
        let ts = now_secs();
        Self { address, metadata, status: ParticipantStatus::Registered, registered_at: ts, updated_at: ts }
    }
}

#[derive(Default)]
struct Store {
    #[allow(dead_code)]
    map: HashMap<String, ParticipantRecord>,
    #[allow(dead_code)]
    blacklist: HashSet<String>,
    #[allow(dead_code)]
    whitelist: HashSet<String>,
}

#[derive(Clone, Default)]
pub struct ParticipantService { 
    #[allow(dead_code)]
    inner: Arc<RwLock<Store>> 
}

impl ParticipantService {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Store::default())),
        }
    }

    /// 检查用户是否有投票权限
    pub async fn has_voting_permission(&self, _user_id: &str) -> bool {
        // 这里应该实现实际的权限检查逻辑
        // 暂时返回true
        true
    }

    /// 验证NFT所有权
    pub async fn verify_nft_ownership(&self, _user_id: &str, _nft_id: &str) -> bool {
        // TODO: 实现NFT所有权验证逻辑
        true
    }

    /// 验证NFT类型
    pub async fn verify_nft_type(&self, _nft_id: &str, _nft_type: &str) -> bool {
        // TODO: 实现NFT类型验证逻辑
        true
    }

    /// 获取NFT类型
    #[allow(dead_code)]
    pub async fn get_nft_type(&self, _nft_id: &str) -> Option<String> {
        // TODO: 实现NFT类型获取逻辑
        Some("default".to_string())
    }

    #[allow(dead_code)]
    pub async fn register(&self, address: String, metadata: serde_json::Value) -> Result<ParticipantRecord, String> {
        // 简化身份验证：要求 address 非空
        if address.trim().is_empty() { return Err("无效地址".into()); }
        let mut g = self.inner.write().await;
        if g.map.contains_key(&address) { return Err("参与者已注册".into()); }
        if g.blacklist.contains(&address) { return Err("地址在黑名单".into()); }
        let rec = ParticipantRecord::new(address.clone(), metadata);
        g.map.insert(address.clone(), rec.clone());
        Ok(rec)
    }

    #[allow(dead_code)]
    pub async fn get(&self, address: &str) -> Option<ParticipantRecord> { self.inner.read().await.map.get(address).cloned() }

    #[allow(dead_code)]
    pub async fn set_status(&self, address: &str, status: ParticipantStatus) -> Result<(), String> {
        let mut g = self.inner.write().await;
        let rec = g.map.get_mut(address).ok_or_else(|| "未注册".to_string())?;
        rec.status = status;
        rec.updated_at = now_secs();
        Ok(())
    }

    #[allow(dead_code)]
    pub async fn add_to_blacklist(&self, address: String) { self.inner.write().await.blacklist.insert(address); }
    #[allow(dead_code)]
    pub async fn remove_from_blacklist(&self, address: &str) { self.inner.write().await.blacklist.remove(address); }
    #[allow(dead_code)]
    pub async fn add_to_whitelist(&self, address: String) { self.inner.write().await.whitelist.insert(address); }
    #[allow(dead_code)]
    pub async fn remove_from_whitelist(&self, address: &str) { self.inner.write().await.whitelist.remove(address); }

    #[allow(dead_code)]
    pub async fn is_allowed(&self, address: &str) -> bool {
        let g = self.inner.read().await;
        if g.blacklist.contains(address) { return false; }
        if !g.whitelist.is_empty() { return g.whitelist.contains(address); }
        true
    }

    #[allow(dead_code)]
    pub async fn list(&self) -> Vec<ParticipantRecord> { self.inner.read().await.map.values().cloned().collect() }

    /// 参与者加入会话
    pub async fn join_session(&self, _session_id: &str, _participant_id: &str) -> Result<(), String> {
        // TODO: 实现实际的会话加入逻辑
        // 暂时返回成功
        Ok(())
    }
}

#[allow(dead_code)]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_register_and_blacklist() {
        let svc = ParticipantService::new();
        let addr = "alice".to_string();
        let rec = svc.register(addr.clone(), serde_json::json!({"age": 20})).await.unwrap();
        assert_eq!(rec.address, addr);
        assert!(svc.get(&addr).await.is_some());
        svc.add_to_blacklist("bob".into()).await;
        let err = svc.register("bob".into(), serde_json::json!({})).await.err().unwrap();
        assert!(err.contains("黑名单"));
    }
}


