//! 序号生成与分配服务
//!
//! 提供唯一序号生成、分配策略、冲突检测、验证与回收功能

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;

/// 序号状态
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum SerialStatus {
    /// 可用
    Available,
    /// 已分配
    Assigned,
    /// 已回收（进入可用池）
    Recycled,
}

/// 单个序号记录
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialRecord {
    pub serial: String,
    pub status: SerialStatus,
    pub owner: Option<String>,
    pub session_id: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

impl SerialRecord {
    fn new(serial: String) -> Self {
        let now = current_ts();
        Self {
            serial,
            status: SerialStatus::Available,
            owner: None,
            session_id: None,
            created_at: now,
            updated_at: now,
        }
    }
}

/// 序号池配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialPoolConfig {
    /// 预生成序号数量
    pub pre_generate: usize,
    /// 序号长度（十六进制字符串长度）
    pub serial_hex_len: usize,
    /// 低水位：当可用池低于该值时自动补齐到pre_generate
    pub low_watermark: usize,
}

impl Default for SerialPoolConfig {
    fn default() -> Self {
        Self { pre_generate: 0, serial_hex_len: 32, low_watermark: 0 }
    }
}

/// 序号服务，线程安全
#[derive(Clone)]
pub struct SerialService {
    inner: Arc<RwLock<SerialState>>,
}

#[derive(Default)]
struct SerialState {
    records: HashMap<String, SerialRecord>,
    available: VecDeque<String>,
    assigned_index: HashMap<String, HashSet<String>>, // session_id -> set(serial)
    audit_log: Vec<AuditEvent>,
    // 池管理配置
    pre_generate_target: usize,
    serial_hex_len: usize,
    low_watermark: usize,
}

#[allow(dead_code)]
impl SerialService {
    /// 创建服务并可选预生成序号
    pub async fn new(config: SerialPoolConfig) -> Self {
        let service = Self { inner: Arc::new(RwLock::new(SerialState { 
            records: HashMap::new(), 
            available: VecDeque::new(), 
            assigned_index: HashMap::new(), 
            audit_log: Vec::new(),
            pre_generate_target: config.pre_generate,
            serial_hex_len: config.serial_hex_len,
            low_watermark: config.low_watermark,
        })) };
        if config.pre_generate > 0 { service.ensure_capacity().await; }
        service
    }

    /// 批量预生成
    pub async fn pre_generate(&self, count: usize, hex_len: usize) {
        let mut state = self.inner.write().await;
        for _ in 0..count {
            let serial = generate_unique_serial(&state.records, hex_len);
            state.available.push_back(serial.clone());
            state.records.insert(serial.clone(), SerialRecord::new(serial));
        }
    }

    /// 确保可用池容量达到目标
    async fn ensure_capacity(&self) {
        let mut to_generate = 0usize;
        {
            let state = self.inner.read().await;
            if state.available.len() <= state.low_watermark {
                to_generate = state.pre_generate_target.saturating_sub(state.available.len());
            }
        }
        if to_generate > 0 {
            // 使用配置的hex长度预生成
            let hex_len = { self.inner.read().await.serial_hex_len };
            self.pre_generate(to_generate, hex_len).await;
        }
    }

    /// 分配一个序号（可指定会话和拥有者）
    pub async fn allocate(&self, session_id: Option<String>, owner: Option<String>, hex_len: usize) -> Result<SerialRecord, String> {
        let mut state = self.inner.write().await;

        // 若可用池低于低水位，触发补齐至目标
        if state.available.len() <= state.low_watermark {
            let deficit = state.pre_generate_target.saturating_sub(state.available.len());
            if deficit > 0 {
                // 释放写锁，批量生成后再进入写锁插入，避免长时间占用
                // 这里直接在持锁状态下生成以简化实现（生成过程O(n)，可接受）
                for _ in 0..deficit {
                    let s = generate_unique_serial(&state.records, state.serial_hex_len);
                    state.available.push_back(s.clone());
                    state.records.insert(s.clone(), SerialRecord::new(s));
                }
            }
        }

        let serial = match state.available.pop_front() {
            Some(s) => s,
            None => {
                let s = generate_unique_serial(&state.records, hex_len);
                state.records.insert(s.clone(), SerialRecord::new(s.clone()));
                s
            }
        };

        // 取出、修改、再插回，避免可变借用重叠
        let mut record = state.records.remove(&serial).ok_or_else(|| "序号不存在".to_string())?;
        record.status = SerialStatus::Assigned;
        record.owner = owner.clone();
        record.session_id = session_id;
        record.updated_at = current_ts();
        let updated_record = record.clone();
        state.records.insert(serial.clone(), record);

        if let Some(sid) = updated_record.session_id.clone() {
            state.assigned_index.entry(sid).or_default().insert(serial.clone());
        }

        state.audit_log.push(AuditEvent::allocated(&serial, owner.as_deref(), updated_record.session_id.as_deref()));

        Ok(updated_record)
    }

    /// 回收一个序号
    pub async fn recycle(&self, serial: &str) -> Result<(), String> {
        let mut state = self.inner.write().await;
        // 先移除记录，再修改并插回，避免可变别名冲突
        let mut record = state.records.remove(serial).ok_or_else(|| "序号不存在".to_string())?;
        if record.status != SerialStatus::Assigned {
            // 插回原记录
            let _ = state.records.insert(record.serial.clone(), record);
            return Err("仅支持回收已分配序号".to_string());
        }
        let sid_opt = record.session_id.clone();
        let serial_owned = record.serial.clone();
        record.status = SerialStatus::Recycled;
        record.owner = None;
        record.session_id = None;
        record.updated_at = current_ts();
        state.records.insert(serial_owned.clone(), record);
        if let Some(sid) = sid_opt {
            if let Some(set) = state.assigned_index.get_mut(&sid) {
                set.remove(serial);
            }
        }
        state.available.push_back(serial_owned.clone());
        state.audit_log.push(AuditEvent::recycled(&serial_owned));
        Ok(())
    }

    /// 转移序号所有权（仅限已分配状态）
    #[allow(dead_code)]
    pub async fn transfer(&self, serial: &str, new_owner: String, new_session: Option<String>) -> Result<SerialRecord, String> {
        let mut state = self.inner.write().await;
        // 先移除记录，再修改后插回
        let mut record = state.records.remove(serial).ok_or_else(|| "序号不存在".to_string())?;
        if record.status != SerialStatus::Assigned {
            // 插回
            let _ = state.records.insert(record.serial.clone(), record);
            return Err("仅支持转移已分配序号".to_string());
        }
        // 更新 session 索引
        if let Some(old_sid) = &record.session_id {
            if let Some(set) = state.assigned_index.get_mut(old_sid) { set.remove(serial); }
        }
        if let Some(ref sid) = new_session { state.assigned_index.entry(sid.clone()).or_default().insert(serial.to_string()); }

        record.owner = Some(new_owner.clone());
        record.session_id = new_session.clone();
        record.updated_at = current_ts();
        let updated = record.clone();
        state.records.insert(serial.to_string(), record);
        state.audit_log.push(AuditEvent::transferred(serial, updated.owner.as_deref(), updated.session_id.as_deref()));
        Ok(updated)
    }

    /// 获取审计日志快照（内存）
    #[allow(dead_code)]
    pub async fn audit_logs(&self) -> Vec<AuditEvent> {
        let state = self.inner.read().await;
        state.audit_log.clone()
    }

    /// 查询序号
    pub async fn get(&self, serial: &str) -> Option<SerialRecord> {
        let state = self.inner.read().await;
        state.records.get(serial).cloned()
    }

    /// 查询会话下的已分配序号
    pub async fn list_by_session(&self, session_id: &str) -> Vec<SerialRecord> {
        let state = self.inner.read().await;
        if let Some(set) = state.assigned_index.get(session_id) {
            set.iter().filter_map(|s| state.records.get(s).cloned()).collect()
        } else {
            Vec::new()
        }
    }

    /// 统计信息
    pub async fn stats(&self) -> SerialStats {
        let state = self.inner.read().await;
        let total = state.records.len();
        let available = state.available.len();
        let assigned = total.saturating_sub(available);
        SerialStats { total, available, assigned }
    }
}

/// 统计数据
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SerialStats {
    pub total: usize,
    pub available: usize,
    pub assigned: usize,
}

/// 审计事件
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AuditEvent {
    pub ts: u64,
    pub action: AuditAction,
    pub serial: String,
    pub owner: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuditAction { Allocated, Recycled, Transferred }

#[allow(dead_code)]
impl AuditEvent {
    #[allow(dead_code)]
    fn allocated(serial: &str, owner: Option<&str>, session: Option<&str>) -> Self {
        Self { ts: current_ts(), action: AuditAction::Allocated, serial: serial.to_string(), owner: owner.map(|s| s.to_string()), session_id: session.map(|s| s.to_string()) }
    }
    #[allow(dead_code)]
    fn recycled(serial: &str) -> Self {
        Self { ts: current_ts(), action: AuditAction::Recycled, serial: serial.to_string(), owner: None, session_id: None }
    }
    #[allow(dead_code)]
    fn transferred(serial: &str, owner: Option<&str>, session: Option<&str>) -> Self {
        Self { ts: current_ts(), action: AuditAction::Transferred, serial: serial.to_string(), owner: owner.map(|s| s.to_string()), session_id: session.map(|s| s.to_string()) }
    }
}

fn current_ts() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn generate_unique_serial(existing: &HashMap<String, SerialRecord>, hex_len: usize) -> String {
    // 使用随机32字节 + 单调时间拼接后做哈希，截断为hex_len
    let mut rng_bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut rng_bytes);
    let mut hasher = Sha256::new();
    hasher.update(&rng_bytes);
    hasher.update(current_ts().to_le_bytes());
    let digest = hasher.finalize();
    let mut serial = hex::encode(digest);
    if hex_len < serial.len() {
        serial.truncate(hex_len);
    }
    // 如冲突则递归重试（概率极低）
    if existing.contains_key(&serial) {
        return generate_unique_serial(existing, hex_len);
    }
    serial
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures::future::join_all;

    #[tokio::test]
    async fn test_allocate_and_recycle() {
        let service = SerialService::new(SerialPoolConfig { pre_generate: 2, serial_hex_len: 16, low_watermark: 0 }).await;
        let rec1 = service.allocate(Some("s1".to_string()), Some("user1".to_string()), 16).await.unwrap();
        assert_eq!(rec1.status, SerialStatus::Assigned);
        let got = service.get(&rec1.serial).await.unwrap();
        assert_eq!(got.owner.as_deref(), Some("user1"));

        service.recycle(&rec1.serial).await.unwrap();
        let got2 = service.get(&rec1.serial).await.unwrap();
        assert_eq!(got2.status, SerialStatus::Recycled);
        let logs = service.audit_logs().await;
        assert!(logs.iter().any(|e| matches!(e.action, AuditAction::Allocated)));
        assert!(logs.iter().any(|e| matches!(e.action, AuditAction::Recycled)));
    }

    #[tokio::test]
    async fn test_list_by_session_and_stats() {
        let service = SerialService::new(Default::default()).await;
        let _ = service.allocate(Some("session-x".to_string()), Some("alice".to_string()), 24).await.unwrap();
        let _ = service.allocate(Some("session-x".to_string()), Some("bob".to_string()), 24).await.unwrap();
        let list = service.list_by_session("session-x").await;
        assert_eq!(list.len(), 2);
        let stats = service.stats().await;
        assert_eq!(stats.assigned, 2);
        assert_eq!(stats.total, 2);
    }

    #[tokio::test]
    async fn test_concurrent_allocate_uniqueness() {
        let service = SerialService::new(Default::default()).await;
        let tasks = (0..64).map(|i| {
            let svc = service.clone();
            async move {
                svc.allocate(Some("s-con".to_string()), Some(format!("u{}", i)), 20).await.unwrap().serial
            }
        });
        let serials = join_all(tasks).await;
        let set: std::collections::HashSet<String> = serials.iter().cloned().collect();
        assert_eq!(set.len(), serials.len());
    }

    #[tokio::test]
    async fn test_transfer_and_audit() {
        let service = SerialService::new(Default::default()).await;
        let rec = service.allocate(Some("sess-a".into()), Some("alice".into()), 20).await.unwrap();
        let rec2 = service.transfer(&rec.serial, "bob".into(), Some("sess-b".into())).await.unwrap();
        assert_eq!(rec2.owner.as_deref(), Some("bob"));
        assert_eq!(rec2.session_id.as_deref(), Some("sess-b"));
        let logs = service.audit_logs().await;
        assert!(logs.iter().any(|e| matches!(e.action, AuditAction::Transferred)));
    }
}


