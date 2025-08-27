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
}

impl Default for SerialPoolConfig {
    fn default() -> Self {
        Self { pre_generate: 0, serial_hex_len: 32 }
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
}

impl SerialService {
    /// 创建服务并可选预生成序号
    pub async fn new(config: SerialPoolConfig) -> Self {
        let service = Self { inner: Arc::new(RwLock::new(SerialState::default())) };
        if config.pre_generate > 0 {
            service.pre_generate(config.pre_generate, config.serial_hex_len).await;
        }
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

    /// 分配一个序号（可指定会话和拥有者）
    pub async fn allocate(&self, session_id: Option<String>, owner: Option<String>, hex_len: usize) -> Result<SerialRecord, String> {
        let mut state = self.inner.write().await;

        let serial = match state.available.pop_front() {
            Some(s) => s,
            None => {
                let s = generate_unique_serial(&state.records, hex_len);
                state.records.insert(s.clone(), SerialRecord::new(s.clone()));
                s
            }
        };

        let sid_for_index = session_id.clone();
        // 取出、修改、再插回，避免可变借用重叠
        let mut record = state.records.remove(&serial).ok_or_else(|| "序号不存在".to_string())?;
        record.status = SerialStatus::Assigned;
        record.owner = owner.clone();
        record.session_id = session_id;
        record.updated_at = current_ts();
        let updated_record = record.clone();
        state.records.insert(serial.clone(), record);

        if let Some(sid) = sid_for_index {
            state.assigned_index.entry(sid).or_default().insert(serial.clone());
        }

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
        state.available.push_back(serial_owned);
        Ok(())
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
        let service = SerialService::new(SerialPoolConfig { pre_generate: 2, serial_hex_len: 16 }).await;
        let rec1 = service.allocate(Some("s1".to_string()), Some("user1".to_string()), 16).await.unwrap();
        assert_eq!(rec1.status, SerialStatus::Assigned);
        let got = service.get(&rec1.serial).await.unwrap();
        assert_eq!(got.owner.as_deref(), Some("user1"));

        service.recycle(&rec1.serial).await.unwrap();
        let got2 = service.get(&rec1.serial).await.unwrap();
        assert_eq!(got2.status, SerialStatus::Recycled);
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
}


