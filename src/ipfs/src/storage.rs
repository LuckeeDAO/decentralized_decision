//! IPFS存储实现

use crate::types::IpfsError;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// 存储项
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageItem {
    pub cid: String,
    pub data: Vec<u8>,
    pub metadata: HashMap<String, String>,
    pub created_at: u64,
    pub accessed_at: u64,
}

/// IPFS存储管理器
pub struct IpfsStorage {
    items: Arc<RwLock<HashMap<String, StorageItem>>>,
    max_cache_size: usize,
}

impl IpfsStorage {
    /// 创建新的存储管理器
    pub fn new(max_cache_size: usize) -> Self {
        Self {
            items: Arc::new(RwLock::new(HashMap::new())),
            max_cache_size,
        }
    }
    
    /// 存储数据
    pub async fn store(&self, key: &str, data: &[u8], metadata: HashMap<String, String>) -> Result<String, Box<dyn std::error::Error>> {
        let mut items = self.items.write().await;
        
        // 检查缓存大小
        if items.len() >= self.max_cache_size {
            self.evict_oldest(&mut items).await;
        }
        
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let item = StorageItem {
            cid: key.to_string(),
            data: data.to_vec(),
            metadata,
            created_at: timestamp,
            accessed_at: timestamp,
        };
        
        items.insert(key.to_string(), item);
        Ok(key.to_string())
    }
    
    /// 获取数据
    pub async fn retrieve(&self, key: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut items = self.items.write().await;
        
        if let Some(item) = items.get_mut(key) {
            // 更新访问时间
            item.accessed_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            
            Ok(item.data.clone())
        } else {
            Err(IpfsError::DataNotFound.into())
        }
    }
    
    /// 删除数据
    pub async fn delete(&self, key: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let mut items = self.items.write().await;
        Ok(items.remove(key).is_some())
    }
    
    /// 检查数据是否存在
    pub async fn exists(&self, key: &str) -> bool {
        let items = self.items.read().await;
        items.contains_key(key)
    }
    
    /// 获取存储统计信息
    pub async fn get_stats(&self) -> StorageStats {
        let items = self.items.read().await;
        
        let mut total_size = 0;
        let mut oldest_access = u64::MAX;
        let mut newest_access = 0;
        
        for item in items.values() {
            total_size += item.data.len();
            oldest_access = oldest_access.min(item.accessed_at);
            newest_access = newest_access.max(item.accessed_at);
        }
        
        StorageStats {
            total_items: items.len(),
            total_size,
            oldest_access,
            newest_access,
            max_cache_size: self.max_cache_size,
        }
    }
    
    /// 清理过期数据
    pub async fn cleanup_expired(&self, max_age: u64) -> usize {
        let mut items = self.items.write().await;
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let initial_count = items.len();
        items.retain(|_, item| current_time - item.accessed_at < max_age);
        initial_count - items.len()
    }
    
    /// 驱逐最旧的数据
    async fn evict_oldest(&self, items: &mut HashMap<String, StorageItem>) {
        if items.is_empty() {
            return;
        }
        
        let oldest_key = items
            .iter()
            .min_by_key(|(_, item)| item.accessed_at)
            .map(|(key, _)| key.clone());
        
        if let Some(key) = oldest_key {
            items.remove(&key);
        }
    }
}

/// 存储统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_items: usize,
    pub total_size: usize,
    pub oldest_access: u64,
    pub newest_access: u64,
    pub max_cache_size: usize,
}

impl StorageStats {
    /// 计算缓存使用率
    pub fn cache_usage_rate(&self) -> f64 {
        if self.max_cache_size == 0 {
            0.0
        } else {
            self.total_items as f64 / self.max_cache_size as f64
        }
    }
    
    /// 计算平均项目大小
    pub fn average_item_size(&self) -> f64 {
        if self.total_items == 0 {
            0.0
        } else {
            self.total_size as f64 / self.total_items as f64
        }
    }
}

/// 存储策略
#[derive(Debug, Clone)]
pub enum StorageStrategy {
    /// 内存存储
    Memory,
    /// IPFS存储
    Ipfs,
    /// 混合存储
    Hybrid,
}

/// 存储配置
#[derive(Debug, Clone)]
pub struct StorageConfig {
    pub strategy: StorageStrategy,
    pub max_cache_size: usize,
    pub max_item_size: usize,
    pub cleanup_interval: u64,
    pub ipfs_url: Option<String>,
}

impl Default for StorageConfig {
    fn default() -> Self {
        Self {
            strategy: StorageStrategy::Memory,
            max_cache_size: 1000,
            max_item_size: 1024 * 1024, // 1MB
            cleanup_interval: 3600, // 1小时
            ipfs_url: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_operations() {
        let storage = IpfsStorage::new(10);
        
        // 存储数据
        let data = b"test data";
        let metadata = HashMap::new();
        let key = storage.store("test_key", data, metadata).await.unwrap();
        assert_eq!(key, "test_key");
        
        // 检查数据存在
        assert!(storage.exists("test_key").await);
        
        // 获取数据
        let retrieved = storage.retrieve("test_key").await.unwrap();
        assert_eq!(retrieved, data);
        
        // 删除数据
        let deleted = storage.delete("test_key").await.unwrap();
        assert!(deleted);
        
        // 检查数据不存在
        assert!(!storage.exists("test_key").await);
    }

    #[tokio::test]
    async fn test_storage_stats() {
        let storage = IpfsStorage::new(5);
        
        // 存储一些数据
        for i in 0..3 {
            let key = format!("key_{}", i);
            let data = format!("data_{}", i).into_bytes();
            let metadata = HashMap::new();
            storage.store(&key, &data, metadata).await.unwrap();
        }
        
        let stats = storage.get_stats().await;
        assert_eq!(stats.total_items, 3);
        assert!(stats.total_size > 0);
        assert!(stats.cache_usage_rate() > 0.0);
    }

    #[tokio::test]
    async fn test_cache_eviction() {
        let storage = IpfsStorage::new(2);
        
        // 存储超过缓存限制的数据
        for i in 0..5 {
            let key = format!("key_{}", i);
            let data = format!("data_{}", i).into_bytes();
            let metadata = HashMap::new();
            storage.store(&key, &data, metadata).await.unwrap();
        }
        
        let stats = storage.get_stats().await;
        assert_eq!(stats.total_items, 2); // 应该只保留最新的2个
    }
}
