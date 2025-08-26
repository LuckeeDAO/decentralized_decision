//! 基于比特承诺模型的去中心化投票系统 - IPFS存储模块
//! 
//! 实现IPFS存储功能，包括数据上传、下载、验证等

pub mod storage;
pub mod client;
pub mod types;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// IPFS存储管理器
pub struct IpfsManager {
    client: client::IpfsClient,
    cache: HashMap<String, Vec<u8>>,
}

impl IpfsManager {
    /// 创建新的IPFS管理器
    pub async fn new(ipfs_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = client::IpfsClient::new(ipfs_url).await?;
        Ok(Self {
            client,
            cache: HashMap::new(),
        })
    }
    
    /// 上传数据到IPFS
    pub async fn upload_data(&mut self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let cid = self.client.add_data(data).await?;
        
        // 缓存数据
        self.cache.insert(cid.clone(), data.to_vec());
        
        Ok(cid)
    }
    
    /// 从IPFS下载数据
    pub async fn download_data(&mut self, cid: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 先检查缓存
        if let Some(data) = self.cache.get(cid) {
            return Ok(data.clone());
        }
        
        // 从IPFS下载
        let data = self.client.get_data(cid).await?;
        
        // 缓存数据
        self.cache.insert(cid.to_string(), data.clone());
        
        Ok(data)
    }
    
    /// 验证数据完整性
    pub async fn verify_data(&self, cid: &str, data: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        self.client.verify_cid(cid, data).await
    }
    
    /// 获取IPFS节点信息
    pub async fn get_node_info(&self) -> Result<types::NodeInfo, Box<dyn std::error::Error>> {
        self.client.get_node_info().await
    }
    
    /// 清理缓存
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }
    
    /// 获取缓存大小
    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// 存储统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageStats {
    pub total_uploads: u64,
    pub total_downloads: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub total_bytes_uploaded: u64,
    pub total_bytes_downloaded: u64,
}

impl StorageStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            total_uploads: 0,
            total_downloads: 0,
            cache_hits: 0,
            cache_misses: 0,
            total_bytes_uploaded: 0,
            total_bytes_downloaded: 0,
        }
    }
    
    /// 更新上传统计
    pub fn record_upload(&mut self, bytes: u64) {
        self.total_uploads += 1;
        self.total_bytes_uploaded += bytes;
    }
    
    /// 更新下载统计
    pub fn record_download(&mut self, bytes: u64, cache_hit: bool) {
        self.total_downloads += 1;
        self.total_bytes_downloaded += bytes;
        
        if cache_hit {
            self.cache_hits += 1;
        } else {
            self.cache_misses += 1;
        }
    }
    
    /// 计算缓存命中率
    pub fn cache_hit_rate(&self) -> f64 {
        let total = self.cache_hits + self.cache_misses;
        if total == 0 {
            0.0
        } else {
            self.cache_hits as f64 / total as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_storage_stats() {
        let mut stats = StorageStats::new();
        
        stats.record_upload(100);
        stats.record_download(50, true);
        stats.record_download(75, false);
        
        assert_eq!(stats.total_uploads, 1);
        assert_eq!(stats.total_downloads, 2);
        assert_eq!(stats.cache_hits, 1);
        assert_eq!(stats.cache_misses, 1);
        assert_eq!(stats.total_bytes_uploaded, 100);
        assert_eq!(stats.total_bytes_downloaded, 125);
        assert_eq!(stats.cache_hit_rate(), 0.5);
    }
}
