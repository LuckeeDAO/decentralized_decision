//! 基于比特承诺模型的去中心化投票系统 - IPFS存储模块
//! 
//! 实现IPFS存储功能，包括数据上传、下载、验证等

pub mod storage;
pub mod client;
pub mod types;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use base64::Engine;
use flate2::{write::GzEncoder, read::GzDecoder, Compression};
use std::io::{Read, Write};

/// IPFS存储管理器
pub struct IpfsManager {
    client: client::IpfsClient,
    cache: HashMap<String, Vec<u8>>,
    // mirrors for redundancy (optional)
    mirrors: Vec<client::IpfsClient>,
    // cid -> list of (mirror_cid, mirror_base_url)
    mirror_index: HashMap<String, Vec<(String, String)>>,
    // compression toggle
    compress_enabled: bool,
    // stats
    stats: StorageStats,
}

impl IpfsManager {
    /// 创建新的IPFS管理器
    pub async fn new(ipfs_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = client::IpfsClient::new(ipfs_url).await?;
        Ok(Self {
            client,
            cache: HashMap::new(),
            mirrors: Vec::new(),
            mirror_index: HashMap::new(),
            compress_enabled: false,
            stats: StorageStats::new(),
        })
    }
    /// 添加冗余镜像节点
    pub async fn add_mirror(&mut self, ipfs_url: &str) -> Result<(), Box<dyn std::error::Error>> {
        let cli = client::IpfsClient::new(ipfs_url).await?;
        self.mirrors.push(cli);
        Ok(())
    }
    /// 启用或关闭压缩
    pub fn set_compression(&mut self, enabled: bool) { self.compress_enabled = enabled; }
    
    /// 上传数据到IPFS
    pub async fn upload_data(&mut self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let payload: Vec<u8> = if self.compress_enabled {
            let mut enc = GzEncoder::new(Vec::new(), Compression::default());
            enc.write_all(data)?;
            enc.finish()?
        } else { data.to_vec() };
        let cid = self.client.add_data(&payload).await?;
        
        // 缓存数据
        self.cache.insert(cid.clone(), data.to_vec());
        self.stats.record_upload(data.len() as u64);
        // 冗余：写入镜像
        if !self.mirrors.is_empty() {
            let mut entries: Vec<(String, String)> = Vec::new();
            for m in &self.mirrors {
                if let Ok(mcid) = m.add_data(&payload).await {
                    entries.push((mcid, m.base_url.clone()));
                }
            }
            if !entries.is_empty() {
                self.mirror_index.insert(cid.clone(), entries);
            }
        }
        
        Ok(cid)
    }
    
    /// 从IPFS下载数据
    pub async fn download_data(&mut self, cid: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        // 先检查缓存
        if let Some(data) = self.cache.get(cid) {
            self.stats.record_download(data.len() as u64, true);
            return Ok(data.clone());
        }
        
        // 从IPFS下载（主节点）
        let mut data = self.client.get_data(cid).await.or_else(|_| async {
            // 尝试从镜像拉取
            for (mcid, _url) in self.mirror_index.get(cid).cloned().unwrap_or_default() {
                for m in &self.mirrors {
                    if let Ok(bytes) = m.get_data(&mcid).await { return Ok(bytes); }
                }
            }
            // 如果没有镜像索引，逐一尝试
            for m in &self.mirrors {
                if let Ok(bytes) = m.get_data(cid).await { return Ok(bytes); }
            }
            Err::<Vec<u8>, Box<dyn std::error::Error>>(Box::new(std::io::Error::new(std::io::ErrorKind::Other, "download failed")))
        }.await)?;
        // 若启用压缩，尝试解压
        if self.compress_enabled {
            let mut decoder = GzDecoder::new(&data[..]);
            let mut decompressed = Vec::new();
            if decoder.read_to_end(&mut decompressed).is_ok() {
                data = decompressed;
            }
        }
        
        // 缓存数据
        self.stats.record_download(data.len() as u64, false);
        self.cache.insert(cid.to_string(), data.clone());
        
        Ok(data)
    }
    
    /// 验证数据完整性
    pub async fn verify_data(&self, cid: &str, data: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        let primary = self.client.verify_cid(cid, data).await.unwrap_or(false);
        if !primary { return Ok(false); }
        // 校验镜像一致性：如果记录了镜像，逐一验证
        if let Some(entries) = self.mirror_index.get(cid) {
            for (mcid, _url) in entries.iter() {
                let ok = self.client.verify_cid(mcid, data).await.unwrap_or(false);
                if !ok { return Ok(false); }
            }
        }
        Ok(true)
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

    /// 当前统计信息
    pub fn stats(&self) -> &StorageStats { &self.stats }
    
    /// 一致性检查：返回主CID与镜像CID校验结果
    pub async fn consistency_check(&self, cid: &str, data: Option<&[u8]>) -> HashMap<String, bool> {
        let mut result: HashMap<String, bool> = HashMap::new();
        // 主节点
        let ok = match data { Some(d) => self.client.verify_cid(cid, d).await.unwrap_or(false), None => false };
        result.insert("primary".to_string(), ok);
        if let Some(entries) = self.mirror_index.get(cid) {
            for (mcid, url) in entries.iter() {
                // 简化：对照主数据验证mirror cid
                let mok = match data { Some(d) => self.client.verify_cid(mcid, d).await.unwrap_or(false), None => false };
                result.insert(url.clone(), mok);
            }
        }
        result
    }

    /// 导出缓存（用于备份）
    pub fn export_cache(&self) -> Vec<(String, String)> {
        // 返回 (cid, base64_data)
        self.cache
            .iter()
            .map(|(cid, data)| (cid.clone(), base64::engine::general_purpose::STANDARD.encode(data)))
            .collect()
    }

    /// 导入缓存（用于恢复）
    pub fn import_cache(&mut self, items: Vec<(String, String)>) -> Result<(), Box<dyn std::error::Error>> {
        for (cid, b64) in items.into_iter() {
            let bytes = base64::engine::general_purpose::STANDARD.decode(b64.as_bytes())?;
            self.cache.insert(cid, bytes);
        }
        Ok(())
    }

    /// 将缓存归档到本地文件
    pub fn archive_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let items = self.export_cache();
        let json = serde_json::to_vec(&items)?;
        std::fs::write(path, json)?;
        Ok(())
    }

    /// 从本地文件导入归档
    pub fn restore_from_file(&mut self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let bytes = std::fs::read(path)?;
        let items: Vec<(String, String)> = serde_json::from_slice(&bytes)?;
        self.import_cache(items)
    }
}

/// 导出指定管理器的缓存（自由函数封装，便于跨crate调用）
pub fn export_cache(manager: &IpfsManager) -> Vec<(String, String)> {
    manager.export_cache()
}

/// 导入缓存到指定管理器（自由函数封装，便于跨crate调用）
pub fn import_cache(manager: &mut IpfsManager, items: Vec<(String, String)>) -> Result<(), Box<dyn std::error::Error>> {
    manager.import_cache(items)
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
