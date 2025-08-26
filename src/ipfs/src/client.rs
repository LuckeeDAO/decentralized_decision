//! IPFS客户端实现

use crate::types::{NodeInfo, AddResponse, IpfsError};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;

/// IPFS客户端
pub struct IpfsClient {
    client: Client,
    base_url: String,
}

impl IpfsClient {
    /// 创建新的IPFS客户端
    pub async fn new(ipfs_url: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let client = Client::builder()
            .timeout(Duration::from_secs(30))
            .build()?;
        
        Ok(Self {
            client,
            base_url: ipfs_url.to_string(),
        })
    }
    
    /// 添加数据到IPFS
    pub async fn add_data(&self, data: &[u8]) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v0/add", self.base_url);
        
        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(data.to_vec()));
        
        let response = self.client
            .post(&url)
            .multipart(form)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(IpfsError::UploadFailed.into());
        }
        
        let add_response: AddResponse = response.json().await?;
        Ok(add_response.hash)
    }
    
    /// 从IPFS获取数据
    pub async fn get_data(&self, cid: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v0/cat?arg={}", self.base_url, cid);
        
        let response = self.client
            .post(&url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(IpfsError::DownloadFailed.into());
        }
        
        let data = response.bytes().await?;
        Ok(data.to_vec())
    }
    
    /// 验证CID
    pub async fn verify_cid(&self, cid: &str, data: &[u8]) -> Result<bool, Box<dyn std::error::Error>> {
        // 使用 IPFS add 接口的 only-hash 选项计算给定数据的CID而不实际存储
        // 参考: /api/v0/add?only-hash=true&pin=false
        let url = format!("{}/api/v0/add?only-hash=true&pin=false", self.base_url);

        let form = reqwest::multipart::Form::new()
            .part("file", reqwest::multipart::Part::bytes(data.to_vec()));

        let response = self.client
            .post(&url)
            .multipart(form)
            .send()
            .await?;

        if !response.status().is_success() {
            return Err(IpfsError::VerificationFailed.into());
        }

        let add_response: AddResponse = response.json().await?;

        // 简单等值比较（如需支持不同CID版本/编码，可在此做规范化）
        Ok(add_response.hash == cid)
    }
    
    /// 获取节点信息
    pub async fn get_node_info(&self) -> Result<NodeInfo, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v0/id", self.base_url);
        
        let response = self.client
            .post(&url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(IpfsError::NetworkError.into());
        }
        
        let node_info: NodeInfo = response.json().await?;
        Ok(node_info)
    }
    
    /// 检查IPFS节点是否可用
    pub async fn ping(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v0/version", self.base_url);
        
        let response = self.client
            .post(&url)
            .send()
            .await;
        
        match response {
            Ok(resp) => Ok(resp.status().is_success()),
            Err(_) => Ok(false),
        }
    }
    
    /// 获取IPFS版本信息
    pub async fn get_version(&self) -> Result<String, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v0/version", self.base_url);
        
        let response = self.client
            .post(&url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(IpfsError::NetworkError.into());
        }
        
        let version_info: Value = response.json().await?;
        let version = version_info["Version"]
            .as_str()
            .unwrap_or("unknown")
            .to_string();
        
        Ok(version)
    }
    
    /// 获取存储统计信息
    pub async fn get_repo_stats(&self) -> Result<Value, Box<dyn std::error::Error>> {
        let url = format!("{}/api/v0/repo/stat", self.base_url);
        
        let response = self.client
            .post(&url)
            .send()
            .await?;
        
        if !response.status().is_success() {
            return Err(IpfsError::NetworkError.into());
        }
        
        let stats: Value = response.json().await?;
        Ok(stats)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ipfs_client_creation() {
        let client = IpfsClient::new("http://localhost:5001").await;
        assert!(client.is_ok());
    }

    #[tokio::test]
    async fn test_ping() {
        let client = IpfsClient::new("http://localhost:5001").await.unwrap();
        let is_available = client.ping().await.unwrap_or(false);
        // 如果本地没有运行IPFS节点，这个测试会失败，这是正常的
        println!("IPFS节点可用性: {}", is_available);
    }
}
