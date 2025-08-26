//! SDK客户端实现

use crate::types::{SDKConfig, SDKError};
use reqwest::Client;
use serde_json::Value;
use std::time::Duration;
use base64::Engine;

/// 投票客户端
pub struct VotingClient {
    client: Client,
    config: SDKConfig,
}

impl VotingClient {
    /// 创建新的投票客户端
    pub fn new(server_url: &str) -> Self {
        let config = SDKConfig {
            server_url: server_url.to_string(),
            ..Default::default()
        };
        
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout))
            .build()
            .unwrap_or_else(|_| Client::new());
        
        Self { client, config }
    }
    
    /// 获取服务器URL
    pub fn server_url(&self) -> &str {
        &self.config.server_url
    }
    
    /// 健康检查
    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        let url = format!("{}/health", self.config.server_url);
        
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let health_data: Value = response.json().await?;
            Ok(health_data["status"].as_str() == Some("healthy"))
        } else {
            Ok(false)
        }
    }
    
    /// 创建投票会话
    pub async fn create_session(
        &self,
        session_id: &str,
        commit_deadline: u64,
        reveal_deadline: u64,
        participants: Vec<String>,
    ) -> Result<super::types::VotingSession, Box<dyn std::error::Error>> {
        let url = format!("{}/sessions", self.config.server_url);
        
        let request_data = serde_json::json!({
            "session_id": session_id,
            "commit_deadline": commit_deadline,
            "reveal_deadline": reveal_deadline,
            "participants": participants,
        });
        
        let response = self.client
            .post(&url)
            .json(&request_data)
            .send()
            .await?;
        
        if response.status().is_success() {
            let api_response: Value = response.json().await?;
            if api_response["success"].as_bool().unwrap_or(false) {
                let session_data = &api_response["data"];
                Ok(serde_json::from_value(session_data.clone())?)
            } else {
                let error_msg = api_response["error"].as_str().unwrap_or("未知错误");
                Err(SDKError::ServerError(error_msg.to_string()).into())
            }
        } else {
            Err(SDKError::ServerError(format!("HTTP {}", response.status())).into())
        }
    }
    
    /// 提交承诺
    pub async fn submit_commitment(
        &self,
        session_id: &str,
        user_id: &str,
        message: &[u8],
    ) -> Result<super::types::BitCommitment, Box<dyn std::error::Error>> {
        let url = format!("{}/sessions/{}/commitments", self.config.server_url, session_id);
        
        let request_data = serde_json::json!({
            "session_id": session_id,
            "user_id": user_id,
            "message": base64::engine::general_purpose::STANDARD.encode(message),
        });
        
        let response = self.client
            .post(&url)
            .json(&request_data)
            .send()
            .await?;
        
        if response.status().is_success() {
            let api_response: Value = response.json().await?;
            if api_response["success"].as_bool().unwrap_or(false) {
                let commitment_data = &api_response["data"];
                Ok(serde_json::from_value(commitment_data.clone())?)
            } else {
                let error_msg = api_response["error"].as_str().unwrap_or("未知错误");
                Err(SDKError::ServerError(error_msg.to_string()).into())
            }
        } else {
            Err(SDKError::ServerError(format!("HTTP {}", response.status())).into())
        }
    }
    
    /// 提交揭示
    pub async fn submit_reveal(
        &self,
        session_id: &str,
        user_id: &str,
        message: &[u8],
        randomness: &[u8; 32],
    ) -> Result<super::types::CommitmentProof, Box<dyn std::error::Error>> {
        let url = format!("{}/sessions/{}/reveals", self.config.server_url, session_id);
        
        let request_data = serde_json::json!({
            "session_id": session_id,
            "user_id": user_id,
            "message": base64::engine::general_purpose::STANDARD.encode(message),
            "randomness": hex::encode(randomness),
        });
        
        let response = self.client
            .post(&url)
            .json(&request_data)
            .send()
            .await?;
        
        if response.status().is_success() {
            let api_response: Value = response.json().await?;
            if api_response["success"].as_bool().unwrap_or(false) {
                let proof_data = &api_response["data"];
                Ok(serde_json::from_value(proof_data.clone())?)
            } else {
                let error_msg = api_response["error"].as_str().unwrap_or("未知错误");
                Err(SDKError::ServerError(error_msg.to_string()).into())
            }
        } else {
            Err(SDKError::ServerError(format!("HTTP {}", response.status())).into())
        }
    }
    
    /// 获取会话信息
    pub async fn get_session(&self, session_id: &str) -> Result<Option<super::types::VotingSession>, Box<dyn std::error::Error>> {
        let url = format!("{}/sessions/{}", self.config.server_url, session_id);
        
        let response = self.client.get(&url).send().await?;
        
        if response.status().is_success() {
            let api_response: Value = response.json().await?;
            if api_response["success"].as_bool().unwrap_or(false) {
                let session_data = &api_response["data"];
                Ok(Some(serde_json::from_value(session_data.clone())?))
            } else {
                Ok(None)
            }
        } else {
            Err(SDKError::ServerError(format!("HTTP {}", response.status())).into())
        }
    }
    
    /// 计算投票结果
    pub async fn calculate_results(&self, session_id: &str) -> Result<super::types::VotingResults, Box<dyn std::error::Error>> {
        let url = format!("{}/sessions/{}/results", self.config.server_url, session_id);
        
        let response = self.client.post(&url).send().await?;
        
        if response.status().is_success() {
            let api_response: Value = response.json().await?;
            if api_response["success"].as_bool().unwrap_or(false) {
                let results_data = &api_response["data"];
                Ok(serde_json::from_value(results_data.clone())?)
            } else {
                let error_msg = api_response["error"].as_str().unwrap_or("未知错误");
                Err(SDKError::ServerError(error_msg.to_string()).into())
            }
        } else {
            Err(SDKError::ServerError(format!("HTTP {}", response.status())).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_client_creation() {
        let client = VotingClient::new("http://localhost:8080");
        assert_eq!(client.server_url(), "http://localhost:8080");
    }

    #[tokio::test]
    async fn test_health_check() {
        let client = VotingClient::new("http://localhost:8080");
        let result = client.health_check().await;
        // 如果服务器没有运行，这个测试会失败，这是正常的
        println!("健康检查结果: {:?}", result);
    }
}
