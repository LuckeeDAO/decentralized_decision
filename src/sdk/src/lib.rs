//! 基于比特承诺模型的去中心化投票系统 - 客户端SDK
//! 
//! 提供客户端API接口和工具函数

pub mod client;
pub mod types;
pub mod utils;



/// SDK版本信息
pub const SDK_VERSION: &str = env!("CARGO_PKG_VERSION");

/// SDK客户端
pub struct VotingSDK {
    client: client::VotingClient,
}

impl VotingSDK {
    /// 创建新的SDK客户端
    pub fn new(server_url: &str) -> Self {
        Self {
            client: client::VotingClient::new(server_url),
        }
    }
    
    /// 获取SDK版本
    pub fn version() -> &'static str {
        SDK_VERSION
    }
    
    /// 检查服务器健康状态
    pub async fn health_check(&self) -> Result<bool, Box<dyn std::error::Error>> {
        self.client.health_check().await
    }
    
    /// 创建投票会话
    pub async fn create_session(
        &self,
        session_id: &str,
        commit_deadline: u64,
        reveal_deadline: u64,
        participants: Vec<String>,
    ) -> Result<types::VotingSession, Box<dyn std::error::Error>> {
        self.client.create_session(session_id, commit_deadline, reveal_deadline, participants).await
    }
    
    /// 提交承诺
    pub async fn submit_commitment(
        &self,
        session_id: &str,
        user_id: &str,
        message: &[u8],
    ) -> Result<types::BitCommitment, Box<dyn std::error::Error>> {
        self.client.submit_commitment(session_id, user_id, message).await
    }
    
    /// 提交揭示
    pub async fn submit_reveal(
        &self,
        session_id: &str,
        user_id: &str,
        message: &[u8],
        randomness: &[u8; 32],
    ) -> Result<types::CommitmentProof, Box<dyn std::error::Error>> {
        self.client.submit_reveal(session_id, user_id, message, randomness).await
    }
    
    /// 获取会话信息
    pub async fn get_session(&self, session_id: &str) -> Result<Option<types::VotingSession>, Box<dyn std::error::Error>> {
        self.client.get_session(session_id).await
    }
    
    /// 计算投票结果
    pub async fn calculate_results(&self, session_id: &str) -> Result<types::VotingResults, Box<dyn std::error::Error>> {
        self.client.calculate_results(session_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sdk_version() {
        assert!(!VotingSDK::version().is_empty());
    }

    #[tokio::test]
    async fn test_sdk_creation() {
        let sdk = VotingSDK::new("http://localhost:8080");
        assert_eq!(sdk.client.server_url(), "http://localhost:8080");
    }
}
