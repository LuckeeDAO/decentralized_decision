//! SDK工具函数

use crate::types::SDKError;
use serde::{Deserialize, Serialize};
use std::time::{SystemTime, UNIX_EPOCH};
use base64::Engine;

/// SDK工具函数
pub struct SDKUtils;

impl SDKUtils {
    /// 生成会话ID
    pub fn generate_session_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let id: u64 = rng.gen();
        format!("session_{:016x}", id)
    }
    
    /// 生成用户ID
    pub fn generate_user_id() -> String {
        use rand::Rng;
        let mut rng = rand::thread_rng();
        let id: u64 = rng.gen();
        format!("user_{:016x}", id)
    }
    
    /// 验证会话ID格式
    pub fn validate_session_id(session_id: &str) -> bool {
        session_id.starts_with("session_") && session_id.len() == 25
    }
    
    /// 验证用户ID格式
    pub fn validate_user_id(user_id: &str) -> bool {
        user_id.starts_with("user_") && user_id.len() == 21
    }
    
    /// 获取当前时间戳
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    /// 计算未来时间戳
    pub fn future_timestamp(seconds_from_now: u64) -> u64 {
        Self::current_timestamp() + seconds_from_now
    }
    
    /// 格式化时间戳
    pub fn format_timestamp(timestamp: u64) -> String {
        let datetime = chrono::DateTime::from_timestamp(timestamp as i64, 0)
            .unwrap_or_default();
        datetime.format("%Y-%m-%d %H:%M:%S").to_string()
    }
    
    /// 编码消息为Base64
    pub fn encode_message(message: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(message)
    }
    
    /// 解码Base64消息
    pub fn decode_message(encoded: &str) -> Result<Vec<u8>, SDKError> {
        base64::engine::general_purpose::STANDARD.decode(encoded)
            .map_err(|e| SDKError::ValidationError(format!("Base64解码失败: {}", e)))
    }
    
    /// 编码随机数为十六进制
    pub fn encode_randomness(randomness: &[u8; 32]) -> String {
        hex::encode(randomness)
    }
    
    /// 解码十六进制随机数
    pub fn decode_randomness(encoded: &str) -> Result<[u8; 32], SDKError> {
        let bytes = hex::decode(encoded)
            .map_err(|e| SDKError::ValidationError(format!("十六进制解码失败: {}", e)))?;
        
        if bytes.len() != 32 {
            return Err(SDKError::ValidationError("随机数长度必须为32字节".to_string()));
        }
        
        let mut randomness = [0u8; 32];
        randomness.copy_from_slice(&bytes);
        Ok(randomness)
    }
}

/// SDK配置构建器
pub struct SDKConfigBuilder {
    config: crate::types::SDKConfig,
}

impl SDKConfigBuilder {
    /// 创建新的配置构建器
    pub fn new() -> Self {
        Self {
            config: crate::types::SDKConfig::default(),
        }
    }
    
    /// 设置服务器URL
    pub fn server_url(mut self, url: &str) -> Self {
        self.config.server_url = url.to_string();
        self
    }
    
    /// 设置超时时间
    pub fn timeout(mut self, timeout: u64) -> Self {
        self.config.timeout = timeout;
        self
    }
    
    /// 设置重试次数
    pub fn retry_count(mut self, retry_count: u32) -> Self {
        self.config.retry_count = retry_count;
        self
    }
    
    /// 设置API密钥
    pub fn api_key(mut self, api_key: &str) -> Self {
        self.config.api_key = Some(api_key.to_string());
        self
    }
    
    /// 构建配置
    pub fn build(self) -> crate::types::SDKConfig {
        self.config
    }
}

/// SDK统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SDKStats {
    pub total_requests: u64,
    pub successful_requests: u64,
    pub failed_requests: u64,
    pub average_response_time_ms: u64,
    pub last_request_time: u64,
}

impl SDKStats {
    /// 创建新的统计信息
    pub fn new() -> Self {
        Self {
            total_requests: 0,
            successful_requests: 0,
            failed_requests: 0,
            average_response_time_ms: 0,
            last_request_time: 0,
        }
    }
    
    /// 记录请求
    pub fn record_request(&mut self, success: bool, response_time_ms: u64) {
        self.total_requests += 1;
        self.last_request_time = SDKUtils::current_timestamp();
        
        if success {
            self.successful_requests += 1;
        } else {
            self.failed_requests += 1;
        }
        
        // 更新平均响应时间
        let total_time = self.average_response_time_ms * (self.total_requests - 1) + response_time_ms;
        self.average_response_time_ms = total_time / self.total_requests;
    }
    
    /// 计算成功率
    pub fn success_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.successful_requests as f64 / self.total_requests as f64
        }
    }
    
    /// 计算失败率
    pub fn failure_rate(&self) -> f64 {
        if self.total_requests == 0 {
            0.0
        } else {
            self.failed_requests as f64 / self.total_requests as f64
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_session_id_generation() {
        let session_id = SDKUtils::generate_session_id();
        assert!(SDKUtils::validate_session_id(&session_id));
        
        let session_id2 = SDKUtils::generate_session_id();
        assert_ne!(session_id, session_id2);
    }

    #[test]
    fn test_user_id_generation() {
        let user_id = SDKUtils::generate_user_id();
        assert!(SDKUtils::validate_user_id(&user_id));
        
        let user_id2 = SDKUtils::generate_user_id();
        assert_ne!(user_id, user_id2);
    }

    #[test]
    fn test_timestamp_operations() {
        let current = SDKUtils::current_timestamp();
        assert!(current > 0);
        
        let future = SDKUtils::future_timestamp(3600);
        assert!(future > current);
        
        let formatted = SDKUtils::format_timestamp(current);
        assert!(!formatted.is_empty());
    }

    #[test]
    fn test_message_encoding() {
        let message = b"test message";
        let encoded = SDKUtils::encode_message(message);
        let decoded = SDKUtils::decode_message(&encoded).unwrap();
        assert_eq!(message, decoded.as_slice());
    }

    #[test]
    fn test_randomness_encoding() {
        let randomness = [1u8; 32];
        let encoded = SDKUtils::encode_randomness(&randomness);
        let decoded = SDKUtils::decode_randomness(&encoded).unwrap();
        assert_eq!(randomness, decoded);
    }

    #[test]
    fn test_config_builder() {
        let config = SDKConfigBuilder::new()
            .server_url("http://example.com")
            .timeout(60)
            .retry_count(5)
            .api_key("test_key")
            .build();
        
        assert_eq!(config.server_url, "http://example.com");
        assert_eq!(config.timeout, 60);
        assert_eq!(config.retry_count, 5);
        assert_eq!(config.api_key, Some("test_key".to_string()));
    }

    #[test]
    fn test_sdk_stats() {
        let mut stats = SDKStats::new();
        
        stats.record_request(true, 100);
        stats.record_request(false, 200);
        stats.record_request(true, 150);
        
        assert_eq!(stats.total_requests, 3);
        assert_eq!(stats.successful_requests, 2);
        assert_eq!(stats.failed_requests, 1);
        assert_eq!(stats.success_rate(), 2.0 / 3.0);
        assert_eq!(stats.failure_rate(), 1.0 / 3.0);
    }
}
