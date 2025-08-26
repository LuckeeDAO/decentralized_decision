//! SDK类型定义

use serde::{Deserialize, Serialize};

/// 重新导出WASM模块的类型
pub use luckee_voting_wasm::types::*;

/// SDK配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SDKConfig {
    pub server_url: String,
    pub timeout: u64,
    pub retry_count: u32,
    pub api_key: Option<String>,
}

impl Default for SDKConfig {
    fn default() -> Self {
        Self {
            server_url: "http://localhost:8080".to_string(),
            timeout: 30,
            retry_count: 3,
            api_key: None,
        }
    }
}

/// SDK错误类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SDKError {
    NetworkError(String),
    ServerError(String),
    InvalidResponse(String),
    TimeoutError,
    AuthenticationError,
    ValidationError(String),
}

impl std::fmt::Display for SDKError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SDKError::NetworkError(msg) => write!(f, "网络错误: {}", msg),
            SDKError::ServerError(msg) => write!(f, "服务器错误: {}", msg),
            SDKError::InvalidResponse(msg) => write!(f, "无效响应: {}", msg),
            SDKError::TimeoutError => write!(f, "请求超时"),
            SDKError::AuthenticationError => write!(f, "认证失败"),
            SDKError::ValidationError(msg) => write!(f, "验证错误: {}", msg),
        }
    }
}

impl std::error::Error for SDKError {}
