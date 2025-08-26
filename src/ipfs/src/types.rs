//! IPFS类型定义

use serde::{Deserialize, Serialize};

/// IPFS节点信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeInfo {
    pub id: String,
    pub version: String,
    pub protocol_version: String,
    pub addresses: Vec<String>,
    pub agent_version: String,
}

/// IPFS文件信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileInfo {
    pub name: String,
    pub size: u64,
    pub cid: String,
    pub hash: String,
}

/// IPFS添加响应
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AddResponse {
    pub name: String,
    pub hash: String,
    pub size: String,
}

/// IPFS错误类型
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum IpfsError {
    ConnectionFailed,
    InvalidCid,
    DataNotFound,
    UploadFailed,
    DownloadFailed,
    VerificationFailed,
    NetworkError,
}

impl std::fmt::Display for IpfsError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            IpfsError::ConnectionFailed => write!(f, "连接失败"),
            IpfsError::InvalidCid => write!(f, "无效的CID"),
            IpfsError::DataNotFound => write!(f, "数据未找到"),
            IpfsError::UploadFailed => write!(f, "上传失败"),
            IpfsError::DownloadFailed => write!(f, "下载失败"),
            IpfsError::VerificationFailed => write!(f, "验证失败"),
            IpfsError::NetworkError => write!(f, "网络错误"),
        }
    }
}

impl std::error::Error for IpfsError {}
