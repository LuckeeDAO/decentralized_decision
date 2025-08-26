//! 基于比特承诺模型的去中心化投票系统 - WebAssembly核心模块
//! 
//! 本模块实现了比特承诺协议、密码学工具库和核心投票逻辑

pub mod crypto;
pub mod commitment;
pub mod voting;
pub mod types;
pub mod utils;

use wasm_bindgen::prelude::*;
use tracing_wasm;

/// 初始化WebAssembly模块
#[wasm_bindgen]
pub fn init() {
    // 设置panic hook
    console_error_panic_hook::set_once();
    
    // 初始化日志
    tracing_wasm::set_as_global_default();
}

/// 获取模块版本信息
#[wasm_bindgen]
pub fn get_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

/// 健康检查
#[wasm_bindgen]
pub fn health_check() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        let version = get_version();
        assert!(!version.is_empty());
    }

    #[test]
    fn test_health_check() {
        assert!(health_check());
    }
}
