//! 工具函数模块
//! 
//! 提供各种辅助功能和工具函数

use crate::types::VotingError;
use serde::{Serialize, Deserialize};
use std::time::{SystemTime, UNIX_EPOCH};

/// 时间工具
pub struct TimeUtils;

impl TimeUtils {
    /// 获取当前时间戳（秒）
    pub fn current_timestamp() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }
    
    /// 获取当前时间戳（毫秒）
    pub fn current_timestamp_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis() as u64
    }
    
    /// 检查时间是否过期
    pub fn is_expired(timestamp: u64) -> bool {
        Self::current_timestamp() > timestamp
    }
    
    /// 计算剩余时间
    pub fn time_remaining(deadline: u64) -> u64 {
        let current = Self::current_timestamp();
        if current >= deadline {
            0
        } else {
            deadline - current
        }
    }
    
    /// 格式化时间
    pub fn format_duration(seconds: u64) -> String {
        let days = seconds / 86400;
        let hours = (seconds % 86400) / 3600;
        let minutes = (seconds % 3600) / 60;
        let secs = seconds % 60;
        
        if days > 0 {
            format!("{}天{}小时{}分钟{}秒", days, hours, minutes, secs)
        } else if hours > 0 {
            format!("{}小时{}分钟{}秒", hours, minutes, secs)
        } else if minutes > 0 {
            format!("{}分钟{}秒", minutes, secs)
        } else {
            format!("{}秒", secs)
        }
    }
}

/// 字符串工具
pub struct StringUtils;

impl StringUtils {
    /// 生成随机字符串
    pub fn random_string(length: usize) -> String {
        use rand::Rng;
        const CHARSET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ\
                                abcdefghijklmnopqrstuvwxyz\
                                0123456789";
        let mut rng = rand::thread_rng();
        
        (0..length)
            .map(|_| {
                let idx = rng.gen_range(0..CHARSET.len());
                CHARSET[idx] as char
            })
            .collect()
    }
    
    /// 生成UUID
    pub fn generate_uuid() -> String {
        use uuid::Uuid;
        Uuid::new_v4().to_string()
    }
    
    /// 检查字符串是否为有效的十六进制
    pub fn is_valid_hex(s: &str) -> bool {
        s.chars().all(|c| c.is_ascii_hexdigit())
    }
    
    /// 将字节数组转换为十六进制字符串
    pub fn bytes_to_hex(bytes: &[u8]) -> String {
        bytes.iter()
            .map(|b| format!("{:02x}", b))
            .collect()
    }
    
    /// 将十六进制字符串转换为字节数组
    pub fn hex_to_bytes(hex: &str) -> Result<Vec<u8>, VotingError> {
        if hex.len() % 2 != 0 {
            return Err(VotingError::InvalidState);
        }
        
        if !Self::is_valid_hex(hex) {
            return Err(VotingError::InvalidState);
        }
        
        let mut bytes = Vec::new();
        let mut chars = hex.chars();
        
        while let (Some(a), Some(b)) = (chars.next(), chars.next()) {
            let byte = u8::from_str_radix(&format!("{}{}", a, b), 16)
                .map_err(|_| VotingError::InvalidState)?;
            bytes.push(byte);
        }
        
        Ok(bytes)
    }
}

/// 验证工具
pub struct ValidationUtils;

impl ValidationUtils {
    /// 验证用户ID格式
    pub fn validate_user_id(user_id: &str) -> bool {
        !user_id.is_empty() && user_id.len() <= 64 && user_id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    }
    
    /// 验证会话ID格式
    pub fn validate_session_id(session_id: &str) -> bool {
        !session_id.is_empty() && session_id.len() <= 128 && session_id.chars().all(|c| c.is_alphanumeric() || c == '_' || c == '-')
    }
    
    /// 验证消息长度
    pub fn validate_message_length(message: &[u8], max_length: usize) -> bool {
        message.len() <= max_length
    }
    
    /// 验证时间戳
    pub fn validate_timestamp(timestamp: u64) -> bool {
        let current = TimeUtils::current_timestamp();
        // 允许时间戳在过去的1小时内或未来的1小时内
        timestamp >= current - 3600 && timestamp <= current + 3600
    }
    
    /// 验证权限等级
    pub fn validate_permission_level(level: &str) -> bool {
        matches!(level, "basic" | "creator" | "admin")
    }
}

/// 性能监控工具
pub struct PerformanceUtils;

impl PerformanceUtils {
    /// 测量函数执行时间
    pub fn measure_time<F, T>(f: F) -> (T, std::time::Duration)
    where
        F: FnOnce() -> T,
    {
        let start = std::time::Instant::now();
        let result = f();
        let duration = start.elapsed();
        (result, duration)
    }
    
    /// 测量函数执行时间（返回毫秒）
    pub fn measure_time_ms<F, T>(f: F) -> (T, u64)
    where
        F: FnOnce() -> T,
    {
        let (result, duration) = Self::measure_time(f);
        (result, duration.as_millis() as u64)
    }
    
    /// 性能基准测试
    pub fn benchmark<F>(name: &str, iterations: u32, f: F) -> BenchmarkResult
    where
        F: Fn() -> (),
    {
        let mut total_time = std::time::Duration::new(0, 0);
        let mut min_time = std::time::Duration::from_secs(u64::MAX);
        let mut max_time = std::time::Duration::new(0, 0);
        
        for _ in 0..iterations {
            let start = std::time::Instant::now();
            f();
            let duration = start.elapsed();
            
            total_time += duration;
            min_time = min_time.min(duration);
            max_time = max_time.max(duration);
        }
        
        let avg_time = total_time / iterations;
        
        BenchmarkResult {
            name: name.to_string(),
            iterations,
            total_time,
            avg_time,
            min_time,
            max_time,
        }
    }
}

/// 基准测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub iterations: u32,
    pub total_time: std::time::Duration,
    pub avg_time: std::time::Duration,
    pub min_time: std::time::Duration,
    pub max_time: std::time::Duration,
}

impl BenchmarkResult {
    /// 打印基准测试结果
    pub fn print(&self) {
        println!("=== 基准测试结果: {} ===", self.name);
        println!("迭代次数: {}", self.iterations);
        println!("总时间: {:?}", self.total_time);
        println!("平均时间: {:?}", self.avg_time);
        println!("最短时间: {:?}", self.min_time);
        println!("最长时间: {:?}", self.max_time);
        println!("平均时间 (毫秒): {:.2}", self.avg_time.as_secs_f64() * 1000.0);
    }
}

/// 错误处理工具
pub struct ErrorUtils;

impl ErrorUtils {
    /// 将错误转换为字符串
    pub fn error_to_string(error: &dyn std::error::Error) -> String {
        error.to_string()
    }
    
    /// 创建错误上下文
    pub fn with_context<T, E>(result: Result<T, E>, context: &str) -> Result<T, String>
    where
        E: std::fmt::Display,
    {
        result.map_err(|e| format!("{}: {}", context, e))
    }
    
    /// 记录错误
    pub fn log_error(error: &dyn std::error::Error) {
        eprintln!("错误: {}", error);
        if let Some(source) = error.source() {
            eprintln!("原因: {}", source);
        }
    }
}

/// 配置工具
pub struct ConfigUtils;

impl ConfigUtils {
    /// 从环境变量获取配置
    pub fn get_env_var(key: &str) -> Option<String> {
        std::env::var(key).ok()
    }
    
    /// 从环境变量获取配置，带默认值
    pub fn get_env_var_or(key: &str, default: &str) -> String {
        std::env::var(key).unwrap_or_else(|_| default.to_string())
    }
    
    /// 从环境变量获取数字配置
    pub fn get_env_var_as_u64(key: &str, default: u64) -> u64 {
        std::env::var(key)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    }
    
    /// 从环境变量获取布尔配置
    pub fn get_env_var_as_bool(key: &str, default: bool) -> bool {
        std::env::var(key)
            .ok()
            .map(|s| s.to_lowercase() == "true" || s == "1")
            .unwrap_or(default)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_time_utils() {
        let timestamp = TimeUtils::current_timestamp();
        assert!(timestamp > 0);
        
        assert!(!TimeUtils::is_expired(timestamp + 3600));
        assert!(TimeUtils::is_expired(timestamp - 3600));
        
        let remaining = TimeUtils::time_remaining(timestamp + 100);
        assert!(remaining <= 100);
        
        let formatted = TimeUtils::format_duration(3661);
        assert!(formatted.contains("小时"));
    }

    #[test]
    fn test_string_utils() {
        let random_str = StringUtils::random_string(10);
        assert_eq!(random_str.len(), 10);
        
        let uuid = StringUtils::generate_uuid();
        assert_eq!(uuid.len(), 36);
        
        assert!(StringUtils::is_valid_hex("deadbeef"));
        assert!(!StringUtils::is_valid_hex("invalid"));
        
        let bytes = vec![0xde, 0xad, 0xbe, 0xef];
        let hex = StringUtils::bytes_to_hex(&bytes);
        assert_eq!(hex, "deadbeef");
        
        let decoded = StringUtils::hex_to_bytes(&hex).unwrap();
        assert_eq!(decoded, bytes);
    }

    #[test]
    fn test_validation_utils() {
        assert!(ValidationUtils::validate_user_id("user123"));
        assert!(!ValidationUtils::validate_user_id(""));
        assert!(!ValidationUtils::validate_user_id("user@123"));
        
        assert!(ValidationUtils::validate_session_id("session_123"));
        assert!(!ValidationUtils::validate_session_id(""));
        
        assert!(ValidationUtils::validate_message_length(b"test", 10));
        assert!(!ValidationUtils::validate_message_length(b"very long message", 5));
        
        let current = TimeUtils::current_timestamp();
        assert!(ValidationUtils::validate_timestamp(current));
        assert!(!ValidationUtils::validate_timestamp(current + 7200)); // 2小时后
    }

    #[test]
    fn test_performance_utils() {
        let (result, duration) = PerformanceUtils::measure_time(|| {
            std::thread::sleep(std::time::Duration::from_millis(10));
            42
        });
        
        assert_eq!(result, 42);
        assert!(duration.as_millis() >= 10);
        
        let (_, duration_ms) = PerformanceUtils::measure_time_ms(|| {
            std::thread::sleep(std::time::Duration::from_millis(5));
        });
        
        assert!(duration_ms >= 5);
        
        let benchmark_result = PerformanceUtils::benchmark("test", 3, || {
            std::thread::sleep(std::time::Duration::from_millis(1));
        });
        
        assert_eq!(benchmark_result.name, "test");
        assert_eq!(benchmark_result.iterations, 3);
    }

    #[test]
    fn test_config_utils() {
        // 测试默认值
        let value = ConfigUtils::get_env_var_or("NONEXISTENT_VAR", "default");
        assert_eq!(value, "default");
        
        let num_value = ConfigUtils::get_env_var_as_u64("NONEXISTENT_NUM", 42);
        assert_eq!(num_value, 42);
        
        let bool_value = ConfigUtils::get_env_var_as_bool("NONEXISTENT_BOOL", true);
        assert_eq!(bool_value, true);
    }
}
