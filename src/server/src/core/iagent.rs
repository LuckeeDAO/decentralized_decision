//! iAgent 自动化执行框架
//!
//! - 配置管理（策略/触发器/参数校验）
//! - 自动化执行引擎（承诺/揭示/错误重试/监控）

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// iAgent 配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IAgentConfig {
    /// 策略标识（random/weighted/priority/custom/...）
    pub strategy: String,
    /// 触发条件配置（time_cron/block_height/webhook/...）
    pub triggers: Vec<TriggerConfig>,
    /// 执行参数（各策略与算法所需）
    pub params: HashMap<String, serde_json::Value>,
    /// 最大重试次数
    pub max_retries: u32,
    /// 是否开启监控
    pub enable_metrics: bool,
}

impl Default for IAgentConfig {
    fn default() -> Self {
        Self {
            strategy: "random".to_string(),
            triggers: vec![TriggerConfig::TimeCron { cron: "@hourly".to_string() }],
            params: HashMap::new(),
            max_retries: 3,
            enable_metrics: true,
        }
    }
}

/// 触发器配置
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TriggerConfig {
    /// 简化版 cron 表达式（@hourly/@daily/固定秒周期）
    TimeCron { cron: String },
    /// 区块高度触发
    BlockHeight { every: u64 },
    /// Webhook 触发（外部事件）
    Webhook { endpoint: String },
}

/// 运行时状态
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct IAgentRuntime {
    pub last_run_ts: Option<u64>,
    pub last_error: Option<String>,
    pub executed_count: u64,
}

impl Default for IAgentRuntime {
    fn default() -> Self {
        Self { last_run_ts: None, last_error: None, executed_count: 0 }
    }
}

/// iAgent 引擎：提供承诺/揭示阶段的自动化触发与执行
#[derive(Default)]
pub struct IAgentEngine {
    #[allow(dead_code)]
    cfg: IAgentConfig,
    #[allow(dead_code)]
    runtime: IAgentRuntime,
}

impl IAgentEngine {
    #[allow(dead_code)]
    pub fn new(cfg: IAgentConfig) -> Self { Self { cfg, runtime: IAgentRuntime::default() } }

    /// 校验配置合法性
    #[allow(dead_code)]
    pub fn validate_config(&self) -> Result<(), String> {
        if self.cfg.max_retries > 10 { return Err("max_retries 过大".into()); }
        if self.cfg.strategy.is_empty() { return Err("strategy 不能为空".into()); }
        if self.cfg.triggers.is_empty() { return Err("至少需要一个触发器".into()); }
        Ok(())
    }

    /// 承诺阶段自动化执行（占位：集成 wasm VotingSystem 由上层注入）
    #[allow(dead_code)]
    pub fn execute_commit(&mut self, session_id: &str, payload: &serde_json::Value) -> Result<ExecutionReport, String> {
        self.run_with_retry("commit", session_id, payload)
    }

    /// 揭示阶段自动化执行
    #[allow(dead_code)]
    pub fn execute_reveal(&mut self, session_id: &str, payload: &serde_json::Value) -> Result<ExecutionReport, String> {
        self.run_with_retry("reveal", session_id, payload)
    }

    #[allow(dead_code)]
    fn run_with_retry(&mut self, phase: &str, session_id: &str, payload: &serde_json::Value) -> Result<ExecutionReport, String> {
        self.validate_config()?;
        let now = now_secs();
        let mut attempts = 0u32;
        loop {
            attempts += 1;
            match self.do_execute(phase, session_id, payload) {
                Ok(details) => {
                    self.runtime.last_run_ts = Some(now);
                    self.runtime.last_error = None;
                    self.runtime.executed_count += 1;
                    return Ok(ExecutionReport { phase: phase.to_string(), session_id: session_id.to_string(), attempts, success: true, details });
                }
                Err(e) => {
                    self.runtime.last_error = Some(e.clone());
                    if attempts >= self.cfg.max_retries { return Err(e); }
                }
            }
        }
    }

    /// 实际执行逻辑（此处为占位，返回可复现的哈希签名以便验证）
    #[allow(dead_code)]
    fn do_execute(&self, phase: &str, session_id: &str, payload: &serde_json::Value) -> Result<String, String> {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(phase.as_bytes());
        hasher.update(session_id.as_bytes());
        hasher.update(payload.to_string().as_bytes());
        let sig = format!("{:x}", hasher.finalize());
        Ok(sig)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExecutionReport {
    pub phase: String,
    pub session_id: String,
    pub attempts: u32,
    pub success: bool,
    pub details: String,
}

#[allow(dead_code)]
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_and_execute() {
        let engine = IAgentEngine::new(IAgentConfig::default());
        assert!(engine.validate_config().is_ok());
    }

    #[test]
    fn test_execute_commit_and_reveal() {
        let mut engine = IAgentEngine::new(IAgentConfig::default());
        let payload = serde_json::json!({"seed":"abc","params":{"k":3}});
        let rep1 = engine.execute_commit("sess-1", &payload).unwrap();
        let rep2 = engine.execute_reveal("sess-1", &payload).unwrap();
        assert!(rep1.success && rep2.success);
        assert_eq!(rep1.session_id, rep2.session_id);
        assert_ne!(rep1.details, rep2.details); // phase 不同导致签名不同
    }
}


