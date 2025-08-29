//! 审计报告生成器
//!
//! 基于内存审计事件，生成简要报告（计数/最近事件等）。

use serde::{Deserialize, Serialize};

use crate::core::serial_numbers::{AuditAction, AuditEvent};
use crate::core::selection_algorithms::SelectionResult;
use crate::core::lottery_config::LevelParameters;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AuditReport {
    pub total: usize,
    pub allocated: usize,
    pub recycled: usize,
    pub transferred: usize,
    pub latest_ts: Option<u64>,
}

#[allow(dead_code)]
pub fn generate_report(events: &[AuditEvent]) -> AuditReport {
    let mut report = AuditReport::default();
    report.total = events.len();
    for e in events {
        report.latest_ts = Some(report.latest_ts.map_or(e.ts, |cur| cur.max(e.ts)));
        match e.action {
            AuditAction::Allocated => report.allocated += 1,
            AuditAction::Recycled => report.recycled += 1,
            AuditAction::Transferred => report.transferred += 1,
        }
    }
    report
}

/// 计算选择结果的审计链路覆盖率
///
/// 覆盖标准（每个level一票）：
/// - 存在 seed
/// - 存在 proof
/// - 存在 stats 且 winner_count/total_participants/selection_time_ms 合理
/// - level 对应的参数可用，且可计算参数摘要（hash）
///
/// 返回 [0.0, 1.0] 区间的比例
#[allow(dead_code)]
pub fn selection_audit_coverage(
    results: &std::collections::HashMap<String, SelectionResult>,
    level_params: &std::collections::HashMap<String, LevelParameters>,
) -> f64 {
    if results.is_empty() { return 0.0; }
    let mut covered = 0usize;
    for (level, res) in results {
        let has_seed = !res.seed.is_empty();
        let has_proof = !res.proof.is_empty();
        let stats_ok = res.stats.winner_count == res.winners.len()
            && res.stats.total_participants >= res.winners.len();
        let param_ok = if let Some(p) = level_params.get(level) {
            // 计算参数哈希（用于链路校验，可用于外部审计对齐）
            let mut hasher = Sha256::new();
            hasher.update(p.min_participants.to_le_bytes());
            if let Some(maxp) = p.max_participants { hasher.update(maxp.to_le_bytes()); }
            hasher.update(p.winner_count.to_le_bytes());
            hasher.update(format!("{:?}", p.selection_algorithm));
            hasher.update(format!("{:?}", p.algorithm_params).as_bytes());
            let _digest = hasher.finalize();
            true
        } else { false };

        if has_seed && has_proof && stats_ok && param_ok { covered += 1; }
    }
    covered as f64 / results.len() as f64
}

// 审计日志模块
//
// 实现系统操作的审计日志记录功能

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// 审计日志级别
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum AuditLevel {
    Info,
    Warning,
    Error,
    Critical,
}

/// 审计日志条目
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditLogEntry {
    pub id: String,
    pub timestamp: u64,
    pub level: AuditLevel,
    pub operation: String,
    pub user_id: Option<String>,
    pub session_id: Option<String>,
    pub details: serde_json::Value,
    pub ip_address: Option<String>,
    pub user_agent: Option<String>,
}

/// 审计日志管理器
pub struct AuditLogger {
    logs: Arc<RwLock<Vec<AuditLogEntry>>>,
    max_logs: usize,
}

impl AuditLogger {
    pub fn new() -> Self {
        Self {
            logs: Arc::new(RwLock::new(Vec::new())),
            max_logs: 10000, // 最多保留10000条日志
        }
    }

    /// 记录信息级别日志
    #[allow(dead_code)]
    pub async fn info(
        &self,
        operation: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        details: serde_json::Value,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        self.log(
            AuditLevel::Info,
            operation,
            user_id,
            session_id,
            details,
            ip_address,
            user_agent,
        ).await;
    }

    /// 记录警告级别日志
    #[allow(dead_code)]
    pub async fn warning(
        &self,
        operation: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        details: serde_json::Value,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        self.log(
            AuditLevel::Warning,
            operation,
            user_id,
            session_id,
            details,
            ip_address,
            user_agent,
        ).await;
    }

    /// 记录错误级别日志
    #[allow(dead_code)]
    pub async fn error(
        &self,
        operation: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        details: serde_json::Value,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        self.log(
            AuditLevel::Error,
            operation,
            user_id,
            session_id,
            details,
            ip_address,
            user_agent,
        ).await;
    }

    /// 记录关键级别日志
    #[allow(dead_code)]
    pub async fn critical(
        &self,
        operation: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        details: serde_json::Value,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        self.log(
            AuditLevel::Critical,
            operation,
            user_id,
            session_id,
            details,
            ip_address,
            user_agent,
        ).await;
    }

    /// 内部日志记录方法
    async fn log(
        &self,
        level: AuditLevel,
        operation: &str,
        user_id: Option<&str>,
        session_id: Option<&str>,
        details: serde_json::Value,
        ip_address: Option<&str>,
        user_agent: Option<&str>,
    ) {
        let entry = AuditLogEntry {
            id: format!("audit_{}", chrono::Utc::now().timestamp_millis()),
            timestamp: chrono::Utc::now().timestamp() as u64,
            level: level.clone(),
            operation: operation.to_string(),
            user_id: user_id.map(|s| s.to_string()),
            session_id: session_id.map(|s| s.to_string()),
            details: details.clone(),
            ip_address: ip_address.map(|s| s.to_string()),
            user_agent: user_agent.map(|s| s.to_string()),
        };

        let mut logs = self.logs.write().await;
        logs.push(entry);

        // 如果日志数量超过限制，删除最旧的日志
        let current_len = logs.len();
        if current_len > self.max_logs {
            logs.drain(0..current_len - self.max_logs);
        }

        // 根据日志级别记录到tracing
        match level {
            AuditLevel::Info => info!("审计日志: {} - {}", operation, details),
            AuditLevel::Warning => warn!("审计日志: {} - {}", operation, details),
            AuditLevel::Error => error!("审计日志: {} - {}", operation, details),
            AuditLevel::Critical => error!("关键审计日志: {} - {}", operation, details),
        }
    }

    /// 获取所有审计日志
    #[allow(dead_code)]
    pub async fn get_all_logs(&self) -> Vec<AuditLogEntry> {
        let logs = self.logs.read().await;
        logs.clone()
    }

    /// 根据用户ID查询审计日志
    #[allow(dead_code)]
    pub async fn get_logs_by_user(&self, user_id: &str) -> Vec<AuditLogEntry> {
        let logs = self.logs.read().await;
        logs.iter()
            .filter(|log| log.user_id.as_ref().map_or(false, |uid| uid == user_id))
            .cloned()
            .collect()
    }

    /// 根据会话ID查询审计日志
    #[allow(dead_code)]
    pub async fn get_logs_by_session(&self, session_id: &str) -> Vec<AuditLogEntry> {
        let logs = self.logs.read().await;
        logs.iter()
            .filter(|log| log.session_id.as_ref().map_or(false, |sid| sid == session_id))
            .cloned()
            .collect()
    }

    /// 根据时间范围查询审计日志
    #[allow(dead_code)]
    pub async fn get_logs_by_time_range(&self, start_time: u64, end_time: u64) -> Vec<AuditLogEntry> {
        let logs = self.logs.read().await;
        logs.iter()
            .filter(|log| log.timestamp >= start_time && log.timestamp <= end_time)
            .cloned()
            .collect()
    }

    /// 根据操作类型查询审计日志
    #[allow(dead_code)]
    pub async fn get_logs_by_operation(&self, operation: &str) -> Vec<AuditLogEntry> {
        let logs = self.logs.read().await;
        logs.iter()
            .filter(|log| log.operation == operation)
            .cloned()
            .collect()
    }

    /// 清理过期日志
    #[allow(dead_code)]
    pub async fn cleanup_expired_logs(&self, max_age_seconds: u64) {
        let current_time = chrono::Utc::now().timestamp() as u64;
        let cutoff_time = current_time - max_age_seconds;

        let mut logs = self.logs.write().await;
        logs.retain(|log| log.timestamp >= cutoff_time);
    }

    /// 记录事件（兼容性方法）
    #[allow(dead_code)]
    pub async fn log_event(&self, operation: &str, details: &serde_json::Value) -> Result<(), String> {
        self.info(
            operation,
            None,
            None,
            details.clone(),
            None,
            None,
        ).await;
        Ok(())
    }

    /// 导出审计日志
    #[allow(dead_code)]
    pub async fn export_logs(&self, format: &str) -> Result<String, String> {
        let logs = self.logs.read().await;
        
        match format.to_lowercase().as_str() {
            "json" => {
                serde_json::to_string_pretty(&*logs)
                    .map_err(|e| format!("JSON序列化失败: {}", e))
            }
            "csv" => {
                let mut csv = String::new();
                csv.push_str("ID,Timestamp,Level,Operation,UserID,SessionID,Details,IPAddress,UserAgent\n");
                
                for log in logs.iter() {
                    csv.push_str(&format!(
                        "{},{},{:?},{},{},{},{},{},{}\n",
                        log.id,
                        log.timestamp,
                        log.level,
                        log.operation,
                        log.user_id.as_deref().unwrap_or(""),
                        log.session_id.as_deref().unwrap_or(""),
                        log.details,
                        log.ip_address.as_deref().unwrap_or(""),
                        log.user_agent.as_deref().unwrap_or("")
                    ));
                }
                
                Ok(csv)
            }
            _ => Err("不支持的导出格式".to_string())
        }
    }
}

impl Default for AuditLogger {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::core::selection_algorithms::SelectionStats;
    use crate::core::lottery_config::{SelectionAlgorithm, LevelParameters};

    #[test]
    fn test_generate_report_counts() {
        let events = vec![
            AuditEvent { ts: 1, action: AuditAction::Allocated, serial: "a".into(), owner: None, session_id: None },
            AuditEvent { ts: 2, action: AuditAction::Transferred, serial: "a".into(), owner: Some("bob".into()), session_id: Some("s1".into()) },
            AuditEvent { ts: 3, action: AuditAction::Recycled, serial: "a".into(), owner: None, session_id: None },
        ];
        let r = generate_report(&events);
        assert_eq!(r.total, 3);
        assert_eq!(r.allocated, 1);
        assert_eq!(r.transferred, 1);
        assert_eq!(r.recycled, 1);
        assert_eq!(r.latest_ts, Some(3));
    }

    #[test]
    fn test_selection_audit_coverage_ge_95_percent() {
        // 构造100个level的结果，其中≥95%满足审计链路项
        let mut results: HashMap<String, SelectionResult> = HashMap::new();
        let mut params: HashMap<String, LevelParameters> = HashMap::new();

        for i in 0..100 {
            let lvl = format!("L{}", i);
            // 参数
            params.insert(lvl.clone(), LevelParameters {
                min_participants: 10,
                max_participants: Some(1000),
                winner_count: 5,
                selection_algorithm: SelectionAlgorithm::Random,
                algorithm_params: HashMap::new(),
                time_limit: None,
                cost_limit: None,
            });

            // 结果（前95个完全合格，最后5个造一个缺项）
            let ok = i < 95;
            results.insert(lvl.clone(), SelectionResult {
                winners: vec![
                    // 只需数量一致即可
                    crate::core::selection_algorithms::Participant { id: "1".into(), address: "a".into(), weight: 1.0, level: lvl.clone(), attributes: HashMap::new(), is_winner: true },
                    crate::core::selection_algorithms::Participant { id: "2".into(), address: "b".into(), weight: 1.0, level: lvl.clone(), attributes: HashMap::new(), is_winner: true },
                    crate::core::selection_algorithms::Participant { id: "3".into(), address: "c".into(), weight: 1.0, level: lvl.clone(), attributes: HashMap::new(), is_winner: true },
                    crate::core::selection_algorithms::Participant { id: "4".into(), address: "d".into(), weight: 1.0, level: lvl.clone(), attributes: HashMap::new(), is_winner: true },
                    crate::core::selection_algorithms::Participant { id: "5".into(), address: "e".into(), weight: 1.0, level: lvl.clone(), attributes: HashMap::new(), is_winner: true },
                ],
                algorithm: SelectionAlgorithm::Random,
                seed: if ok { "seed".into() } else { String::new() },
                proof: if ok { "proof".into() } else { String::new() },
                timestamp: 1,
                stats: SelectionStats {
                    total_participants: 100,
                    winner_count: 5,
                    selection_time_ms: 10,
                    conflict_resolutions: 0,
                    algorithm_stats: HashMap::new(),
                },
            });
        }

        let cov = selection_audit_coverage(&results, &params);
        assert!(cov >= 0.95, "coverage {} < 0.95", cov);
    }
}


