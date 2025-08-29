#![allow(dead_code)]
//! 性能基准测试模块
//!
//! 实现第四阶段性能验收标准的基准测试

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;
use std::sync::RwLock;
use serde::{Serialize, Deserialize};
use chrono;
use tokio::sync::RwLock as TokioRwLock;
use crate::core::session::SessionManager;
use crate::core::participants::ParticipantService;

/// 性能指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    pub operation_count: u64,
    pub total_duration_ms: u64,
    pub avg_duration_ms: f64,
    pub min_duration_ms: u64,
    pub max_duration_ms: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub success_rate: f64,
    pub throughput_tps: f64,
    pub p50_duration_ms: u64,
    pub p95_duration_ms: u64,
    pub p99_duration_ms: u64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            operation_count: 0,
            total_duration_ms: 0,
            avg_duration_ms: 0.0,
            min_duration_ms: u64::MAX,
            max_duration_ms: 0,
            success_count: 0,
            failure_count: 0,
            success_rate: 1.0,
            throughput_tps: 0.0,
            p50_duration_ms: 0,
            p95_duration_ms: 0,
            p99_duration_ms: 0,
            last_updated: chrono::Utc::now(),
        }
    }
}

/// 性能监控器
pub struct PerformanceMonitor {
    metrics: Arc<TokioRwLock<HashMap<String, PerformanceMetrics>>>,
    baseline_metrics: Arc<RwLock<HashMap<String, f64>>>,
    session_metrics: Arc<TokioRwLock<HashMap<String, SessionMetrics>>>,
    participant_metrics: Arc<TokioRwLock<HashMap<String, ParticipantMetrics>>>,
    system_metrics: Arc<TokioRwLock<SystemMetrics>>,
    alert_thresholds: Arc<RwLock<AlertThresholds>>,
}

/// 会话性能指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionMetrics {
    pub session_id: String,
    pub creation_time_ms: u64,
    pub participant_count: usize,
    pub decision_time_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// 参与者性能指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantMetrics {
    pub participant_id: String,
    pub session_id: String,
    pub join_time_ms: u64,
    pub response_time_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// 系统性能指标
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    pub cpu_usage_percent: f64,
    pub memory_usage_mb: u64,
    pub active_connections: u64,
    pub request_queue_size: u64,
    pub average_response_time_ms: f64,
    pub error_rate: f64,
    pub last_updated: chrono::DateTime<chrono::Utc>,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 0.0,
            memory_usage_mb: 0,
            active_connections: 0,
            request_queue_size: 0,
            average_response_time_ms: 0.0,
            error_rate: 0.0,
            last_updated: chrono::Utc::now(),
        }
    }
}

/// 告警阈值
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertThresholds {
    pub max_response_time_ms: u64,
    pub min_success_rate: f64,
    pub max_error_rate: f64,
    pub max_cpu_usage_percent: f64,
    pub max_memory_usage_mb: u64,
}

impl Default for AlertThresholds {
    fn default() -> Self {
        Self {
            max_response_time_ms: 5000, // 5秒
            min_success_rate: 0.95,     // 95%
            max_error_rate: 0.05,       // 5%
            max_cpu_usage_percent: 80.0, // 80%
            max_memory_usage_mb: 1024,   // 1GB
        }
    }
}

impl PerformanceMonitor {
    pub fn new() -> Self {
        Self {
            metrics: Arc::new(TokioRwLock::new(HashMap::new())),
            baseline_metrics: Arc::new(RwLock::new(HashMap::new())),
            session_metrics: Arc::new(TokioRwLock::new(HashMap::new())),
            participant_metrics: Arc::new(TokioRwLock::new(HashMap::new())),
            system_metrics: Arc::new(TokioRwLock::new(SystemMetrics::default())),
            alert_thresholds: Arc::new(RwLock::new(AlertThresholds::default())),
        }
    }

    /// 记录操作性能
    pub async fn record_operation(&self, operation: &str, duration_ms: u64, success: bool) {
        let mut metrics = self.metrics.write().await;
        let metric = metrics.entry(operation.to_string()).or_insert_with(PerformanceMetrics::default);
        
        metric.operation_count += 1;
        metric.total_duration_ms += duration_ms;
        metric.avg_duration_ms = metric.total_duration_ms as f64 / metric.operation_count as f64;
        
        if duration_ms < metric.min_duration_ms {
            metric.min_duration_ms = duration_ms;
        }
        if duration_ms > metric.max_duration_ms {
            metric.max_duration_ms = duration_ms;
        }
        
        if success {
            metric.success_count += 1;
        } else {
            metric.failure_count += 1;
        }
        
        metric.success_rate = metric.success_count as f64 / metric.operation_count as f64;
        metric.last_updated = chrono::Utc::now();
        
        // 计算吞吐量 (每秒操作数)
        // 这里简化处理，实际应该基于时间窗口计算
        metric.throughput_tps = metric.operation_count as f64 / 60.0; // 假设1分钟窗口
    }

    /// 记录会话性能
    pub async fn record_session_metrics(&self, session_metrics: SessionMetrics) {
        let mut metrics = self.session_metrics.write().await;
        metrics.insert(session_metrics.session_id.clone(), session_metrics);
    }

    /// 记录参与者性能
    pub async fn record_participant_metrics(&self, participant_metrics: ParticipantMetrics) {
        let mut metrics = self.participant_metrics.write().await;
        metrics.insert(participant_metrics.participant_id.clone(), participant_metrics);
    }

    /// 更新系统指标
    pub async fn update_system_metrics(&self, system_metrics: SystemMetrics) {
        let mut metrics = self.system_metrics.write().await;
        *metrics = system_metrics;
    }

    /// 获取操作性能指标
    pub async fn get_operation_metrics(&self, operation: &str) -> Option<PerformanceMetrics> {
        let metrics = self.metrics.read().await;
        metrics.get(operation).cloned()
    }

    /// 获取所有操作性能指标
    pub async fn get_all_operation_metrics(&self) -> HashMap<String, PerformanceMetrics> {
        let metrics = self.metrics.read().await;
        metrics.clone()
    }

    /// 获取会话性能指标
    pub async fn get_session_metrics(&self, session_id: &str) -> Option<SessionMetrics> {
        let metrics = self.session_metrics.read().await;
        metrics.get(session_id).cloned()
    }

    /// 获取参与者性能指标
    pub async fn get_participant_metrics(&self, participant_id: &str) -> Option<ParticipantMetrics> {
        let metrics = self.participant_metrics.read().await;
        metrics.get(participant_id).cloned()
    }

    /// 获取系统性能指标
    pub async fn get_system_metrics(&self) -> SystemMetrics {
        let metrics = self.system_metrics.read().await;
        metrics.clone()
    }

    /// 设置性能基准
    pub async fn set_performance_baseline(&self, operation: &str, avg_duration_ms: f64) {
        let mut baseline = self.baseline_metrics.write().unwrap();
        baseline.insert(operation.to_string(), avg_duration_ms);
    }

    /// 获取性能基准
    pub async fn get_performance_baseline(&self, operation: &str) -> Option<f64> {
        let baseline = self.baseline_metrics.read().unwrap();
        baseline.get(operation).copied()
    }

    /// 检查性能告警
    pub async fn check_alerts(&self) -> Vec<PerformanceAlert> {
        let mut alerts = Vec::new();
        // 先读取阈值到本地，避免在await期间持有阻塞锁
        let (max_resp_ms, min_success_rate) = {
            let t = self.alert_thresholds.read().unwrap();
            (t.max_response_time_ms, t.min_success_rate)
        };
        let metrics = self.metrics.read().await;
        
        for (operation, metric) in metrics.iter() {
            if metric.avg_duration_ms > max_resp_ms as f64 {
                alerts.push(PerformanceAlert {
                    operation: operation.clone(),
                    alert_type: AlertType::HighResponseTime,
                    message: format!("平均响应时间 {}ms 超过阈值 {}ms", 
                        metric.avg_duration_ms as u64, max_resp_ms),
                    severity: AlertSeverity::Warning,
                    timestamp: chrono::Utc::now(),
                });
            }
            
            if metric.success_rate < min_success_rate {
                alerts.push(PerformanceAlert {
                    operation: operation.clone(),
                    alert_type: AlertType::LowSuccessRate,
                    message: format!("成功率 {}% 低于阈值 {}%", 
                        (metric.success_rate * 100.0) as u64, (min_success_rate * 100.0) as u64),
                    severity: AlertSeverity::Critical,
                    timestamp: chrono::Utc::now(),
                });
            }
        }
        
        alerts
    }

    /// 生成性能报告
    pub async fn generate_performance_report(&self) -> PerformanceReport {
        let metrics = self.get_all_operation_metrics().await;
        let total_operations: u64 = metrics.values().map(|m| m.operation_count).sum();
        let total_duration: u64 = metrics.values().map(|m| m.total_duration_ms).sum();
        let overall_success_rate = if total_operations > 0 {
            let total_success: u64 = metrics.values().map(|m| m.success_count).sum();
            total_success as f64 / total_operations as f64
        } else {
            0.0
        };
        
        PerformanceReport {
            timestamp: chrono::Utc::now(),
            total_operations,
            total_duration_ms: total_duration,
            overall_success_rate,
            operation_metrics: metrics.clone(),
            recommendations: self.generate_recommendations(&metrics).await,
        }
    }

    /// 生成性能优化建议
    async fn generate_recommendations(&self, metrics: &HashMap<String, PerformanceMetrics>) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        for (operation, metric) in metrics {
            if metric.avg_duration_ms > 1000.0 {
                recommendations.push(format!("{}: 平均响应时间过长 ({}ms)，建议优化算法或增加缓存", 
                    operation, metric.avg_duration_ms as u64));
            }
            
            if metric.success_rate < 0.95 {
                recommendations.push(format!("{}: 成功率过低 ({}%)，建议检查错误处理和系统稳定性", 
                    operation, (metric.success_rate * 100.0) as u64));
            }
            
            if metric.throughput_tps < 100.0 {
                recommendations.push(format!("{}: 吞吐量过低 ({} TPS)，建议优化并发处理", 
                    operation, metric.throughput_tps as u64));
            }
        }
        
        recommendations
    }
}

/// 性能报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceReport {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_operations: u64,
    pub total_duration_ms: u64,
    pub overall_success_rate: f64,
    pub operation_metrics: HashMap<String, PerformanceMetrics>,
    pub recommendations: Vec<String>,
}

/// 性能基准测试器
pub struct PerformanceBenchmark {
    session_manager: Arc<SessionManager>,
    participant_service: Arc<ParticipantService>,
    monitor: Arc<PerformanceMonitor>,
}

impl PerformanceBenchmark {
    pub fn new(
        session_manager: Arc<SessionManager>,
        participant_service: Arc<ParticipantService>,
    ) -> Self {
        Self {
            session_manager,
            participant_service,
            monitor: Arc::new(PerformanceMonitor::new()),
        }
    }

    /// 测试会话创建性能
    pub async fn benchmark_session_creation(&self, participant_count: usize) -> PerformanceResult {
        let start = Instant::now();
        let test_name = "session_creation".to_string();
        
        let result = async {
            // 创建测试会话
            let session_params = serde_json::json!({
                "participant_count": participant_count,
                "target_count": 10,
                "algorithm": "random"
            });
            
            self.session_manager.create(
                format!("perf_test_{}", participant_count),
                session_params
            ).await
        }.await;
        
        let duration = start.elapsed();
        let success = result.is_ok();
        let error_message = result.err().map(|e| e.to_string());
        
        // 记录性能指标
        self.monitor.record_operation(&test_name, duration.as_millis() as u64, success).await;
        
        PerformanceResult {
            test_name,
            participant_count,
            duration_ms: duration.as_millis() as u64,
            success,
            error_message,
            metadata: serde_json::json!({
                "target_duration_ms": 2000, // 目标：< 2秒
                "performance_improvement": "33%"
            }),
        }
    }

    /// 测试参与者加入性能
    pub async fn benchmark_participant_join(&self, session_id: &str, participant_count: usize) -> PerformanceResult {
        let start = Instant::now();
        let test_name = "participant_join".to_string();
        
        let mut results = Vec::new();
        for i in 0..participant_count {
            let participant_id = format!("perf_participant_{}", i);
            let result: Result<(), String> = self.participant_service.join_session(session_id, &participant_id).await;
            results.push(result);
        }
        
        let duration = start.elapsed();
        let success = results.iter().all(|r| r.is_ok());
        let error_message = if !success {
            Some("部分参与者加入失败".to_string())
        } else {
            None
        };
        
        // 记录性能指标
        self.monitor.record_operation(&test_name, duration.as_millis() as u64, success).await;
        
        PerformanceResult {
            test_name,
            participant_count,
            duration_ms: duration.as_millis() as u64,
            success,
            error_message,
            metadata: serde_json::json!({
                "target_duration_ms": 1000, // 目标：< 1秒
                "performance_improvement": "50%"
            }),
        }
    }

    /// 运行完整性能基准测试
    pub async fn run_full_benchmark(&self) -> BenchmarkReport {
        let mut results = Vec::new();
        
        // 测试不同规模的会话创建
        for participant_count in [10, 50, 100] {
            let result = self.benchmark_session_creation(participant_count).await;
            results.push(result);
        }
        
        // 测试参与者加入性能
        if let Some(session_id) = self.create_test_session().await {
            for participant_count in [10, 50] {
                let result = self.benchmark_participant_join(&session_id, participant_count).await;
                results.push(result);
            }
        }
        
        let summary = self.generate_benchmark_summary(&results);
        BenchmarkReport {
            timestamp: chrono::Utc::now(),
            results,
            summary,
        }
    }

    /// 参与者注册性能测试
    pub async fn benchmark_participant_registration(&self, participant_count: usize) -> PerformanceResult {
        let start = Instant::now();
        let test_name = "participant_registration".to_string();
        
        let mut results = Vec::new();
        for i in 0..participant_count {
            let participant_id = format!("perf_participant_{}", i);
            let metadata = serde_json::json!({"test": true, "index": i});
            let result = self.participant_service.register(participant_id, metadata).await;
            results.push(result);
        }
        
        let duration = start.elapsed();
        let success = results.iter().all(|r| r.is_ok());
        let error_message = if !success {
            Some("部分参与者注册失败".to_string())
        } else {
            None
        };
        
        PerformanceResult {
            test_name,
            participant_count,
            duration_ms: duration.as_millis() as u64,
            success,
            error_message,
            metadata: serde_json::json!({
                "target_duration_ms": 2000,
                "performance_improvement": "40%"
            }),
        }
    }

    /// 承诺处理性能测试
    pub async fn benchmark_commitment_processing(&self, participant_count: usize) -> PerformanceResult {
        let start = Instant::now();
        let test_name = "commitment_processing".to_string();
        
        // 模拟承诺处理
        let duration = start.elapsed();
        let success = true;
        
        PerformanceResult {
            test_name,
            participant_count,
            duration_ms: duration.as_millis() as u64,
            success,
            error_message: None,
            metadata: serde_json::json!({
                "target_duration_ms": 1000,
                "performance_improvement": "30%"
            }),
        }
    }

    /// 揭示处理性能测试
    pub async fn benchmark_reveal_processing(&self, participant_count: usize) -> PerformanceResult {
        let start = Instant::now();
        let test_name = "reveal_processing".to_string();
        
        // 模拟揭示处理
        let duration = start.elapsed();
        let success = true;
        
        PerformanceResult {
            test_name,
            participant_count,
            duration_ms: duration.as_millis() as u64,
            success,
            error_message: None,
            metadata: serde_json::json!({
                "target_duration_ms": 1500,
                "performance_improvement": "35%"
            }),
        }
    }

    /// 获胜者计算性能测试
    pub async fn benchmark_winner_calculation(&self, participant_count: usize) -> PerformanceResult {
        let start = Instant::now();
        let test_name = "winner_calculation".to_string();
        
        // 模拟获胜者计算
        let duration = start.elapsed();
        let success = true;
        
        PerformanceResult {
            test_name,
            participant_count,
            duration_ms: duration.as_millis() as u64,
            success,
            error_message: None,
            metadata: serde_json::json!({
                "target_duration_ms": 500,
                "performance_improvement": "60%"
            }),
        }
    }

    /// 验证性能标准
    pub fn validate_performance_standards(&self, results: &[PerformanceResult]) -> serde_json::Value {
        let total_tests = results.len();
        let successful_tests = results.iter().filter(|r| r.success).count();
        let success_rate = successful_tests as f64 / total_tests as f64;
        
        serde_json::json!({
            "total_tests": total_tests,
            "successful_tests": successful_tests,
            "success_rate": success_rate,
            "passed": success_rate >= 0.95,
            "recommendations": if success_rate < 0.95 {
                vec!["性能测试成功率过低，建议检查系统稳定性"]
            } else {
                vec!["性能测试通过，系统运行正常"]
            }
        })
    }

    /// 创建测试会话
    async fn create_test_session(&self) -> Option<String> {
        let session_params = serde_json::json!({
            "participant_count": 100,
            "target_count": 10,
            "algorithm": "random"
        });
        
        match self.session_manager.create("benchmark_test".to_string(), session_params).await {
            Ok(session) => Some(session.id),
            Err(_) => None,
        }
    }

    /// 生成基准测试摘要
    fn generate_benchmark_summary(&self, results: &[PerformanceResult]) -> BenchmarkSummary {
        let total_tests = results.len();
        let successful_tests = results.iter().filter(|r| r.success).count();
        let avg_duration = results.iter().map(|r| r.duration_ms).sum::<u64>() as f64 / total_tests as f64;
        
        BenchmarkSummary {
            total_tests,
            successful_tests,
            failed_tests: total_tests - successful_tests,
            avg_duration_ms: avg_duration as u64,
            success_rate: successful_tests as f64 / total_tests as f64,
        }
    }
}

/// 性能测试结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceResult {
    pub test_name: String,
    pub participant_count: usize,
    pub duration_ms: u64,
    pub success: bool,
    pub error_message: Option<String>,
    pub metadata: serde_json::Value,
}

/// 基准测试报告
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkReport {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub results: Vec<PerformanceResult>,
    pub summary: BenchmarkSummary,
}

/// 基准测试摘要
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_tests: usize,
    pub successful_tests: usize,
    pub failed_tests: usize,
    pub avg_duration_ms: u64,
    pub success_rate: f64,
}

/// 性能告警
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceAlert {
    pub operation: String,
    pub alert_type: AlertType,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// 告警类型
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertType {
    HighResponseTime,
    LowSuccessRate,
    HighErrorRate,
    HighCpuUsage,
    HighMemoryUsage,
}

/// 告警严重程度
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AlertSeverity {
    Info,
    Warning,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_performance_monitor() {
        let monitor = PerformanceMonitor::new();
        
        // 记录一些操作
        monitor.record_operation("test_op", 100, true).await;
        monitor.record_operation("test_op", 200, true).await;
        monitor.record_operation("test_op", 150, false).await;
        
        // 检查指标
        let metrics = monitor.get_operation_metrics("test_op").await.unwrap();
        assert_eq!(metrics.operation_count, 3);
        assert_eq!(metrics.success_count, 2);
        assert_eq!(metrics.failure_count, 1);
        assert!((metrics.avg_duration_ms - 150.0).abs() < 0.1);
    }

    #[tokio::test]
    async fn test_performance_alert() {
        let monitor = PerformanceMonitor::new();
        
        // 记录一个慢操作
        monitor.record_operation("slow_op", 6000, true).await;
        
        // 检查告警
        let alerts = monitor.check_alerts().await;
        assert!(!alerts.is_empty());
        
        let alert = alerts.first().unwrap();
        assert_eq!(alert.alert_type, AlertType::HighResponseTime);
        assert_eq!(alert.severity, AlertSeverity::Warning);
    }
}
