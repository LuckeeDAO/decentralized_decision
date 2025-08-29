#![allow(dead_code)]

//! 压力测试和性能调优模块
//!
//! 实现第六阶段的压力测试、性能调优和性能验证功能

use std::sync::Arc;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use tokio::sync::Semaphore;
use serde::{Serialize, Deserialize};
use anyhow::Result;

use crate::core::performance::PerformanceMonitor;
use crate::core::concurrency::ConcurrencyController;

/// 压力测试配置
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StressTestConfig {
    pub test_duration_seconds: u64,
    pub target_tps: u64,
    pub max_concurrent_users: usize,
    pub ramp_up_seconds: u64,
    pub ramp_down_seconds: u64,
    pub error_threshold_percent: f64,
    pub response_time_threshold_ms: u64,
}

impl Default for StressTestConfig {
    fn default() -> Self {
        Self {
            test_duration_seconds: 300, // 5分钟
            target_tps: 5000,
            max_concurrent_users: 10000,
            ramp_up_seconds: 60, // 1分钟
            ramp_down_seconds: 60, // 1分钟
            error_threshold_percent: 5.0,
            response_time_threshold_ms: 800,
        }
    }
}

/// 压力测试结果
#[derive(Debug, Clone)]
#[allow(dead_code)]
pub struct StressTestResult {
    #[allow(dead_code)]
    pub test_name: String,
    #[allow(dead_code)]
    pub config: StressTestConfig,
    #[allow(dead_code)]
    pub start_time: Instant,
    #[allow(dead_code)]
    pub end_time: Option<Instant>,
    #[allow(dead_code)]
    pub total_requests: u64,
    #[allow(dead_code)]
    pub successful_requests: u64,
    #[allow(dead_code)]
    pub failed_requests: u64,
    #[allow(dead_code)]
    pub avg_response_time_ms: f64,
    #[allow(dead_code)]
    pub p50_response_time_ms: u64,
    #[allow(dead_code)]
    pub p95_response_time_ms: u64,
    #[allow(dead_code)]
    pub p99_response_time_ms: u64,
    #[allow(dead_code)]
    pub min_response_time_ms: u64,
    #[allow(dead_code)]
    pub max_response_time_ms: u64,
    #[allow(dead_code)]
    pub actual_tps: f64,
    #[allow(dead_code)]
    pub error_rate_percent: f64,
    #[allow(dead_code)]
    pub success: bool,
    #[allow(dead_code)]
    pub error_messages: Vec<String>,
}



/// 测试状态
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TestStatus {
    Running,
    Completed,
    Failed,
    Cancelled,
    Passed,
}

/// 压力测试器
pub struct StressTester {
    #[allow(dead_code)]
    monitor: Arc<PerformanceMonitor>,
    #[allow(dead_code)]
    concurrency_controller: Arc<ConcurrencyController>,
}

impl StressTester {
    pub fn new(monitor: Arc<PerformanceMonitor>, max_concurrent: usize) -> Self {
        Self {
            monitor,
            concurrency_controller: Arc::new(ConcurrencyController::new(max_concurrent)),
        }
    }

    /// 运行负载测试
    #[allow(dead_code)]
    pub async fn run_load_test<F>(&self, test_name: &str, config: StressTestConfig, operation: F) -> StressTestResult
    where
        F: Fn() -> Result<()> + Send + Sync + 'static,
    {
        let start_time = Instant::now();
        let test_name = test_name.to_string();
        
        let mut total_requests = 0u64;
        let mut successful_requests = 0u64;
        let mut failed_requests = 0u64;
        let mut response_times = Vec::new();
        let mut error_messages = Vec::new();
        
        let semaphore = Arc::new(Semaphore::new(config.max_concurrent_users));
        let operation = Arc::new(operation);
        
        // 计算请求间隔以达到目标TPS
        let request_interval = Duration::from_micros(1_000_000 / config.target_tps);
        
        let test_duration = Duration::from_secs(config.test_duration_seconds);
        let ramp_up_duration = Duration::from_secs(config.ramp_up_seconds);
        let ramp_down_duration = Duration::from_secs(config.ramp_down_seconds);
        
        let mut handles = Vec::new();
        
        while start_time.elapsed() < test_duration {
            let elapsed = start_time.elapsed();
            
            // 计算当前应该的并发用户数（考虑ramp up和ramp down）
            let current_concurrent_users = if elapsed < ramp_up_duration {
                // Ramp up阶段
                let progress = elapsed.as_secs_f64() / ramp_up_duration.as_secs_f64();
                (config.max_concurrent_users as f64 * progress) as usize
            } else if elapsed > test_duration - ramp_down_duration {
                // Ramp down阶段
                let remaining = (test_duration - elapsed).as_secs_f64();
                let progress = remaining / ramp_down_duration.as_secs_f64();
                (config.max_concurrent_users as f64 * progress) as usize
            } else {
                // 稳定阶段
                config.max_concurrent_users
            };
            
            // 启动新的并发用户
            for _ in 0..current_concurrent_users {
                let semaphore = semaphore.clone();
                let operation = operation.clone();
                let monitor = self.monitor.clone();
                
                let handle = tokio::spawn(async move {
                    let _permit = semaphore.acquire().await.unwrap();
                    
                    let start = Instant::now();
                    let result = operation();
                    let duration = start.elapsed();
                    
                    // 记录性能指标
                    monitor.record_operation("stress_test", duration.as_millis() as u64, result.is_ok()).await;
                    
                    (duration, result)
                });
                
                handles.push(handle);
            }
            
            // 等待请求间隔
            tokio::time::sleep(request_interval).await;
        }
        
        // 等待所有请求完成
        for handle in handles {
            if let Ok((duration, result)) = handle.await {
                total_requests += 1;
                response_times.push(duration.as_millis() as u64);
                
                match result {
                    Ok(_) => successful_requests += 1,
                    Err(e) => {
                        failed_requests += 1;
                        error_messages.push(e.to_string());
                    }
                }
            }
        }
        
        let end_time = Instant::now();
        let test_duration_actual = end_time.duration_since(start_time);
        
        // 计算统计信息
        let avg_response_time = if !response_times.is_empty() {
            response_times.iter().sum::<u64>() as f64 / response_times.len() as f64
        } else {
            0.0
        };
        
        let mut sorted_times = response_times.clone();
        sorted_times.sort();
        
        let p50_idx = (sorted_times.len() as f64 * 0.5) as usize;
        let p95_idx = (sorted_times.len() as f64 * 0.95) as usize;
        let p99_idx = (sorted_times.len() as f64 * 0.99) as usize;
        
        let p50_response_time = sorted_times.get(p50_idx).unwrap_or(&0);
        let p95_response_time = sorted_times.get(p95_idx).unwrap_or(&0);
        let p99_response_time = sorted_times.get(p99_idx).unwrap_or(&0);
        
        let min_response_time = *sorted_times.first().unwrap_or(&0);
        let max_response_time = *sorted_times.last().unwrap_or(&0);
        
        let actual_tps = if test_duration_actual.as_secs() > 0 {
            total_requests as f64 / test_duration_actual.as_secs_f64()
        } else {
            0.0
        };
        
        let error_rate = if total_requests > 0 {
            (failed_requests as f64 / total_requests as f64) * 100.0
        } else {
            0.0
        };
        
        let success = error_rate <= config.error_threshold_percent && 
                     avg_response_time <= config.response_time_threshold_ms as f64;
        
        StressTestResult {
            test_name,
            config,
            start_time,
            end_time: Some(end_time),
            total_requests,
            successful_requests,
            failed_requests,
            avg_response_time_ms: avg_response_time,
            p50_response_time_ms: *p50_response_time,
            p95_response_time_ms: *p95_response_time,
            p99_response_time_ms: *p99_response_time,
            min_response_time_ms: min_response_time,
            max_response_time_ms: max_response_time,
            actual_tps,
            error_rate_percent: error_rate,
            success,
            error_messages,
        }
    }

    /// 运行稳定性测试
    #[allow(dead_code)]
    pub async fn run_stability_test<F>(&self, test_name: &str, config: StressTestConfig, operation: F) -> StressTestResult
    where
        F: Fn() -> Result<()> + Send + Sync + 'static,
    {
        // 稳定性测试使用更长的测试时间和更保守的配置
        let mut stability_config = config.clone();
        stability_config.test_duration_seconds = 3600; // 1小时
        stability_config.target_tps = config.target_tps / 2; // 降低TPS要求
        stability_config.error_threshold_percent = 1.0; // 更严格的错误率要求
        
        self.run_load_test(test_name, stability_config, operation).await
    }

    /// 运行极限测试
    #[allow(dead_code)]
    pub async fn run_extreme_test<F>(&self, test_name: &str, config: StressTestConfig, operation: F) -> StressTestResult
    where
        F: Fn() -> Result<()> + Send + Sync + 'static,
    {
        // 极限测试使用更高的负载
        let mut extreme_config = config.clone();
        extreme_config.target_tps = config.target_tps * 2; // 双倍TPS
        extreme_config.max_concurrent_users = config.max_concurrent_users * 2; // 双倍并发用户
        extreme_config.error_threshold_percent = 10.0; // 允许更高的错误率
        
        self.run_load_test(test_name, extreme_config, operation).await
    }
}

/// 性能调优器
#[allow(dead_code)]
pub struct PerformanceTuner {
    #[allow(dead_code)]
    monitor: Arc<PerformanceMonitor>,
    #[allow(dead_code)]
    baseline_metrics: Option<HashMap<String, f64>>,
}

impl PerformanceTuner {
    #[allow(dead_code)]
    pub fn new(monitor: Arc<PerformanceMonitor>) -> Self {
        Self {
            monitor,
            baseline_metrics: None,
        }
    }

    /// 设置性能基准
    #[allow(dead_code)]
    pub async fn set_baseline(&mut self) {
        let metrics = self.monitor.get_all_operation_metrics().await;
        let mut baseline = HashMap::new();
        
        for (operation, metric) in metrics {
            baseline.insert(operation, metric.avg_duration_ms);
        }
        
        self.baseline_metrics = Some(baseline);
    }

    /// 分析性能瓶颈
    #[allow(dead_code)]
    pub async fn analyze_bottlenecks(&self) -> Vec<BottleneckAnalysis> {
        let current_metrics = self.monitor.get_all_operation_metrics().await;
        let mut bottlenecks = Vec::new();
        
        if let Some(baseline) = &self.baseline_metrics {
            for (operation, current_metric) in current_metrics {
                if let Some(baseline_duration) = baseline.get(&operation) {
                    let improvement = ((*baseline_duration - current_metric.avg_duration_ms) / *baseline_duration) * 100.0;
                    
                    if improvement < 0.0 {
                        // 性能下降
                        bottlenecks.push(BottleneckAnalysis {
                            operation: operation.clone(),
                            current_performance: current_metric.avg_duration_ms,
                            baseline_performance: *baseline_duration,
                            improvement_percent: improvement,
                            severity: if improvement < -20.0 { BottleneckSeverity::Critical } 
                                     else if improvement < -10.0 { BottleneckSeverity::High }
                                     else { BottleneckSeverity::Medium },
                            recommendations: self.generate_recommendations(&operation, &current_metric),
                        });
                    }
                }
            }
        }
        
        bottlenecks.sort_by(|a, b| a.improvement_percent.partial_cmp(&b.improvement_percent).unwrap());
        bottlenecks
    }

    /// 生成优化建议
    #[allow(dead_code)]
    fn generate_recommendations(&self, operation: &str, metric: &crate::core::performance::PerformanceMetrics) -> Vec<String> {
        let mut recommendations = Vec::new();
        
        if metric.avg_duration_ms > 1000.0 {
            recommendations.push(format!("{}: 响应时间过长，建议优化算法或增加缓存", operation));
        }
        
        if metric.success_rate < 0.95 {
            recommendations.push(format!("{}: 成功率过低，建议检查错误处理和系统稳定性", operation));
        }
        
        if metric.throughput_tps < 100.0 {
            recommendations.push(format!("{}: 吞吐量过低，建议优化并发处理", operation));
        }
        
        if metric.p99_duration_ms as f64 > metric.avg_duration_ms * 3.0 {
            recommendations.push(format!("{}: P99响应时间异常，建议检查长尾问题", operation));
        }
        
        recommendations
    }

    /// 验证性能优化效果
    #[allow(dead_code)]
    pub async fn validate_optimization(&self, operation: &str) -> OptimizationValidation {
        let current_metrics = self.monitor.get_operation_metrics(operation).await;
        
        if let (Some(current), Some(baseline)) = (current_metrics, &self.baseline_metrics) {
            if let Some(baseline_duration) = baseline.get(operation) {
                let improvement = ((*baseline_duration - current.avg_duration_ms) / *baseline_duration) * 100.0;
                
                return OptimizationValidation {
                    operation: operation.to_string(),
                    baseline_performance: *baseline_duration,
                    current_performance: current.avg_duration_ms,
                    improvement_percent: improvement,
                    success: improvement > 0.0,
                    recommendations: if improvement < 0.0 {
                        vec!["性能出现回退，建议回滚优化或进一步调优".to_string()]
                    } else {
                        vec!["优化成功，性能得到提升".to_string()]
                    },
                };
            }
        }
        
        OptimizationValidation {
            operation: operation.to_string(),
            baseline_performance: 0.0,
            current_performance: 0.0,
            improvement_percent: 0.0,
            success: false,
            recommendations: vec!["无法获取基准数据".to_string()],
        }
    }
}

/// 瓶颈分析
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BottleneckAnalysis {
    pub operation: String,
    pub current_performance: f64,
    pub baseline_performance: f64,
    pub improvement_percent: f64,
    pub severity: BottleneckSeverity,
    pub recommendations: Vec<String>,
}

/// 瓶颈严重程度
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BottleneckSeverity {
    Low,
    Medium,
    High,
    Critical,
}

/// 优化验证结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OptimizationValidation {
    pub operation: String,
    pub baseline_performance: f64,
    pub current_performance: f64,
    pub improvement_percent: f64,
    pub success: bool,
    pub recommendations: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::performance::PerformanceMonitor;

    #[tokio::test]
    async fn test_stress_tester() {
        let monitor = Arc::new(PerformanceMonitor::new());
        let tester = StressTester::new(monitor.clone(), 100);
        
        let config = StressTestConfig {
            test_duration_seconds: 5, // 短时间测试
            target_tps: 100,
            max_concurrent_users: 10,
            ramp_up_seconds: 1,
            ramp_down_seconds: 1,
            error_threshold_percent: 5.0,
            response_time_threshold_ms: 1000,
        };
        
        let result = tester.run_load_test("test_stress", config, || {
            // Simulate some work
            std::thread::sleep(Duration::from_millis(10));
            Ok::<(), anyhow::Error>(())
        }).await;
        
        assert!(result.total_requests > 0);
        assert!(result.successful_requests > 0);
    }

    #[tokio::test]
    async fn test_performance_tuner() {
        let monitor = Arc::new(PerformanceMonitor::new());
        let mut tuner = PerformanceTuner::new(monitor.clone());
        
        // 设置基准
        tuner.set_baseline().await;
        
        // 分析瓶颈
        let bottlenecks = tuner.analyze_bottlenecks().await;
        // 新系统没有基准数据，所以瓶颈列表应该为空
        assert!(bottlenecks.is_empty());
    }
}
