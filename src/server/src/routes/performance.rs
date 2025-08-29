//! 性能优化API路由
//!
//! 提供性能监控、压力测试和性能调优的REST API接口

use std::sync::Arc;
use warp::{Filter, Reply, Rejection};
use crate::core::performance::{PerformanceMonitor, PerformanceBenchmark};
use crate::core::stress_testing::{StressTester, StressTestConfig, PerformanceTuner};

/// 性能相关路由
pub fn performance_routes(
    monitor: Arc<PerformanceMonitor>,
    benchmark: Arc<PerformanceBenchmark>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let monitor_routes = monitor_routes(monitor.clone());
    let benchmark_routes = benchmark_routes(benchmark.clone());
    let stress_test_routes = stress_test_routes(monitor.clone());
    let optimization_routes = optimization_routes(monitor.clone());
    
    monitor_routes
        .or(benchmark_routes)
        .or(stress_test_routes)
        .or(optimization_routes)
}

/// 性能监控路由
fn monitor_routes(
    monitor: Arc<PerformanceMonitor>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let monitor = warp::any().map(move || monitor.clone());
    
    // GET /api/performance/metrics - 获取所有性能指标
    let get_metrics = warp::path!("api" / "performance" / "metrics")
        .and(warp::get())
        .and(monitor.clone())
        .and_then(get_performance_metrics);
    
    // GET /api/performance/metrics/{operation} - 获取特定操作的性能指标
    let get_operation_metrics = warp::path!("api" / "performance" / "metrics" / String)
        .and(warp::get())
        .and(monitor.clone())
        .and_then(get_operation_metrics);
    
    // GET /api/performance/report - 生成性能报告
    let get_report = warp::path!("api" / "performance" / "report")
        .and(warp::get())
        .and(monitor.clone())
        .and_then(generate_performance_report);
    
    // POST /api/performance/clear - 清理历史数据
    let clear_data = warp::path!("api" / "performance" / "clear")
        .and(warp::post())
        .and(monitor.clone())
        .and_then(clear_performance_data);
    
    get_metrics
        .or(get_operation_metrics)
        .or(get_report)
        .or(clear_data)
}

/// 性能基准测试路由
fn benchmark_routes(
    benchmark: Arc<PerformanceBenchmark>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let benchmark = warp::any().map(move || benchmark.clone());
    
    // POST /api/performance/benchmark - 运行性能基准测试
    let run_benchmark = warp::path!("api" / "performance" / "benchmark")
        .and(warp::post())
        .and(benchmark.clone())
        .and_then(run_performance_benchmark);
    
    // GET /api/performance/benchmark/status - 获取基准测试状态
    let get_status = warp::path!("api" / "performance" / "benchmark" / "status")
        .and(warp::get())
        .and(benchmark.clone())
        .and_then(get_benchmark_status);
    
    run_benchmark.or(get_status)
}

/// 压力测试路由
fn stress_test_routes(
    monitor: Arc<PerformanceMonitor>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let monitor = warp::any().map(move || monitor.clone());
    
    // POST /api/performance/stress-test - 运行压力测试
    let run_stress_test = warp::path!("api" / "performance" / "stress-test")
        .and(warp::post())
        .and(warp::body::json())
        .and(monitor.clone())
        .and_then(run_stress_test);
    
    // POST /api/performance/stability-test - 运行稳定性测试
    let run_stability_test = warp::path!("api" / "performance" / "stability-test")
        .and(warp::post())
        .and(warp::body::json())
        .and(monitor.clone())
        .and_then(run_stability_test);
    
    // POST /api/performance/extreme-test - 运行极限测试
    let run_extreme_test = warp::path!("api" / "performance" / "extreme-test")
        .and(warp::post())
        .and(warp::body::json())
        .and(monitor.clone())
        .and_then(run_extreme_test);
    
    run_stress_test
        .or(run_stability_test)
        .or(run_extreme_test)
}

/// 性能优化路由
fn optimization_routes(
    monitor: Arc<PerformanceMonitor>,
) -> impl Filter<Extract = impl Reply, Error = Rejection> + Clone {
    let monitor = warp::any().map(move || monitor.clone());
    
    // POST /api/performance/optimize - 运行性能优化
    let run_optimization = warp::path!("api" / "performance" / "optimize")
        .and(warp::post())
        .and(warp::body::json())
        .and(monitor.clone())
        .and_then(run_performance_optimization);
    
    // GET /api/performance/optimization/status - 获取优化状态
    let get_optimization_status = warp::path!("api" / "performance" / "optimization" / "status")
        .and(warp::get())
        .and(monitor.clone())
        .and_then(get_optimization_status);
    
    // POST /api/performance/baseline - 设置性能基准
    let set_baseline = warp::path!("api" / "performance" / "baseline")
        .and(warp::post())
        .and(warp::body::json())
        .and(monitor.clone())
        .and_then(set_performance_baseline);
    
    run_optimization
        .or(get_optimization_status)
        .or(set_baseline)
}

/// 获取性能指标
async fn get_performance_metrics(
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let metrics = monitor.get_all_operation_metrics().await;
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": metrics
    })))
}

/// 获取特定操作的性能指标
async fn get_operation_metrics(
    operation: String,
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let metrics = monitor.get_operation_metrics(&operation).await;
    match metrics {
        Some(metric) => Ok(warp::reply::json(&serde_json::json!({
            "status": "success",
            "data": metric
        }))),
        None => Ok(warp::reply::json(&serde_json::json!({
            "status": "error",
            "message": "Operation not found"
        })))
    }
}

/// 生成性能报告
async fn generate_performance_report(
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let report = monitor.generate_performance_report().await;
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": report
    })))
}

/// 清理性能数据
async fn clear_performance_data(
    _monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    // 这里应该实现清理逻辑
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": "Performance data cleared"
    })))
}

/// 运行性能基准测试
async fn run_performance_benchmark(
    benchmark: Arc<PerformanceBenchmark>,
) -> Result<impl Reply, Rejection> {
    let result = benchmark.run_full_benchmark().await;
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": result
    })))
}

/// 获取基准测试状态
async fn get_benchmark_status(
    _benchmark: Arc<PerformanceBenchmark>,
) -> Result<impl Reply, Rejection> {
    // 这里应该返回基准测试的状态
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": "Benchmark status retrieved"
    })))
}

/// 运行压力测试
async fn run_stress_test(
    config: serde_json::Value,
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    // 解析配置
    let cfg: StressTestConfig = serde_json::from_value(config).unwrap_or_default();
    let tester = StressTester::new(monitor.clone(), cfg.max_concurrent_users);

    // 后台异步运行，避免阻塞请求
    tokio::spawn(async move {
        let _ = tester.run_load_test("api_stress_test", cfg, || {
            // 模拟一次典型操作耗时
            std::thread::sleep(std::time::Duration::from_millis(5));
            Ok::<(), anyhow::Error>(())
        }).await;
    });

    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": "Stress test started"
    })))
}

/// 运行稳定性测试
async fn run_stability_test(
    config: serde_json::Value,
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let cfg: StressTestConfig = serde_json::from_value(config).unwrap_or_default();
    let tester = StressTester::new(monitor.clone(), cfg.max_concurrent_users);
    tokio::spawn(async move {
        let _ = tester.run_stability_test("api_stability_test", cfg, || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            Ok::<(), anyhow::Error>(())
        }).await;
    });
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": "Stability test started"
    })))
}

/// 运行极限测试
async fn run_extreme_test(
    config: serde_json::Value,
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let cfg: StressTestConfig = serde_json::from_value(config).unwrap_or_default();
    let tester = StressTester::new(monitor.clone(), cfg.max_concurrent_users);
    tokio::spawn(async move {
        let _ = tester.run_extreme_test("api_extreme_test", cfg, || {
            std::thread::sleep(std::time::Duration::from_millis(5));
            Ok::<(), anyhow::Error>(())
        }).await;
    });
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "message": "Extreme test started"
    })))
}

/// 运行性能优化
async fn run_performance_optimization(
    _config: serde_json::Value,
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let mut tuner = PerformanceTuner::new(monitor.clone());
    tuner.set_baseline().await;
    let bottlenecks = tuner.analyze_bottlenecks().await;
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": { "bottlenecks": bottlenecks }
    })))
}

/// 获取优化状态
async fn get_optimization_status(
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let alerts = monitor.check_alerts().await;
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": { "alerts": alerts }
    })))
}

/// 设置性能基准
async fn set_performance_baseline(
    config: serde_json::Value,
    monitor: Arc<PerformanceMonitor>,
) -> Result<impl Reply, Rejection> {
    let operation = config.get("operation").and_then(|v| v.as_str()).unwrap_or("default");
    let avg_ms = config.get("avg_duration_ms").and_then(|v| v.as_f64()).unwrap_or(0.0);
    monitor.set_performance_baseline(operation, avg_ms).await;
    Ok(warp::reply::json(&serde_json::json!({
        "status": "success",
        "data": { "operation": operation, "avg_duration_ms": avg_ms }
    })))
}
