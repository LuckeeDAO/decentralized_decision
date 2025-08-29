use crate::state::ServerState;
use crate::types::{ApiResponse, now_secs};
use crate::core::performance::{PerformanceBenchmark, PerformanceResult};
use crate::core::quality::{QualityValidator, QualityTestResult};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// 基准测试请求
#[derive(Debug, Deserialize)]
pub struct BenchmarkRequest {
    pub participant_count: Option<usize>,
    pub run_full_suite: Option<bool>,
}

/// 基准测试响应
#[derive(Debug, Serialize)]
pub struct BenchmarkResponse {
    pub test_type: String,
    pub timestamp: u64,
    pub results: serde_json::Value,
    pub summary: serde_json::Value,
}

/// 统一的基准测试结果
#[derive(Debug, Serialize)]
#[serde(untagged)]
pub enum UnifiedBenchmarkResult {
    Performance(PerformanceResult),
    Quality(QualityTestResult),
}

/// 运行性能基准测试
pub async fn run_performance_benchmark(
    state: Arc<ServerState>,
    request: BenchmarkRequest,
) -> Result<impl Reply, Rejection> {
    let participant_count = request.participant_count.unwrap_or(1000);
    
    // 创建性能基准测试器
    let session_manager = Arc::new(crate::core::session::SessionManager::new());
    let participant_service = Arc::new(crate::core::participants::ParticipantService::new());
    let _multi_target_selector = state.multi_target_selector.clone();
    let _config_manager = state.config_manager.clone();
    
    let benchmark = PerformanceBenchmark::new(
        session_manager,
        participant_service,
    );
    
    let results = if request.run_full_suite.unwrap_or(false) {
        benchmark.run_full_benchmark().await
    } else {
        // 运行单个规模的测试
        let mut results = Vec::new();
        results.push(benchmark.benchmark_session_creation(participant_count).await);
        results.push(benchmark.benchmark_participant_registration(participant_count).await);
        results.push(benchmark.benchmark_commitment_processing(participant_count).await);
        results.push(benchmark.benchmark_reveal_processing(participant_count).await);
        results.push(benchmark.benchmark_winner_calculation(participant_count).await);
        results
    };
    
    // 验证性能标准
    let validation_report = benchmark.validate_performance_standards(&results);
    
    let response = BenchmarkResponse {
        test_type: "performance".to_string(),
        timestamp: now_secs(),
        results: serde_json::to_value(results).unwrap_or_default(),
        summary: serde_json::to_value(validation_report).unwrap_or_default(),
    };
    
    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// 运行质量验收测试
pub async fn run_quality_benchmark(
    _state: Arc<ServerState>,
    _request: BenchmarkRequest,
) -> Result<impl Reply, Rejection> {
    // 创建质量验证器
    let session_manager = Arc::new(crate::core::session::SessionManager::new());
    let validator = QualityValidator::new(
        session_manager,
    );
    
    // 运行完整的质量测试套件
    let results = validator.run_full_quality_suite().await;
    
    // 生成质量报告
    let quality_report = validator.generate_quality_report(&results);
    
    let response = BenchmarkResponse {
        test_type: "quality".to_string(),
        timestamp: now_secs(),
        results: serde_json::to_value(results).unwrap_or_default(),
        summary: serde_json::to_value(quality_report).unwrap_or_default(),
    };
    
    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// 运行综合基准测试
pub async fn run_comprehensive_benchmark(
    state: Arc<ServerState>,
    request: BenchmarkRequest,
) -> Result<impl Reply, Rejection> {
    let mut all_results: Vec<UnifiedBenchmarkResult> = Vec::new();
    
    // 运行性能测试
    let performance_results: Vec<PerformanceResult> = {
        let session_manager = Arc::new(crate::core::session::SessionManager::new());
        let participant_service = Arc::new(crate::core::participants::ParticipantService::new());
        let _multi_target_selector = state.multi_target_selector.clone();
        let _config_manager = state.config_manager.clone();
        
        let benchmark = PerformanceBenchmark::new(
            session_manager,
            participant_service,
        );
        
        if request.run_full_suite.unwrap_or(false) {
            benchmark.run_full_benchmark().await
        } else {
            let participant_count = request.participant_count.unwrap_or(1000);
            let mut results = Vec::new();
            results.push(benchmark.benchmark_session_creation(participant_count).await);
            results.push(benchmark.benchmark_participant_registration(participant_count).await);
            results.push(benchmark.benchmark_commitment_processing(participant_count).await);
            results.push(benchmark.benchmark_reveal_processing(participant_count).await);
            results.push(benchmark.benchmark_winner_calculation(participant_count).await);
            results
        }
    };
    
    // 运行质量测试
    let quality_results: Vec<QualityTestResult> = {
        let session_manager = Arc::new(crate::core::session::SessionManager::new());
        let validator = QualityValidator::new(
            session_manager,
        );
        
        validator.run_full_quality_suite().await
    };
    
    // 保存长度用于报告
    let performance_count = performance_results.len();
    let quality_count = quality_results.len();
    
    // 合并结果到统一类型
    for result in &performance_results {
        all_results.push(UnifiedBenchmarkResult::Performance(result.clone()));
    }
    
    for result in &quality_results {
        all_results.push(UnifiedBenchmarkResult::Quality(result.clone()));
    }
    
    // 生成综合报告
    let comprehensive_summary = serde_json::json!({
        "performance_tests": performance_count,
        "quality_tests": quality_count,
        "total_tests": all_results.len(),
        "timestamp": now_secs(),
        "test_type": "comprehensive"
    });
    
    let response = BenchmarkResponse {
        test_type: "comprehensive".to_string(),
        timestamp: now_secs(),
        results: serde_json::to_value(all_results).unwrap_or_default(),
        summary: comprehensive_summary,
    };
    
    Ok(warp::reply::json(&ApiResponse::success(response)))
}

/// 获取基准测试状态
pub async fn get_benchmark_status(
    _state: Arc<ServerState>,
) -> Result<impl Reply, Rejection> {
    let status = serde_json::json!({
        "status": "ready",
        "available_tests": [
            "performance",
            "quality", 
            "comprehensive"
        ],
        "last_run": null,
        "next_scheduled": null
    });
    
    Ok(warp::reply::json(&ApiResponse::success(status)))
}

/// 创建基准测试路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let performance_route = {
        let state = Arc::clone(&state);
        warp::path!("benchmark" / "performance")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|request: BenchmarkRequest, state: Arc<ServerState>| async move {
                run_performance_benchmark(state, request).await
            })
            .boxed()
    };

    let quality_route = {
        let state = Arc::clone(&state);
        warp::path!("benchmark" / "quality")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|request: BenchmarkRequest, state: Arc<ServerState>| async move {
                run_quality_benchmark(state, request).await
            })
            .boxed()
    };

    let comprehensive_route = {
        let state = Arc::clone(&state);
        warp::path!("benchmark" / "comprehensive")
            .and(warp::post())
            .and(warp::body::json())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|request: BenchmarkRequest, state: Arc<ServerState>| async move {
                run_comprehensive_benchmark(state, request).await
            })
            .boxed()
    };

    let status_route = {
        let state = Arc::clone(&state);
        warp::path!("benchmark" / "status")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|state: Arc<ServerState>| async move {
                get_benchmark_status(state).await
            })
            .boxed()
    };

    performance_route
        .or(quality_route)
        .or(comprehensive_route)
        .or(status_route)
        .boxed()
}
