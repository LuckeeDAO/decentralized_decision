use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

use luckee_voting_wasm::voting::VotingSystem;
use luckee_voting_ipfs::IpfsManager;

use crate::ServerState;
use crate::core::nft_types::{NftTypeRegistry, NftTypePluginRegistry};
use crate::core::lottery_levels::LevelManager;
use crate::core::lottery_config::ConfigManager;
use crate::core::selection_algorithms::MultiTargetSelector;
use crate::core::serial_numbers::{SerialService, SerialPoolConfig};
use crate::core::performance::{PerformanceMonitor, PerformanceBenchmark};
use crate::core::concurrency::{SmartThreadPool, ThreadPoolConfig, ConcurrencyController};
use crate::core::stress_testing::StressTester;
use crate::core::participants::ParticipantService;

/// 创建测试用的 ServerState
#[allow(dead_code)]
pub async fn create_test_state() -> Arc<ServerState> {
    Arc::new(ServerState {
        voting_system: Arc::new(RwLock::new(VotingSystem::new())),
        balances: Arc::new(RwLock::new(HashMap::new())),
        delegations_to: Arc::new(RwLock::new(HashMap::new())),
        inheritance_parent: Arc::new(RwLock::new(HashMap::new())),
        audit_logs: Arc::new(RwLock::new(Vec::new())),
        ipfs: Arc::new(RwLock::new(
            match IpfsManager::new("http://127.0.0.1:5001").await {
                Ok(ipfs) => ipfs,
                Err(_) => {
                    // 如果IPFS初始化失败，创建一个空的mock
                    IpfsManager::new("http://127.0.0.1:5001").await.unwrap()
                }
            }
        )),
        metadata_versions: Arc::new(RwLock::new(HashMap::new())),
        nft_owners: Arc::new(RwLock::new(HashMap::new())),
        nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())),
        nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())),
        nft_type_states: Arc::new(RwLock::new(HashMap::new())),
        nft_global_states: Arc::new(RwLock::new(HashMap::new())),
        nft_global_state_history: Arc::new(RwLock::new(HashMap::new())),
        lottery_configs: Arc::new(RwLock::new(HashMap::new())),
        staking: Arc::new(RwLock::new(HashMap::new())),
        stake_events: Arc::new(RwLock::new(Vec::new())),
        staking_conditions: Arc::new(RwLock::new(HashMap::new())),
        qualifications: Arc::new(RwLock::new(HashMap::new())),
        metadata_cache: Arc::new(RwLock::new(HashMap::new())),
        redis: None,
        state_metrics: Arc::new(RwLock::new(HashMap::new())),
        level_manager: Arc::new(RwLock::new(LevelManager::new().unwrap())),
        config_manager: Arc::new(RwLock::new(ConfigManager::new().unwrap())),
        multi_target_selector: Arc::new(RwLock::new(MultiTargetSelector::new())),
        serials: Arc::new(RwLock::new(
            SerialService::new(SerialPoolConfig { 
                pre_generate: 0, 
                serial_hex_len: 16,
                low_watermark: 0,
            }).await
        )),
        
        // 第五阶段组件
        voting_flow_engine: None,
        voting_submitter: None,
        voting_verifier: None,
        result_query: None,
        commitment_generator: None,
        security_system: None,
        storage_system: None,
        participant_service: None,
        audit_logger: None,
        cache_manager: None,
        
        // 第六阶段新增组件 - 性能优化
        performance_monitor: Arc::new(PerformanceMonitor::new()),
        performance_benchmark: {
            let participant_service = Arc::new(ParticipantService::new());
            let session_manager = Arc::new(crate::core::session::SessionManager::new());
            Arc::new(PerformanceBenchmark::new(session_manager, participant_service))
        },
        thread_pool: Arc::new(SmartThreadPool::new(ThreadPoolConfig::default())),
        concurrency_controller: Arc::new(ConcurrencyController::new(1000)),
        stress_tester: Arc::new(StressTester::new(
            Arc::new(PerformanceMonitor::new()),
            1000,
        )),
    })
}

/// 创建带有自定义配置的测试 ServerState
#[allow(dead_code)]
pub async fn create_test_state_with_config(
    pre_generate: usize,
    serial_hex_len: usize,
) -> Arc<ServerState> {
    Arc::new(ServerState {
        voting_system: Arc::new(RwLock::new(VotingSystem::new())),
        balances: Arc::new(RwLock::new(HashMap::new())),
        delegations_to: Arc::new(RwLock::new(HashMap::new())),
        inheritance_parent: Arc::new(RwLock::new(HashMap::new())),
        audit_logs: Arc::new(RwLock::new(Vec::new())),
        ipfs: Arc::new(RwLock::new(
            match IpfsManager::new("http://127.0.0.1:5001").await {
                Ok(ipfs) => ipfs,
                Err(_) => {
                    IpfsManager::new("http://127.0.0.1:5001").await.unwrap()
                }
            }
        )),
        metadata_versions: Arc::new(RwLock::new(HashMap::new())),
        nft_owners: Arc::new(RwLock::new(HashMap::new())),
        nft_types: Arc::new(RwLock::new(NftTypeRegistry::new())),
        nft_type_plugins: Arc::new(RwLock::new(NftTypePluginRegistry::new())),
        nft_type_states: Arc::new(RwLock::new(HashMap::new())),
        nft_global_states: Arc::new(RwLock::new(HashMap::new())),
        nft_global_state_history: Arc::new(RwLock::new(HashMap::new())),
        lottery_configs: Arc::new(RwLock::new(HashMap::new())),
        staking: Arc::new(RwLock::new(HashMap::new())),
        stake_events: Arc::new(RwLock::new(Vec::new())),
        staking_conditions: Arc::new(RwLock::new(HashMap::new())),
        qualifications: Arc::new(RwLock::new(HashMap::new())),
        metadata_cache: Arc::new(RwLock::new(HashMap::new())),
        redis: None,
        state_metrics: Arc::new(RwLock::new(HashMap::new())),
        level_manager: Arc::new(RwLock::new(LevelManager::new().unwrap())),
        config_manager: Arc::new(RwLock::new(ConfigManager::new().unwrap())),
        multi_target_selector: Arc::new(RwLock::new(MultiTargetSelector::new())),
        serials: Arc::new(RwLock::new(
            SerialService::new(SerialPoolConfig { 
                pre_generate, 
                serial_hex_len,
                low_watermark: 0,
            }).await
        )),
        
        // 第五阶段组件
        voting_flow_engine: None,
        voting_submitter: None,
        voting_verifier: None,
        result_query: None,
        commitment_generator: None,
        security_system: None,
        storage_system: None,
        participant_service: None,
        audit_logger: None,
        cache_manager: None,
        
        // 第六阶段新增组件 - 性能优化
        performance_monitor: Arc::new(PerformanceMonitor::new()),
        performance_benchmark: {
            let participant_service = Arc::new(ParticipantService::new());
            let session_manager = Arc::new(crate::core::session::SessionManager::new());
            Arc::new(PerformanceBenchmark::new(session_manager, participant_service))
        },
        thread_pool: Arc::new(SmartThreadPool::new(ThreadPoolConfig::default())),
        concurrency_controller: Arc::new(ConcurrencyController::new(1000)),
        stress_tester: Arc::new(StressTester::new(
            Arc::new(PerformanceMonitor::new()),
            1000,
        )),
    })
}
