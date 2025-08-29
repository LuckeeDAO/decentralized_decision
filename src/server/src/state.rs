use std::sync::Arc;
use std::collections::HashMap;
use tokio::sync::RwLock;

use luckee_voting_wasm::voting::VotingSystem;
use luckee_voting_ipfs::IpfsManager;
use redis::aio::ConnectionManager as RedisConnManager;

use crate::core::nft_types::{NftTypeRegistry, NftTypePluginRegistry};
use crate::core::lottery_levels::LevelManager;
use crate::core::lottery_config::ConfigManager;
use crate::core::selection_algorithms::MultiTargetSelector;
use crate::core::serial_numbers::{SerialService, SerialPoolConfig};

// 第五阶段组件
use crate::core::voting_lifecycle::VotingFlowEngine;
use crate::core::voting_sdk::{VotingSubmitter, VotingVerifier, ResultQueryInterface, CommitmentGenerator};
use crate::core::security::SecurityProtectionSystem;
use crate::core::storage_strategy::LayeredStorageSystem;
use crate::core::participants::ParticipantService;
use crate::core::audit::AuditLogger;
use crate::core::cache::CacheManager;

// 第六阶段新增组件 - 性能优化
use crate::core::performance::{PerformanceMonitor, PerformanceBenchmark};
use crate::core::concurrency::{SmartThreadPool, ThreadPoolConfig, ConcurrencyController};
use crate::core::stress_testing::StressTester;

use crate::routes::sync::{AuditEvent, StakeRecord, QualStatus};
use crate::types::StakeEvent;

/// 服务器状态（提取至 state.rs）
#[derive(Clone)]
pub struct ServerState {
    pub(crate) voting_system: Arc<RwLock<VotingSystem>>,
    pub(crate) balances: Arc<RwLock<HashMap<String, u128>>>,
    // key: delegatee, value: list of delegator addresses
    pub(crate) delegations_to: Arc<RwLock<HashMap<String, Vec<String>>>>,
    // key: child, value: parent
    pub(crate) inheritance_parent: Arc<RwLock<HashMap<String, String>>>,
    // audit logs for permission actions
    pub(crate) audit_logs: Arc<RwLock<Vec<AuditEvent>>>,
    pub(crate) ipfs: Arc<RwLock<IpfsManager>>, 
    // NFT元数据版本注册表: token_id -> Vec<(cid, timestamp)>
    pub(crate) metadata_versions: Arc<RwLock<HashMap<String, Vec<(String, u64)>>>>,
    // 简化版NFT所有权注册表: token_id -> owner
    pub(crate) nft_owners: Arc<RwLock<HashMap<String, String>>>,
    // NFT 类型注册表
    pub(crate) nft_types: Arc<RwLock<NftTypeRegistry>>,
    // NFT 类型插件注册表
    pub(crate) nft_type_plugins: Arc<RwLock<NftTypePluginRegistry>>,
    // NFT 类型状态机: type_id -> state
    pub(crate) nft_type_states: Arc<RwLock<HashMap<String, String>>>,
    // NFT 全局状态：token_id -> state
    pub(crate) nft_global_states: Arc<RwLock<HashMap<String, String>>>,
    // NFT 全局状态历史：token_id -> Vec<(state, timestamp)>
    pub(crate) nft_global_state_history: Arc<RwLock<HashMap<String, Vec<(String, u64)>>>>,
    // 抽奖配置版本：config_id -> Vec<(version, cid, timestamp)>
    pub(crate) lottery_configs: Arc<RwLock<HashMap<String, Vec<(u32, String, u64)>>>>,
    // 质押与锁定：address -> StakeRecord
    pub(crate) staking: Arc<RwLock<HashMap<String, StakeRecord>>>,
    // 质押事件列表
    pub(crate) stake_events: Arc<RwLock<Vec<StakeEvent>>>,
    // 条件锁校验标志：address -> satisfied
    pub(crate) staking_conditions: Arc<RwLock<HashMap<String, bool>>>,
    // 资格状态：token_id -> QualStatus
    pub(crate) qualifications: Arc<RwLock<HashMap<String, QualStatus>>>,
    // 元数据缓存（可替换为Redis），cid -> (json, cached_at)
    pub(crate) metadata_cache: Arc<RwLock<HashMap<String, (serde_json::Value, u64)>>>,
    // 可选：Redis缓存连接
    #[allow(dead_code)]
    pub(crate) redis: Option<Arc<RwLock<RedisConnManager>>>,
    // 简单运行时状态指标
    pub(crate) state_metrics: Arc<RwLock<HashMap<String, u64>>>,
    // 抽奖等级管理器
    pub(crate) level_manager: Arc<RwLock<LevelManager>>,
    // 抽奖配置管理器
    #[allow(dead_code)]
    pub(crate) config_manager: Arc<RwLock<ConfigManager>>,
    // 多目标选择器
    #[allow(dead_code)]
    pub(crate) multi_target_selector: Arc<RwLock<MultiTargetSelector>>,
    // 序号服务
    pub(crate) serials: Arc<RwLock<SerialService>>,
    
    // 第五阶段组件
    pub(crate) voting_flow_engine: Option<Arc<VotingFlowEngine>>,
    pub(crate) voting_submitter: Option<Arc<VotingSubmitter>>,
    pub(crate) voting_verifier: Option<Arc<VotingVerifier>>,
    pub(crate) result_query: Option<Arc<ResultQueryInterface>>,
    pub(crate) commitment_generator: Option<Arc<CommitmentGenerator>>,
    #[allow(dead_code)]
    pub(crate) security_system: Option<Arc<SecurityProtectionSystem>>,
    #[allow(dead_code)]
    pub(crate) storage_system: Option<Arc<LayeredStorageSystem>>,
    #[allow(dead_code)]
    pub(crate) participant_service: Option<Arc<ParticipantService>>,
    #[allow(dead_code)]
    pub(crate) audit_logger: Option<Arc<AuditLogger>>,
    #[allow(dead_code)]
    pub(crate) cache_manager: Option<Arc<CacheManager>>,
    
    // 第六阶段新增组件 - 性能优化
    #[allow(dead_code)]
    pub(crate) performance_monitor: Arc<PerformanceMonitor>,
    #[allow(dead_code)]
    pub(crate) performance_benchmark: Arc<PerformanceBenchmark>,
    #[allow(dead_code)]
    pub(crate) thread_pool: Arc<SmartThreadPool>,
    #[allow(dead_code)]
    pub(crate) concurrency_controller: Arc<ConcurrencyController>,
    #[allow(dead_code)]
    pub(crate) stress_tester: Arc<StressTester>,
}

impl ServerState {
    /// 创建新的服务器状态实例
    pub async fn new() -> Result<Self, String> {
        // 可选初始化Redis
        let redis = if let Ok(url) = std::env::var("REDIS_URL") {
            match redis::Client::open(url) {
                Ok(client) => match client.get_connection_manager().await {
                    Ok(manager) => Some(Arc::new(RwLock::new(manager))),
                    Err(e) => {
                        tracing::error!("初始化 Redis 失败: {}", e);
                        None
                    }
                },
                Err(e) => {
                    tracing::error!("创建 Redis 客户端失败: {}", e);
                    None
                }
            }
        } else { 
            None 
        };

        // 初始化IPFS管理器
        let ipfs_url = std::env::var("IPFS_API").unwrap_or_else(|_| "http://127.0.0.1:5001".to_string());
        let ipfs = IpfsManager::new(&ipfs_url).await
            .map_err(|e| format!("初始化 IPFS 失败: {}", e))?;

        // 初始化序号服务
        // NFT 为事实源：关闭本地序号池预生成与低水位补齐
        let serials = SerialService::new(SerialPoolConfig { 
            pre_generate: 0, 
            serial_hex_len: 24,
            low_watermark: 0,
        }).await;

        // 初始化等级管理器
        let level_manager = LevelManager::new()
            .map_err(|e| format!("初始化等级管理器失败: {}", e))?;

        // 初始化配置管理器
        let config_manager = ConfigManager::new()
            .map_err(|e| format!("初始化配置管理器失败: {}", e))?;

        // 第六阶段新增组件初始化 - 性能优化
        let performance_monitor = Arc::new(PerformanceMonitor::new());
        let participant_service = Arc::new(ParticipantService::new());
        let session_manager = Arc::new(crate::core::session::SessionManager::new());
        let performance_benchmark = Arc::new(PerformanceBenchmark::new(
            session_manager,
            participant_service,
        ));
        
        // 初始化智能线程池
        let thread_pool_config = ThreadPoolConfig::default();
        let thread_pool = Arc::new(SmartThreadPool::new(thread_pool_config));
        
        // 初始化并发控制器
        let max_concurrent = std::env::var("MAX_CONCURRENT_OPERATIONS")
            .unwrap_or_else(|_| "1000".to_string())
            .parse::<usize>()
            .unwrap_or(1000);
        let concurrency_controller = Arc::new(ConcurrencyController::new(max_concurrent));
        
        // 初始化压力测试器
        let stress_tester = Arc::new(StressTester::new(
            performance_monitor.clone(),
            max_concurrent,
        ));

        Ok(ServerState {
            voting_system: Arc::new(RwLock::new(VotingSystem::new())),
            balances: Arc::new(RwLock::new(HashMap::new())),
            delegations_to: Arc::new(RwLock::new(HashMap::new())),
            inheritance_parent: Arc::new(RwLock::new(HashMap::new())),
            audit_logs: Arc::new(RwLock::new(Vec::new())),
            ipfs: Arc::new(RwLock::new(ipfs)),
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
            redis,
            state_metrics: Arc::new(RwLock::new(HashMap::new())),
            level_manager: Arc::new(RwLock::new(level_manager)),
            config_manager: Arc::new(RwLock::new(config_manager)),
            multi_target_selector: Arc::new(RwLock::new(MultiTargetSelector::new())),
            serials: Arc::new(RwLock::new(serials)),
            
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
            performance_monitor,
            performance_benchmark,
            thread_pool,
            concurrency_controller,
            stress_tester,
        })
    }
}


