//! 第五阶段集成测试
//!
//! 测试投票生命周期管理、SDK功能、安全机制和存储策略的集成功能

use std::sync::Arc;
use serde_json::json;

use luckee_voting_server::core::voting_lifecycle::{
    VotingFlowEngine, VotingStatus, VotingPhaseConfig, CreateVotingFlowRequest
};
use luckee_voting_server::core::voting_sdk::{
    VotingSubmitter, VotingVerifier, ResultQueryInterface, CommitmentGenerator, NFTProof
};
use luckee_voting_server::core::security::{
    SecurityProtectionSystem, SecurityConfig, InputValidator, InputValidationConfig, ReplayProtector,
    AccessController, EncryptionManager, RateLimiter, BlacklistManager
};
use luckee_voting_server::core::storage_strategy::{
    LayeredStorageSystem, StorageStrategyConfig, StorageTier
};
use luckee_voting_server::core::participants::ParticipantService;
use luckee_voting_server::core::audit::AuditLogger;
use luckee_voting_server::core::cache::CacheManager;
use luckee_voting_server::core::session::SessionManager;

/// 测试投票生命周期管理
#[tokio::test]
async fn test_voting_lifecycle_management() {
    // 初始化组件
    let session_manager = Arc::new(SessionManager::new());
    let participant_service = Arc::new(ParticipantService::new());
    let audit_logger = Arc::new(AuditLogger::new());
    let cache_manager = Arc::new(CacheManager::new());
    
    let flow_engine = VotingFlowEngine::new(
        Arc::clone(&session_manager),
        Arc::clone(&participant_service),
        Arc::clone(&audit_logger),
        Arc::clone(&cache_manager),
    );

    // 创建投票流程
    let create_request = CreateVotingFlowRequest {
        session_id: "test_session_001".to_string(),
        title: "测试投票".to_string(),
        description: "这是一个测试投票".to_string(),
        phase_config: VotingPhaseConfig {
            commit_start_time: chrono::Utc::now().timestamp() as u64,
            commit_end_time: chrono::Utc::now().timestamp() as u64 + 3600,
            reveal_start_time: chrono::Utc::now().timestamp() as u64 + 3600,
            reveal_end_time: chrono::Utc::now().timestamp() as u64 + 7200,
            buffer_time: 300,
            min_participants: 2,
            max_participants: Some(100),
        },
        participants: vec!["user1".to_string(), "user2".to_string()],
        creator: "admin".to_string(),
        nft_type: "lottery".to_string(),
        metadata: json!({}),
    };

    // 测试创建投票流程
    let session = flow_engine.create_voting_flow(create_request).await.unwrap();
    assert_eq!(session.session_id, "test_session_001");
    assert_eq!(session.status, VotingStatus::Created);
    assert_eq!(session.participants.len(), 2);

    // 测试启动承诺阶段
    let updated_session = flow_engine.start_voting_phase(
        &session.session_id,
        VotingStatus::CommitmentPhase
    ).await.unwrap();
    assert_eq!(updated_session.status, VotingStatus::CommitmentPhase);

    // 测试提交承诺
    flow_engine.submit_commitment(
        &session.session_id,
        "user1",
        "commitment_hash_1"
    ).await.unwrap();

    // 测试启动揭示阶段
    let updated_session = flow_engine.start_voting_phase(
        &session.session_id,
        VotingStatus::RevealPhase
    ).await.unwrap();
    assert_eq!(updated_session.status, VotingStatus::RevealPhase);

    // 测试提交揭示
    flow_engine.submit_reveal(
        &session.session_id,
        "user1",
        "reveal_data_1"
    ).await.unwrap();

    // 测试计算结果 - 由于只有1个揭示，应该只有1个有效票
    let results = flow_engine.calculate_results(&session.session_id).await.unwrap();
    assert_eq!(results.total_votes, 2);
    assert_eq!(results.valid_votes, 1);
    assert_eq!(results.invalid_votes, 1);

    // 测试查询会话
    let retrieved_session = flow_engine.get_session(&session.session_id).await.unwrap();
    assert_eq!(retrieved_session.session_id, session.session_id);
}

/// 测试投票SDK功能
#[tokio::test]
async fn test_voting_sdk_functionality() {
    // 初始化组件
    let session_manager = Arc::new(SessionManager::new());
    let participant_service = Arc::new(ParticipantService::new());
    let audit_logger = Arc::new(AuditLogger::new());
    let cache_manager = Arc::new(CacheManager::new());
    
    let flow_engine = Arc::new(VotingFlowEngine::new(
        Arc::clone(&session_manager),
        Arc::clone(&participant_service),
        Arc::clone(&audit_logger),
        Arc::clone(&cache_manager),
    ));

    // 创建SDK组件
    let voting_submitter = VotingSubmitter::new(
        Arc::clone(&flow_engine),
        Arc::clone(&participant_service),
        Arc::clone(&audit_logger),
        luckee_voting_server::core::voting_sdk::VotingSdkConfig {
            api_endpoint: "http://localhost:8080".to_string(),
            timeout_seconds: 30,
            retry_count: 3,
            retry_delay_ms: 1000,
            enable_cache: true,
            cache_ttl_seconds: 300,
        },
    );

    let voting_verifier = VotingVerifier::new(
        Arc::clone(&flow_engine),
        Arc::clone(&audit_logger),
    );

    let result_query = ResultQueryInterface::new(
        Arc::clone(&flow_engine),
        Arc::clone(&audit_logger),
    );

    let commitment_generator = CommitmentGenerator::new();

    // 测试比特承诺生成
    let (commitment_hash, randomness) = commitment_generator.generate_commitment(b"test_message");
    assert!(!commitment_hash.is_empty());
    assert_eq!(randomness.len(), 32);

    // 测试比特承诺验证
    let is_valid = commitment_generator.verify_commitment(
        b"test_message",
        &randomness,
        &commitment_hash
    );
    assert!(is_valid);

    // 测试NFT证明
    let nft_proof = NFTProof {
        user_id: "user1".to_string(),
        nft_id: "nft_001".to_string(),
        nft_type: "lottery".to_string(),
        signature: "signature_1".to_string(),
    };

    // 测试提交承诺（需要先创建投票会话）
    // 这里简化测试，实际应该先创建会话
    let commitment_result = voting_submitter.submit_commitment(
        "test_session_002",
        "user1",
        1,
        nft_proof.clone(),
    ).await;
    // 由于会话不存在，应该返回错误
    assert!(commitment_result.is_err());

    // 测试会话完整性验证
    let integrity_result = voting_verifier.verify_session_integrity("test_session_002").await;
    assert!(integrity_result.is_err()); // 会话不存在

    // 测试结果查询
    let session_info = result_query.get_session_info("test_session_002").await.unwrap();
    assert!(session_info.is_none()); // 会话不存在
}

/// 测试安全机制
#[tokio::test]
async fn test_security_mechanisms() {
    // 初始化安全组件
    let audit_logger = Arc::new(AuditLogger::new());
    let input_config = InputValidationConfig {
        max_input_size: 1024 * 1024, // 1MB limit
        allowed_patterns: vec!["valid".to_string()],
        blocked_patterns: vec!["<script".to_string(), "javascript:".to_string()],
    };
    let input_validator = Arc::new(InputValidator::new(input_config));
    let replay_protector = Arc::new(ReplayProtector::new(300)); // 5分钟TTL
    let access_controller = Arc::new(AccessController::new());
    let encryption_manager = Arc::new(EncryptionManager::new(vec![1; 32], "AES-256-GCM".to_string())); // 32字节密钥
    let rate_limiter = Arc::new(RateLimiter::new(100, 60)); // 每分钟100次请求
    let blacklist_manager = Arc::new(BlacklistManager::new());

    let security_config = SecurityConfig {
        input_validation_enabled: true,
        replay_protection_enabled: true,
        access_control_enabled: true,
        encryption_enabled: true,
        rate_limiting_enabled: true,
        max_requests_per_minute: 100,
        session_timeout_seconds: 3600,
        max_failed_attempts: 5,
        blacklist_duration_minutes: 30,
    };

    let _security_system = SecurityProtectionSystem::new(
        security_config,
        Arc::clone(&audit_logger),
        Arc::clone(&input_validator),
        Arc::clone(&replay_protector),
        Arc::clone(&access_controller),
        Arc::clone(&encryption_manager),
        Arc::clone(&rate_limiter),
        Arc::clone(&blacklist_manager),
    );

    // 测试输入验证
    let valid_input = b"normal_input";
    let validation_result = input_validator.validate_input(valid_input).await.unwrap();
    assert!(validation_result);

    // 测试恶意输入检测
    let malicious_input = b"<script>alert('xss')</script>";
    let validation_result = input_validator.validate_input(malicious_input).await;
    assert!(validation_result.is_err());

    // 测试重放防护
    let nonce = "unique_nonce_1234567890123456";
    let nonce_result = replay_protector.check_nonce(nonce).await.unwrap();
    assert!(nonce_result);

    // 测试重复nonce
    let nonce_result = replay_protector.check_nonce(nonce).await;
    assert!(nonce_result.is_err());

    // 测试访问控制
    access_controller.add_user_permission("user1", "/api/v1/voting").await;
    let access_result = access_controller.check_access("user1", "/api/v1/voting").await.unwrap();
    assert!(access_result);

    // 测试无权限访问
    let access_result = access_controller.check_access("user2", "/api/v1/admin").await;
    assert!(access_result.is_err());

    // 测试速率限制
    let rate_limit_result = rate_limiter.check_rate_limit("client1").await.unwrap();
    assert!(rate_limit_result);

    // 测试黑名单
    blacklist_manager.add_to_blacklist("bad_client", 5).await; // 5分钟
    let is_blacklisted = blacklist_manager.is_blacklisted("bad_client").await;
    assert!(is_blacklisted);

    // 测试加密
    let plaintext = b"sensitive_data";
    let encrypted = encryption_manager.encrypt_data(plaintext).await.unwrap();
    assert_ne!(&encrypted, plaintext);

    let decrypted = encryption_manager.decrypt_data(&encrypted).await.unwrap();
    assert_eq!(&decrypted, plaintext);
}

/// 测试存储策略
#[tokio::test]
async fn test_storage_strategy() {
    // 初始化存储组件
    let cache_manager = Arc::new(CacheManager::new());
    let storage_config = StorageStrategyConfig {
        enable_memory_cache: true,
        memory_cache_ttl: 300,
        enable_redis_cache: false,
        redis_cache_ttl: 600,
        enable_ipfs_storage: true,
        ipfs_gateway_url: "http://localhost:5001".to_string(),
        enable_blockchain_storage: true,
        blockchain_rpc_url: "http://localhost:8545".to_string(),
        compression_enabled: true,
        encryption_enabled: true,
        redundancy_factor: 3,
    };

    let storage_system = LayeredStorageSystem::new(storage_config, Arc::clone(&cache_manager));

    // 测试内存缓存存储
    let test_data = b"test_data_for_memory_cache";
    let metadata = storage_system.store_data(
        "test_key_1",
        test_data,
        "test",
        StorageTier::Memory,
    ).await.unwrap();

    assert_eq!(metadata.data_id, "test_key_1");
    assert_eq!(metadata.tier, StorageTier::Memory);
    assert_eq!(metadata.size_bytes, test_data.len() as u64);

    // 测试内存缓存检索
    let retrieved_data = storage_system.retrieve_data("test_key_1").await.unwrap();
    assert_eq!(retrieved_data, test_data);

    // 测试IPFS存储
    let ipfs_data = b"test_data_for_ipfs";
    let ipfs_metadata = storage_system.store_data(
        "test_key_2",
        ipfs_data,
        "test",
        StorageTier::IPFS,
    ).await.unwrap();

    assert_eq!(ipfs_metadata.tier, StorageTier::IPFS);
    assert!(ipfs_metadata.cid.is_some());

    // 测试区块链存储
    let blockchain_data = b"test_data_for_blockchain";
    let blockchain_metadata = storage_system.store_data(
        "test_key_3",
        blockchain_data,
        "test",
        StorageTier::Blockchain,
    ).await.unwrap();

    assert_eq!(blockchain_metadata.tier, StorageTier::Blockchain);
    assert!(blockchain_metadata.blockchain_tx_hash.is_some());

    // 测试数据删除
    storage_system.delete_data("test_key_1").await.unwrap();
    let retrieve_result = storage_system.retrieve_data("test_key_1").await;
    assert!(retrieve_result.is_err());

    // 测试备份和恢复
    let backup_metadata = storage_system.backup_data("test_key_2", StorageTier::Memory).await.unwrap();
    assert!(backup_metadata.data_id.starts_with("backup_"));

    storage_system.restore_data("backup_test_key_2", "restored_key").await.unwrap();
    let restored_data = storage_system.retrieve_data("restored_key").await.unwrap();
    assert_eq!(restored_data, ipfs_data);

    // 测试清理过期数据
    let cleaned_count = storage_system.cleanup_expired_data().await.unwrap();
    // cleaned_count is usize, so it's always >= 0
    println!("清理了 {} 个过期数据项", cleaned_count);

    // 测试存储统计
    let stats = storage_system.get_storage_stats().await.unwrap();
    assert!(stats.total_entries > 0);
    assert!(stats.total_size_bytes > 0);
}

/// 测试端到端投票流程
#[tokio::test]
async fn test_end_to_end_voting_flow() {
    // 初始化所有组件
    let session_manager = Arc::new(SessionManager::new());
    let participant_service = Arc::new(ParticipantService::new());
    let audit_logger = Arc::new(AuditLogger::new());
    let cache_manager = Arc::new(CacheManager::new());

    let flow_engine = Arc::new(VotingFlowEngine::new(
        Arc::clone(&session_manager),
        Arc::clone(&participant_service),
        Arc::clone(&audit_logger),
        Arc::clone(&cache_manager),
    ));

    let voting_submitter = VotingSubmitter::new(
        Arc::clone(&flow_engine),
        Arc::clone(&participant_service),
        Arc::clone(&audit_logger),
        luckee_voting_server::core::voting_sdk::VotingSdkConfig {
            api_endpoint: "http://localhost:8080".to_string(),
            timeout_seconds: 30,
            retry_count: 3,
            retry_delay_ms: 1000,
            enable_cache: true,
            cache_ttl_seconds: 300,
        },
    );

    let voting_verifier = VotingVerifier::new(
        Arc::clone(&flow_engine),
        Arc::clone(&audit_logger),
    );

    let result_query = ResultQueryInterface::new(
        Arc::clone(&flow_engine),
        Arc::clone(&audit_logger),
    );

    // 1. 创建投票流程
    let create_request = CreateVotingFlowRequest {
        session_id: "e2e_test_session".to_string(),
        title: "端到端测试投票".to_string(),
        description: "这是一个端到端测试投票".to_string(),
        phase_config: VotingPhaseConfig {
            commit_start_time: chrono::Utc::now().timestamp() as u64,
            commit_end_time: chrono::Utc::now().timestamp() as u64 + 3600,
            reveal_start_time: chrono::Utc::now().timestamp() as u64 + 3600,
            reveal_end_time: chrono::Utc::now().timestamp() as u64 + 7200,
            buffer_time: 300,
            min_participants: 1,
            max_participants: Some(10),
        },
        participants: vec!["user1".to_string()],
        creator: "admin".to_string(),
        nft_type: "lottery".to_string(),
        metadata: json!({}),
    };

    let session = flow_engine.create_voting_flow(create_request).await.unwrap();
    assert_eq!(session.session_id, "e2e_test_session");

    // 2. 启动承诺阶段
    flow_engine.start_voting_phase(&session.session_id, VotingStatus::CommitmentPhase).await.unwrap();

    // 3. 提交投票承诺
    let nft_proof = NFTProof {
        user_id: "user1".to_string(),
        nft_id: "nft_001".to_string(),
        nft_type: "lottery".to_string(),
        signature: "signature_1".to_string(),
    };

    let commitment_hash = voting_submitter.submit_commitment(
        &session.session_id,
        "user1",
        1,
        nft_proof.clone(),
    ).await.unwrap();
    assert!(!commitment_hash.is_empty());

    // 4. 启动揭示阶段
    flow_engine.start_voting_phase(&session.session_id, VotingStatus::RevealPhase).await.unwrap();

    // 5. 提交投票揭示
    let reveal_data = voting_submitter.submit_reveal(
        &session.session_id,
        "user1",
        1,
        "randomness_123",
        nft_proof,
    ).await.unwrap();
    assert!(!reveal_data.is_empty());

    // 6. 计算投票结果
    let results = flow_engine.calculate_results(&session.session_id).await.unwrap();
    assert_eq!(results.total_votes, 1);
    assert_eq!(results.valid_votes, 1);
    assert_eq!(results.invalid_votes, 0);

    // 7. 验证会话完整性
    let integrity_report = voting_verifier.verify_session_integrity(&session.session_id).await.unwrap();
    assert!(integrity_report.is_valid);

    // 8. 验证投票结果
    let results_report = voting_verifier.verify_voting_results(&session.session_id).await.unwrap();
    assert!(results_report.is_valid);

    // 9. 查询最终结果
    let final_results = result_query.get_voting_results(&session.session_id).await.unwrap();
    assert!(final_results.is_some());
    let final_results = final_results.unwrap();
    assert_eq!(final_results.total_votes, 1);
    assert_eq!(final_results.valid_votes, 1);

    println!("端到端投票流程测试完成！");
    println!("会话ID: {}", session.session_id);
    println!("总票数: {}", final_results.total_votes);
    println!("有效票数: {}", final_results.valid_votes);
    println!("中奖者数量: {}", final_results.winner_count);
}
