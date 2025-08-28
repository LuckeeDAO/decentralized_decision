use std::collections::HashMap;
use std::time::Instant;

use luckee_voting_server::core::serial_numbers::{SerialService, SerialPoolConfig};
use luckee_voting_server::core::selection_algorithms::Participant;
use luckee_voting_server::core::lottery_config::{LevelParameters, SelectionAlgorithm};
use luckee_voting_server::core::lottery_levels::executor::{ExecutionInput, SelectionAlgorithmExecutor, InputParticipant};

#[tokio::test]
async fn perf_serial_allocate_under_2s_for_2000() {
    let svc = SerialService::new(SerialPoolConfig { pre_generate: 2000, serial_hex_len: 16, low_watermark: 0 }).await;
    let start = Instant::now();
    let mut recs = Vec::with_capacity(2000);
    for i in 0..2000 {
        let r = svc.allocate(Some("sess-p3".into()), Some(format!("u{}", i)), 16).await.unwrap();
        recs.push(r);
    }
    let elapsed = start.elapsed();
    assert!(elapsed.as_secs_f64() < 2.0, "alloc 2k took {:?}", elapsed);

    // recycle a few to ensure service stays responsive
    for r in recs.into_iter().take(10) {
        svc.recycle(&r.serial).await.unwrap();
    }
}

#[test]
fn supports_20k_participants_selection_random() {
    // Build 20k participants for one level
    let n = 20_000usize;
    let mut participants: Vec<Participant> = Vec::with_capacity(n);
    for i in 0..n {
        participants.push(Participant {
            id: (i + 1).to_string(),
            address: format!("addr{}", i + 1),
            weight: 1.0,
            level: "L1".to_string(),
            attributes: HashMap::new(),
            is_winner: false,
        });
    }

    let params = LevelParameters {
        min_participants: n as u32,
        max_participants: None,
        winner_count: 1000,
        selection_algorithm: SelectionAlgorithm::Random,
        algorithm_params: HashMap::new(),
        time_limit: None,
        cost_limit: None,
    };

    let mut level_params = HashMap::new();
    level_params.insert("L1".to_string(), params);

    let mut selector = luckee_voting_server::core::selection_algorithms::MultiTargetSelector::new();
    let sel = luckee_voting_server::core::selection_algorithms::SelectorFactory::create(&SelectionAlgorithm::Random);
    selector.add_selector("L1".into(), sel);

    let start = Instant::now();
    let res = selector.select_multi_target(&participants, &level_params, "seed20k").unwrap();
    let elapsed = start.elapsed();
    assert_eq!(res.get("L1").unwrap().winners.len(), 1000);
    // 不设过严时限，保证规模可跑通，给出宽松上限以避免环境抖动影响
    assert!(elapsed.as_secs_f64() < 6.0, "20k selection took {:?}", elapsed);
}

#[test]
fn verify_result_under_1s() {
    // Prepare small input for fast verify
    let level_params = HashMap::from([
        ("bronze".to_string(), LevelParameters {
            min_participants: 200,
            max_participants: None,
            winner_count: 50,
            selection_algorithm: SelectionAlgorithm::Random,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        })
    ]);

    let mut participants = Vec::with_capacity(200);
    for i in 0..200 {
        participants.push(InputParticipant { id: (i+1).to_string(), address: format!("a{}", i+1), weight: 1.0, level: "bronze".into(), attributes: HashMap::new() });
    }

    let exec = SelectionAlgorithmExecutor::new();
    let input = ExecutionInput { participants: participants.clone(), level_params: level_params.clone(), seed: "seed-x".into(), scoring: None };
    let out = exec.execute(input.clone()).unwrap();

    let start = Instant::now();
    let ok = exec.verify(&input, &out).unwrap();
    let elapsed = start.elapsed();
    assert!(ok);
    assert!(elapsed.as_secs_f64() < 1.0, "verify took {:?}", elapsed);
}

#[test]
fn level_config_load_and_validate_under_500ms() {
    // 模拟加载：构造100个等级的JSON并反序列化+校验
    use luckee_voting_server::core::lottery_levels::validator::LevelValidator;
    use luckee_voting_server::core::lottery_levels::{LotteryLevel, LevelPermissions, LevelStatus, LevelParameters as LevelParamsLv, SelectionAlgorithm as SelAlgLv};

    let mut levels = Vec::with_capacity(100);
    for i in 0..100 {
        levels.push(LotteryLevel {
            id: format!("L{}", i),
            name: format!("Level {}", i),
            description: String::new(),
            priority: i as u32 + 1,
            weight: 1.0,
            parameters: LevelParamsLv {
                min_participants: 10,
                max_participants: Some(10_000),
                winner_count: 5,
                selection_algorithm: SelAlgLv::Random,
                algorithm_params: HashMap::new(),
                time_limit: None,
                cost_limit: None,
            },
            permissions: LevelPermissions {
                min_balance: 0,
                min_stake: 0,
                min_holding_time: 0,
                required_nft_types: vec![],
                required_permission_level: None,
                blacklisted_addresses: vec![],
                whitelisted_addresses: vec![],
            },
            status: LevelStatus::Active,
            created_at: 0,
            updated_at: 0,
        });
    }

    let json = serde_json::to_string(&levels).unwrap();
    let start = Instant::now();
    let loaded: Vec<LotteryLevel> = serde_json::from_str(&json).unwrap();
    let validator = LevelValidator::new().unwrap();
    for l in &loaded { validator.validate(l).unwrap(); }
    let elapsed = start.elapsed();
    assert!(elapsed.as_millis() < 500, "load+validate 100 levels took {:?}", elapsed);
}


