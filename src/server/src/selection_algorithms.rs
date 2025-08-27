//! 中奖者选择算法模块
//! 
//! 实现多目标选择算法、公平选择机制和防冲突算法

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use rand::{Rng, SeedableRng};
use rand::rngs::StdRng;
use sha2::{Sha256, Digest};
use crate::lottery_config::{SelectionAlgorithm, LevelParameters};

/// 参与者信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Participant {
    /// 参与者ID
    pub id: String,
    /// 参与者地址
    pub address: String,
    /// 参与者权重（用于加权选择）
    pub weight: f64,
    /// 参与者等级
    pub level: String,
    /// 参与者属性（用于自定义算法）
    pub attributes: HashMap<String, f64>,
    /// 是否已中奖
    pub is_winner: bool,
}

/// 选择结果
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionResult {
    /// 中奖者列表
    pub winners: Vec<Participant>,
    /// 选择算法类型
    pub algorithm: SelectionAlgorithm,
    /// 随机种子
    pub seed: String,
    /// 选择证明
    pub proof: String,
    /// 选择时间戳
    pub timestamp: u64,
    /// 选择统计信息
    pub stats: SelectionStats,
}

/// 选择统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectionStats {
    /// 总参与者数量
    pub total_participants: usize,
    /// 中奖者数量
    pub winner_count: usize,
    /// 选择耗时（毫秒）
    pub selection_time_ms: u64,
    /// 冲突解决次数
    pub conflict_resolutions: usize,
    /// 算法特定统计
    pub algorithm_stats: HashMap<String, f64>,
}

/// 选择器接口
#[allow(dead_code)]
pub trait Selector: Send + Sync {
    /// 执行选择
    fn select(&self, participants: &[Participant], params: &LevelParameters, seed: &str) -> Result<SelectionResult, String>;
    
    /// 验证选择结果
    fn verify(&self, result: &SelectionResult, participants: &[Participant], params: &LevelParameters) -> Result<bool, String>;
}

/// 随机选择器
#[allow(dead_code)]
pub struct RandomSelector;

impl Selector for RandomSelector {
    fn select(&self, participants: &[Participant], params: &LevelParameters, seed: &str) -> Result<SelectionResult, String> {
        let start_time = std::time::Instant::now();
        
        // 生成随机数生成器
        let mut rng = self.create_rng(seed);
        
        // 过滤有效参与者
        let valid_participants: Vec<Participant> = participants
            .iter()
            .filter(|p| !p.is_winner)
            .cloned()
            .collect();
        
        if valid_participants.len() < params.winner_count as usize {
            return Err("参与者数量不足".to_string());
        }
        
        // 随机选择
        let mut winners = Vec::new();
        let mut selected_indices = HashSet::new();
        
        while winners.len() < params.winner_count as usize {
            let index = rng.gen_range(0..valid_participants.len());
            if selected_indices.insert(index) {
                let mut winner = valid_participants[index].clone();
                winner.is_winner = true;
                winners.push(winner);
            }
        }
        
        let selection_time = start_time.elapsed();
        
        Ok(SelectionResult {
            winners,
            algorithm: SelectionAlgorithm::Random,
            seed: seed.to_string(),
            proof: self.generate_proof(seed, &valid_participants),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            stats: SelectionStats {
                total_participants: valid_participants.len(),
                winner_count: params.winner_count as usize,
                selection_time_ms: selection_time.as_millis() as u64,
                conflict_resolutions: 0,
                algorithm_stats: HashMap::new(),
            },
        })
    }
    
    fn verify(&self, result: &SelectionResult, participants: &[Participant], _params: &LevelParameters) -> Result<bool, String> {
        // 验证种子
        let expected_proof = self.generate_proof(&result.seed, participants);
        if result.proof != expected_proof {
            return Ok(false);
        }
        
        // 验证中奖者数量
        if result.winners.len() != result.stats.winner_count {
            return Ok(false);
        }
        
        // 验证中奖者唯一性
        let mut winner_ids = HashSet::new();
        for winner in &result.winners {
            if !winner_ids.insert(&winner.id) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

impl RandomSelector {
    fn create_rng(&self, seed: &str) -> StdRng {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        let seed_array: [u8; 32] = hash.into();
        StdRng::from_seed(seed_array)
    }
    
    fn generate_proof(&self, seed: &str, participants: &[Participant]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        for participant in participants {
            hasher.update(participant.id.as_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

/// 加权随机选择器
#[allow(dead_code)]
pub struct WeightedRandomSelector;

impl Selector for WeightedRandomSelector {
    fn select(&self, participants: &[Participant], params: &LevelParameters, seed: &str) -> Result<SelectionResult, String> {
        let start_time = std::time::Instant::now();
        
        // 生成随机数生成器
        let mut rng = self.create_rng(seed);
        
        // 过滤有效参与者
        let valid_participants: Vec<Participant> = participants
            .iter()
            .filter(|p| !p.is_winner)
            .cloned()
            .collect();
        
        if valid_participants.len() < params.winner_count as usize {
            return Err("参与者数量不足".to_string());
        }
        
        // 计算总权重
        let total_weight: f64 = valid_participants.iter().map(|p| p.weight).sum();
        if total_weight <= 0.0 {
            return Err("总权重必须大于0".to_string());
        }
        
        // 加权随机选择
        let mut winners = Vec::new();
        let mut selected_indices = HashSet::new();
        
        while winners.len() < params.winner_count as usize {
            let random_value = rng.gen_range(0.0..total_weight);
            let mut cumulative_weight = 0.0;
            
            for (index, participant) in valid_participants.iter().enumerate() {
                if selected_indices.contains(&index) {
                    continue;
                }
                
                cumulative_weight += participant.weight;
                if random_value <= cumulative_weight {
                    selected_indices.insert(index);
                    let mut winner = participant.clone();
                    winner.is_winner = true;
                    winners.push(winner);
                    break;
                }
            }
        }
        
        let selection_time = start_time.elapsed();
        
        Ok(SelectionResult {
            winners,
            algorithm: SelectionAlgorithm::WeightedRandom,
            seed: seed.to_string(),
            proof: self.generate_proof(seed, &valid_participants),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            stats: SelectionStats {
                total_participants: valid_participants.len(),
                winner_count: params.winner_count as usize,
                selection_time_ms: selection_time.as_millis() as u64,
                conflict_resolutions: 0,
                algorithm_stats: {
                    let mut stats = HashMap::new();
                    stats.insert("total_weight".to_string(), total_weight);
                    stats
                },
            },
        })
    }
    
    fn verify(&self, result: &SelectionResult, participants: &[Participant], _params: &LevelParameters) -> Result<bool, String> {
        // 验证种子
        let expected_proof = self.generate_proof(&result.seed, participants);
        if result.proof != expected_proof {
            return Ok(false);
        }
        
        // 验证中奖者数量
        if result.winners.len() != result.stats.winner_count {
            return Ok(false);
        }
        
        // 验证中奖者唯一性
        let mut winner_ids = HashSet::new();
        for winner in &result.winners {
            if !winner_ids.insert(&winner.id) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

impl WeightedRandomSelector {
    fn create_rng(&self, seed: &str) -> StdRng {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        let seed_array: [u8; 32] = hash.into();
        StdRng::from_seed(seed_array)
    }
    
    fn generate_proof(&self, seed: &str, participants: &[Participant]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        for participant in participants {
            hasher.update(participant.id.as_bytes());
            hasher.update(participant.weight.to_le_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

/// 锦标赛选择器
#[allow(dead_code)]
pub struct TournamentSelector;

impl Selector for TournamentSelector {
    fn select(&self, participants: &[Participant], params: &LevelParameters, seed: &str) -> Result<SelectionResult, String> {
        let start_time = std::time::Instant::now();
        
        // 生成随机数生成器
        let mut rng = self.create_rng(seed);
        
        // 过滤有效参与者
        let valid_participants: Vec<Participant> = participants
            .iter()
            .filter(|p| !p.is_winner)
            .cloned()
            .collect();
        
        if valid_participants.len() < params.winner_count as usize {
            return Err("参与者数量不足".to_string());
        }
        
        // 获取锦标赛大小
        let tournament_size = params.algorithm_params
            .get("tournament_size")
            .and_then(|v| v.as_u64())
            .unwrap_or(8) as usize;
        
        // 锦标赛选择
        let mut winners = Vec::new();
        let mut available_participants = valid_participants.clone();
        
        while winners.len() < params.winner_count as usize && !available_participants.is_empty() {
            // 随机选择锦标赛参与者
            let tournament_participants = if available_participants.len() <= tournament_size {
                available_participants.clone()
            } else {
                let mut selected = Vec::new();
                let mut indices: Vec<usize> = (0..available_participants.len()).collect();
                for _ in 0..tournament_size {
                    if indices.is_empty() {
                        break;
                    }
                    let random_index = rng.gen_range(0..indices.len());
                    let participant_index = indices.remove(random_index);
                    selected.push(available_participants[participant_index].clone());
                }
                selected
            };
            
            // 选择锦标赛获胜者（权重最高的）
            let winner = tournament_participants
                .iter()
                .max_by(|a, b| a.weight.partial_cmp(&b.weight).unwrap())
                .unwrap()
                .clone();
            
            // 从可用参与者中移除获胜者
            available_participants.retain(|p| p.id != winner.id);
            
            let mut winner_mut = winner;
            winner_mut.is_winner = true;
            winners.push(winner_mut);
        }
        
        let selection_time = start_time.elapsed();
        
        let winner_count = winners.len();
        Ok(SelectionResult {
            winners,
            algorithm: SelectionAlgorithm::Tournament,
            seed: seed.to_string(),
            proof: self.generate_proof(seed, &valid_participants),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            stats: SelectionStats {
                total_participants: valid_participants.len(),
                winner_count,
                selection_time_ms: selection_time.as_millis() as u64,
                conflict_resolutions: 0,
                algorithm_stats: {
                    let mut stats = HashMap::new();
                    stats.insert("tournament_size".to_string(), tournament_size as f64);
                    stats
                },
            },
        })
    }
    
    fn verify(&self, result: &SelectionResult, participants: &[Participant], _params: &LevelParameters) -> Result<bool, String> {
        // 验证种子
        let expected_proof = self.generate_proof(&result.seed, participants);
        if result.proof != expected_proof {
            return Ok(false);
        }
        
        // 验证中奖者唯一性
        let mut winner_ids = HashSet::new();
        for winner in &result.winners {
            if !winner_ids.insert(&winner.id) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

impl TournamentSelector {
    fn create_rng(&self, seed: &str) -> StdRng {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        let hash = hasher.finalize();
        let seed_array: [u8; 32] = hash.into();
        StdRng::from_seed(seed_array)
    }
    
    fn generate_proof(&self, seed: &str, participants: &[Participant]) -> String {
        let mut hasher = Sha256::new();
        hasher.update(seed.as_bytes());
        for participant in participants {
            hasher.update(participant.id.as_bytes());
            hasher.update(participant.weight.to_le_bytes());
        }
        format!("{:x}", hasher.finalize())
    }
}

/// 选择器工厂
#[allow(dead_code)]
pub struct SelectorFactory;

impl SelectorFactory {
    /// 创建选择器
    #[allow(dead_code)]
    pub fn create(algorithm: &SelectionAlgorithm) -> Box<dyn Selector> {
        match algorithm {
            SelectionAlgorithm::Random => Box::new(RandomSelector),
            SelectionAlgorithm::WeightedRandom => Box::new(WeightedRandomSelector),
            SelectionAlgorithm::Tournament => Box::new(TournamentSelector),
            SelectionAlgorithm::RouletteWheel => Box::new(WeightedRandomSelector), // 简化实现
            SelectionAlgorithm::Custom(_) => Box::new(RandomSelector), // 默认使用随机选择
        }
    }
}

/// 多目标选择器
#[allow(dead_code)]
pub struct MultiTargetSelector {
    selectors: HashMap<String, Box<dyn Selector>>,
}

impl MultiTargetSelector {
    /// 创建多目标选择器
    pub fn new() -> Self {
        Self {
            selectors: HashMap::new(),
        }
    }
    
    /// 添加选择器
    #[allow(dead_code)]
    pub fn add_selector(&mut self, level: String, selector: Box<dyn Selector>) {
        self.selectors.insert(level, selector);
    }
    
    /// 执行多目标选择
    #[allow(dead_code)]
    pub fn select_multi_target(
        &self,
        participants: &[Participant],
        level_params: &HashMap<String, LevelParameters>,
        seed: &str,
    ) -> Result<HashMap<String, SelectionResult>, String> {
        let mut results = HashMap::new();
        let mut remaining_participants = participants.to_vec();
        
        // 按优先级排序等级
        let mut sorted_levels: Vec<(&String, &LevelParameters)> = level_params.iter().collect();
        sorted_levels.sort_by(|a, b| a.1.min_participants.cmp(&b.1.min_participants));
        
        for (level, params) in sorted_levels {
            let selector = self.selectors.get(level)
                .ok_or_else(|| format!("未找到等级{}的选择器", level))?;
            
            // 过滤该等级的参与者
            let level_participants: Vec<Participant> = remaining_participants
                .iter()
                .filter(|p| p.level == *level && !p.is_winner)
                .cloned()
                .collect();
            
            if level_participants.len() < params.min_participants as usize {
                continue; // 跳过参与者不足的等级
            }
            
            // 执行选择
            let result = selector.select(&level_participants, params, seed)?;
            
            // 更新参与者状态
            for winner in &result.winners {
                if let Some(participant) = remaining_participants.iter_mut().find(|p| p.id == winner.id) {
                    participant.is_winner = true;
                }
            }
            
            results.insert(level.clone(), result);
        }
        
        Ok(results)
    }
    
    /// 验证多目标选择结果
    #[allow(dead_code)]
    pub fn verify_multi_target(
        &self,
        results: &HashMap<String, SelectionResult>,
        participants: &[Participant],
        level_params: &HashMap<String, LevelParameters>,
    ) -> Result<bool, String> {
        for (level, result) in results {
            let params = level_params.get(level)
                .ok_or_else(|| format!("未找到等级{}的参数", level))?;
            
            let selector = self.selectors.get(level)
                .ok_or_else(|| format!("未找到等级{}的选择器", level))?;
            
            if !selector.verify(result, participants, params)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lottery_config::SelectionAlgorithm;

    #[test]
    fn test_random_selector() {
        let selector = RandomSelector;
        let participants = vec![
            Participant {
                id: "1".to_string(),
                address: "addr1".to_string(),
                weight: 1.0,
                level: "bronze".to_string(),
                attributes: HashMap::new(),
                is_winner: false,
            },
            Participant {
                id: "2".to_string(),
                address: "addr2".to_string(),
                weight: 1.0,
                level: "bronze".to_string(),
                attributes: HashMap::new(),
                is_winner: false,
            },
        ];
        
        let params = LevelParameters {
            min_participants: 2,
            max_participants: None,
            winner_count: 1,
            selection_algorithm: SelectionAlgorithm::Random,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        };
        
        let result = selector.select(&participants, &params, "test_seed");
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.winners.len(), 1);
        assert_eq!(result.algorithm, SelectionAlgorithm::Random);
    }

    #[test]
    fn test_weighted_random_selector() {
        let selector = WeightedRandomSelector;
        let participants = vec![
            Participant {
                id: "1".to_string(),
                address: "addr1".to_string(),
                weight: 2.0,
                level: "bronze".to_string(),
                attributes: HashMap::new(),
                is_winner: false,
            },
            Participant {
                id: "2".to_string(),
                address: "addr2".to_string(),
                weight: 1.0,
                level: "bronze".to_string(),
                attributes: HashMap::new(),
                is_winner: false,
            },
        ];
        
        let params = LevelParameters {
            min_participants: 2,
            max_participants: None,
            winner_count: 1,
            selection_algorithm: SelectionAlgorithm::WeightedRandom,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        };
        
        let result = selector.select(&participants, &params, "test_seed");
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.winners.len(), 1);
        assert_eq!(result.algorithm, SelectionAlgorithm::WeightedRandom);
    }

    #[test]
    fn test_tournament_selector() {
        let selector = TournamentSelector;
        let participants = vec![
            Participant {
                id: "1".to_string(),
                address: "addr1".to_string(),
                weight: 1.0,
                level: "bronze".to_string(),
                attributes: HashMap::new(),
                is_winner: false,
            },
            Participant {
                id: "2".to_string(),
                address: "addr2".to_string(),
                weight: 2.0,
                level: "bronze".to_string(),
                attributes: HashMap::new(),
                is_winner: false,
            },
        ];
        
        let mut algorithm_params = HashMap::new();
        algorithm_params.insert("tournament_size".to_string(), serde_json::json!(2));
        
        let params = LevelParameters {
            min_participants: 2,
            max_participants: None,
            winner_count: 1,
            selection_algorithm: SelectionAlgorithm::Tournament,
            algorithm_params,
            time_limit: None,
            cost_limit: None,
        };
        
        let result = selector.select(&participants, &params, "test_seed");
        assert!(result.is_ok());
        
        let result = result.unwrap();
        assert_eq!(result.winners.len(), 1);
        assert_eq!(result.algorithm, SelectionAlgorithm::Tournament);
    }

    #[test]
    fn test_selector_factory() {
        let random_selector = SelectorFactory::create(&SelectionAlgorithm::Random);
        let weighted_selector = SelectorFactory::create(&SelectionAlgorithm::WeightedRandom);
        let tournament_selector = SelectorFactory::create(&SelectionAlgorithm::Tournament);
        
        // Test that selectors can be created without errors
        assert!(random_selector.select(&vec![], &LevelParameters {
            min_participants: 0,
            max_participants: None,
            winner_count: 0,
            selection_algorithm: SelectionAlgorithm::Random,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        }, "test").is_err()); // Should fail due to insufficient participants, but not due to creation
        
        assert!(weighted_selector.select(&vec![], &LevelParameters {
            min_participants: 0,
            max_participants: None,
            winner_count: 0,
            selection_algorithm: SelectionAlgorithm::WeightedRandom,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        }, "test").is_err()); // Should fail due to insufficient participants, but not due to creation
        
        assert!(tournament_selector.select(&vec![], &LevelParameters {
            min_participants: 0,
            max_participants: None,
            winner_count: 0,
            selection_algorithm: SelectionAlgorithm::Tournament,
            algorithm_params: HashMap::new(),
            time_limit: None,
            cost_limit: None,
        }, "test").is_err()); // Should fail due to insufficient participants, but not due to creation
    }
}
