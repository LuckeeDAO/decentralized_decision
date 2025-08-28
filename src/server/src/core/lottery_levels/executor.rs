use std::collections::HashMap;

use crate::core::selection_algorithms as algo;
use crate::core::scoring::{ScoringConfig, ScoringContext, ScorerFactory};

use crate::core::lottery_config::LevelParameters;

/// 算法执行输入
#[derive(Clone)]
#[allow(dead_code)]
pub struct ExecutionInput {
    pub participants: Vec<InputParticipant>,
    pub level_params: HashMap<String, LevelParameters>,
    pub seed: String,
    pub scoring: Option<ScoringConfig>,
}

/// 执行后的产出
#[allow(dead_code)]
pub struct ExecutionOutcome {
    pub results: HashMap<String, algo::SelectionResult>,
}

/// 输入参与者（与算法模块的Participant解耦）
#[derive(Clone)]
pub struct InputParticipant {
    pub id: String,
    pub address: String,
    pub weight: f64,
    pub level: String,
    pub attributes: HashMap<String, f64>,
}

impl From<&InputParticipant> for algo::Participant {
    fn from(p: &InputParticipant) -> Self {
        algo::Participant {
            id: p.id.clone(),
            address: p.address.clone(),
            weight: p.weight,
            level: p.level.clone(),
            attributes: p.attributes.clone(),
            is_winner: false,
        }
    }
}

/// 算法执行器：根据等级参数选择对应算法并执行/验证
#[allow(dead_code)]
pub struct SelectionAlgorithmExecutor;

#[allow(dead_code)]
impl SelectionAlgorithmExecutor {
    pub fn new() -> Self { Self }

    /// 执行多等级选择
    pub fn execute(&self, input: ExecutionInput) -> Result<ExecutionOutcome, String> {
        let mut multi = algo::MultiTargetSelector::new();

        // 为每个等级注册选择器
        for (level, params) in &input.level_params {
            let selector = algo::SelectorFactory::create(&params.selection_algorithm);
            multi.add_selector(level.clone(), selector);
        }

        // 如提供算分配置，则先根据算分结果调整参与者权重
        let algo_participants: Vec<algo::Participant> = if let Some(cfg) = &input.scoring {
            let scorer = ScorerFactory::build(cfg)?;
            input.participants.iter().map(|p| {
                let ctx = ScoringContext { attributes: p.attributes.clone() };
                let s = scorer.score(&ctx);
                let mut ap: algo::Participant = p.into();
                // 将normalized分映射为权重乘子（保底权重）
                ap.weight = (ap.weight * (0.5 + 0.5 * s.normalized)).max(0.0);
                ap
            }).collect()
        } else {
            input.participants.iter().map(algo::Participant::from).collect()
        };
        let results = multi.select_multi_target(&algo_participants, &input.level_params, &input.seed)?;
        Ok(ExecutionOutcome { results })
    }

    /// 验证选择结果
    pub fn verify(
        &self,
        input: &ExecutionInput,
        outcome: &ExecutionOutcome,
    ) -> Result<bool, String> {
        let mut multi = algo::MultiTargetSelector::new();
        for (level, params) in &input.level_params {
            let selector = algo::SelectorFactory::create(&params.selection_algorithm);
            multi.add_selector(level.clone(), selector);
        }
        let algo_participants: Vec<algo::Participant> = if let Some(cfg) = &input.scoring {
            let scorer = ScorerFactory::build(cfg)?;
            input.participants.iter().map(|p| {
                let ctx = ScoringContext { attributes: p.attributes.clone() };
                let s = scorer.score(&ctx);
                let mut ap: algo::Participant = p.into();
                ap.weight = (ap.weight * (0.5 + 0.5 * s.normalized)).max(0.0);
                ap
            }).collect()
        } else {
            input.participants.iter().map(algo::Participant::from).collect()
        };
        multi.verify_multi_target(&outcome.results, &algo_participants, &input.level_params)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::iter::FromIterator;
    use crate::core::lottery_config::SelectionAlgorithm;

    #[test]
    fn test_execute_and_verify() {
        let exec = SelectionAlgorithmExecutor::new();
        let level_params = HashMap::from_iter([
            (
                "bronze".to_string(),
                LevelParameters {
                    min_participants: 2,
                    max_participants: None,
                    winner_count: 1,
                    selection_algorithm: SelectionAlgorithm::Random,
                    algorithm_params: HashMap::new(),
                    time_limit: None,
                    cost_limit: None,
                },
            ),
        ]);

        let participants = vec![
            InputParticipant { id: "1".into(), address: "a1".into(), weight: 1.0, level: "bronze".into(), attributes: HashMap::new() },
            InputParticipant { id: "2".into(), address: "a2".into(), weight: 1.0, level: "bronze".into(), attributes: HashMap::new() },
        ];

        let input = ExecutionInput { participants, level_params, seed: "seed-x".into(), scoring: None };
        let out = exec.execute(input.clone()).unwrap();
        assert!(exec.verify(&input, &out).unwrap());
    }
}


