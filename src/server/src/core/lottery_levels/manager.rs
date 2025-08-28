use std::collections::HashMap;

use super::participant::ParticipantInfo;
use super::types::{LevelStatus, LotteryLevel};
use super::validator::LevelValidator;

/// 等级管理器
pub struct LevelManager {
    pub(crate) levels: HashMap<String, LotteryLevel>,
    pub(crate) validator: LevelValidator,
}

impl LevelManager {
    /// 创建新的等级管理器
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> {
        Ok(Self { levels: HashMap::new(), validator: LevelValidator::new()? })
    }

    /// 添加或更新等级
    pub fn upsert_level(&mut self, level: LotteryLevel) -> Result<(), Vec<String>> {
        self.validator.validate(&level)?;

        // 检查ID冲突（除了更新自己的情况）
        if let Some(existing) = self.levels.get(&level.id) {
            if existing.updated_at != level.updated_at {
                return Err(vec!["等级ID已存在，请使用不同的ID".to_string()]);
            }
        }

        // 检查优先级冲突
        for (existing_id, existing_level) in &self.levels {
            if existing_id != &level.id && existing_level.priority == level.priority {
                return Err(vec![format!("优先级{}已被等级{}使用", level.priority, existing_id)]);
            }
        }

        self.levels.insert(level.id.clone(), level);
        Ok(())
    }

    /// 获取等级
    pub fn get_level(&self, id: &str) -> Option<&LotteryLevel> { self.levels.get(id) }

    /// 获取所有等级
    pub fn get_all_levels(&self) -> Vec<&LotteryLevel> { self.levels.values().collect() }

    /// 获取激活的等级
    pub fn get_active_levels(&self) -> Vec<&LotteryLevel> {
        self.levels.values().filter(|level| level.status == LevelStatus::Active).collect()
    }

    /// 按优先级排序获取等级
    #[allow(dead_code)]
    pub fn get_levels_by_priority(&self) -> Vec<&LotteryLevel> {
        let mut levels: Vec<&LotteryLevel> = self.levels.values().collect();
        levels.sort_by(|a, b| a.priority.cmp(&b.priority));
        levels
    }

    /// 删除等级
    pub fn delete_level(&mut self, id: &str) -> bool { self.levels.remove(id).is_some() }

    /// 更新等级状态
    pub fn update_level_status(&mut self, id: &str, status: LevelStatus) -> Result<(), String> {
        if let Some(level) = self.levels.get_mut(id) {
            level.status = status;
            level.updated_at = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(())
        } else {
            Err("等级不存在".to_string())
        }
    }

    /// 验证参与者是否符合等级要求
    #[allow(dead_code)]
    pub fn validate_participant_eligibility(
        &self,
        level_id: &str,
        participant: &ParticipantInfo,
    ) -> Result<(), Vec<String>> {
        let level = self.get_level(level_id).ok_or_else(|| vec!["等级不存在".to_string()])?;

        if level.status != LevelStatus::Active {
            return Err(vec!["等级未激活".to_string()]);
        }

        let mut errors = Vec::new();

        // 检查余额要求
        if participant.balance < level.permissions.min_balance {
            errors.push(format!(
                "余额不足: 需要{}, 当前{}",
                level.permissions.min_balance, participant.balance
            ));
        }

        // 检查质押要求
        if participant.staked_amount < level.permissions.min_stake {
            errors.push(format!(
                "质押不足: 需要{}, 当前{}",
                level.permissions.min_stake, participant.staked_amount
            ));
        }

        // 检查持有时间
        let current_time = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if current_time - participant.first_stake_time < level.permissions.min_holding_time {
            errors.push("持有时间不足".to_string());
        }

        // 检查NFT要求
        for required_type in &level.permissions.required_nft_types {
            if !participant.nft_types.contains(required_type) {
                errors.push(format!("缺少必需的NFT类型: {}", required_type));
            }
        }

        // 检查黑名单
        if level.permissions.blacklisted_addresses.contains(&participant.address) {
            errors.push("地址在黑名单中".to_string());
        }

        // 检查白名单
        if !level.permissions.whitelisted_addresses.is_empty() {
            if !level.permissions.whitelisted_addresses.contains(&participant.address) {
                errors.push("地址不在白名单中".to_string());
            }
        }

        if errors.is_empty() { Ok(()) } else { Err(errors) }
    }
}


