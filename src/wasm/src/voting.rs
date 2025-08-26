//! 投票系统核心功能
//! 
//! 实现投票会话管理、多目标选择、结果验证等功能

use crate::types::{
    VotingSession, VotingSessionState, VotingResults, VotingError,
    BitCommitment, CommitmentProof, UserPermissions, PermissionLevel
};
use crate::commitment::CommitmentProtocol;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use rand::Rng;

/// 投票系统核心
pub struct VotingSystem {
    sessions: HashMap<String, VotingSession>,
    user_permissions: HashMap<String, UserPermissions>,
}

impl VotingSystem {
    /// 创建新的投票系统
    pub fn new() -> Self {
        Self {
            sessions: HashMap::new(),
            user_permissions: HashMap::new(),
        }
    }
    
    /// 创建投票会话
    pub fn create_session(
        &mut self,
        session_id: &str,
        commit_deadline: u64,
        reveal_deadline: u64,
        participants: Vec<String>
    ) -> Result<VotingSession, VotingError> {
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VotingError::StorageError)?
            .as_secs();
        
        if commit_deadline <= current_time || reveal_deadline <= commit_deadline {
            return Err(VotingError::InvalidState);
        }
        
        let session = VotingSession {
            session_id: session_id.to_string(),
            state: VotingSessionState::Created,
            created_at: current_time,
            commit_deadline,
            reveal_deadline,
            participants,
            commitments: HashMap::new(),
            reveals: HashMap::new(),
            results: None,
        };
        
        self.sessions.insert(session_id.to_string(), session.clone());
        Ok(session)
    }
    
    /// 获取投票会话
    pub fn get_session(&self, session_id: &str) -> Option<&VotingSession> {
        self.sessions.get(session_id)
    }
    
    /// 提交承诺
    pub fn submit_commitment(
        &mut self,
        session_id: &str,
        user_id: &str,
        message: &[u8]
    ) -> Result<BitCommitment, VotingError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or(VotingError::SessionNotFound)?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VotingError::StorageError)?
            .as_secs();
        
        if current_time > session.commit_deadline {
            return Err(VotingError::SessionExpired);
        }
        
        if !session.participants.contains(&user_id.to_string()) {
            return Err(VotingError::InsufficientPermissions);
        }
        
        if session.commitments.contains_key(user_id) {
            return Err(VotingError::InvalidState);
        }
        
        let (commitment, _randomness) = CommitmentProtocol::create_commitment(message)?;
        
        // 存储承诺
        session.commitments.insert(user_id.to_string(), commitment.clone());
        
        if session.commitments.len() == session.participants.len() {
            session.state = VotingSessionState::CommitPhase;
        }
        
        Ok(commitment)
    }
    
    /// 揭示投票
    pub fn reveal_vote(
        &mut self,
        session_id: &str,
        user_id: &str,
        message: &[u8],
        randomness: &[u8; 32]
    ) -> Result<CommitmentProof, VotingError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or(VotingError::SessionNotFound)?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VotingError::StorageError)?
            .as_secs();
        
        if current_time <= session.commit_deadline || current_time > session.reveal_deadline {
            return Err(VotingError::InvalidState);
        }
        
        if !session.participants.contains(&user_id.to_string()) {
            return Err(VotingError::InsufficientPermissions);
        }
        
        if !session.commitments.contains_key(user_id) {
            return Err(VotingError::InvalidState);
        }
        
        if session.reveals.contains_key(user_id) {
            return Err(VotingError::InvalidState);
        }
        
        let commitment = session.commitments.get(user_id).unwrap();
        if !CommitmentProtocol::verify_commitment(commitment, message, randomness) {
            return Err(VotingError::InvalidCommitment);
        }
        
        let proof = CommitmentProtocol::create_proof(commitment, message, randomness)?;
        
        session.reveals.insert(user_id.to_string(), proof.clone());
        
        if session.reveals.len() == session.participants.len() {
            session.state = VotingSessionState::RevealPhase;
        }
        
        Ok(proof)
    }
    
    /// 计算投票结果
    pub fn calculate_results(&mut self, session_id: &str) -> Result<VotingResults, VotingError> {
        let session = self.sessions.get_mut(session_id)
            .ok_or(VotingError::SessionNotFound)?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| VotingError::StorageError)?
            .as_secs();
        
        if current_time <= session.reveal_deadline {
            return Err(VotingError::InvalidState);
        }
        
        session.state = VotingSessionState::Counting;
        
        let total_votes = session.participants.len() as u32;
        let valid_votes = session.reveals.len() as u32;
        let invalid_votes = total_votes - valid_votes;
        
        // 简单的投票结果计算（这里可以根据具体需求实现更复杂的算法）
        let reveals = session.reveals.clone();
        let winner_indices = Self::calculate_winners_static(&reveals)?;
        
        let results = VotingResults {
            total_votes,
            valid_votes,
            invalid_votes,
            winner_indices,
            proof: "voting_proof".to_string(), // 这里应该生成实际的证明
        };
        
        session.results = Some(results.clone());
        session.state = VotingSessionState::Completed;
        
        Ok(results)
    }
    
    /// 计算获胜者
    #[allow(dead_code)]
    fn calculate_winners(&self, reveals: &HashMap<String, CommitmentProof>) -> Result<Vec<u32>, VotingError> {
        Self::calculate_winners_static(reveals)
    }
    
    /// 静态计算获胜者方法
    #[allow(dead_code)]
    fn calculate_winners_static(reveals: &HashMap<String, CommitmentProof>) -> Result<Vec<u32>, VotingError> {
        // 这里实现具体的获胜者选择算法
        // 目前使用简单的随机选择
        let mut winners = Vec::new();
        let participant_count = reveals.len();
        
        if participant_count == 0 {
            return Ok(winners);
        }
        
        // 简单的随机选择（实际应用中应该使用更复杂的算法）
        let winner_count = std::cmp::min(3, participant_count); // 选择前3名
        for i in 0..winner_count {
            winners.push(i as u32);
        }
        
        Ok(winners)
    }
    
    /// 验证用户权限
    pub fn verify_user_permissions(&self, user_id: &str, required_level: PermissionLevel) -> bool {
        if let Some(permissions) = self.user_permissions.get(user_id) {
            match (permissions.permission_level.clone(), required_level) {
                (PermissionLevel::Admin, _) => true,
                (PermissionLevel::Creator, PermissionLevel::Creator | PermissionLevel::Basic) => true,
                (PermissionLevel::Basic, PermissionLevel::Basic) => true,
                _ => false,
            }
        } else {
            false
        }
    }
    
    /// 设置用户权限
    pub fn set_user_permissions(&mut self, user_id: &str, permissions: UserPermissions) {
        self.user_permissions.insert(user_id.to_string(), permissions);
    }
    
    /// 获取会话统计信息
    pub fn get_session_stats(&self, session_id: &str) -> Option<SessionStats> {
        let session = self.sessions.get(session_id)?;
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Some(SessionStats {
            session_id: session_id.to_string(),
            state: session.state.clone(),
            total_participants: session.participants.len() as u32,
            committed_participants: session.commitments.len() as u32,
            revealed_participants: session.reveals.len() as u32,
            time_until_commit_deadline: if current_time < session.commit_deadline {
                session.commit_deadline - current_time
            } else {
                0
            },
            time_until_reveal_deadline: if current_time < session.reveal_deadline {
                session.reveal_deadline - current_time
            } else {
                0
            },
        })
    }
    
    /// 生成下一个组合
    #[allow(dead_code)]
    fn next_combination(combination: &mut Vec<u32>, n: u32) -> bool {
        let k = combination.len();
        if k == 0 {
            return false;
        }
        
        let mut i = k - 1;
        while i > 0 && combination[i] == n - (k as u32) + (i as u32) {
            i -= 1;
        }
        
        if combination[i] >= n - (k as u32) + (i as u32) {
            return false;
        }
        
        combination[i] += 1;
        for j in (i + 1)..k {
            combination[j] = combination[j - 1] + 1;
        }
        
        true
    }
    
    /// 公平选择算法
    pub fn fair_selection(participants: &[String], winners_count: u32, seed: &[u8]) -> Result<Vec<String>, VotingError> {
        if winners_count > participants.len() as u32 {
            return Err(VotingError::InvalidState);
        }
        
        let mut rng = Self::seeded_rng(seed);
        let mut indices: Vec<usize> = (0..participants.len()).collect();
        
        // Fisher-Yates洗牌算法
        for i in (1..indices.len()).rev() {
            let j = rng.gen_range(0..=i);
            indices.swap(i, j);
        }
        
        let winners: Vec<String> = indices
            .into_iter()
            .take(winners_count as usize)
            .map(|i| participants[i].clone())
            .collect();
        
        Ok(winners)
    }
    
    /// 基于种子的随机数生成器
    fn seeded_rng(seed: &[u8]) -> impl rand::Rng {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut seed_bytes = [0u8; 32];
        let seed_len = std::cmp::min(seed.len(), 32);
        seed_bytes[..seed_len].copy_from_slice(&seed[..seed_len]);
        
        StdRng::from_seed(seed_bytes)
    }
}

/// 会话统计信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStats {
    pub session_id: String,
    pub state: VotingSessionState,
    pub total_participants: u32,
    pub committed_participants: u32,
    pub revealed_participants: u32,
    pub time_until_commit_deadline: u64,
    pub time_until_reveal_deadline: u64,
}

/// 多目标选择算法
pub struct MultiTargetSelector;

impl MultiTargetSelector {
    /// n选k选择算法
    pub fn n_choose_k(n: u32, k: u32) -> Result<Vec<Vec<u32>>, VotingError> {
        if k > n {
            return Err(VotingError::InvalidState);
        }
        
        let mut combinations = Vec::new();
        let mut current = (0..k).collect::<Vec<u32>>();
        
        combinations.push(current.clone());
        
        while Self::next_combination(&mut current, n) {
            combinations.push(current.clone());
        }
        
        Ok(combinations)
    }
    
    /// 生成下一个组合
    fn next_combination(combination: &mut Vec<u32>, n: u32) -> bool {
        let k = combination.len();
        if k == 0 {
            return false;
        }
        
        let mut i = k - 1;
        while i > 0 && combination[i] == n - (k as u32) + (i as u32) {
            i -= 1;
        }
        
        if combination[i] >= n - (k as u32) + (i as u32) {
            return false;
        }
        
        combination[i] += 1;
        for j in (i + 1)..k {
            combination[j] = combination[j - 1] + 1;
        }
        
        true
    }
    
    /// 公平选择算法
    pub fn fair_selection(participants: &[String], winners_count: u32, seed: &[u8]) -> Result<Vec<String>, VotingError> {
        if winners_count > participants.len() as u32 {
            return Err(VotingError::InvalidState);
        }
        
        let mut rng = Self::seeded_rng(seed);
        let mut indices: Vec<usize> = (0..participants.len()).collect();
        
        // Fisher-Yates洗牌算法
        for i in (1..indices.len()).rev() {
            let j = rng.gen_range(0..=i);
            indices.swap(i, j);
        }
        
        let winners: Vec<String> = indices
            .into_iter()
            .take(winners_count as usize)
            .map(|i| participants[i].clone())
            .collect();
        
        Ok(winners)
    }
    
    /// 基于种子的随机数生成器
    fn seeded_rng(seed: &[u8]) -> impl rand::Rng {
        use rand::SeedableRng;
        use rand::rngs::StdRng;
        
        let mut seed_bytes = [0u8; 32];
        let seed_len = std::cmp::min(seed.len(), 32);
        seed_bytes[..seed_len].copy_from_slice(&seed[..seed_len]);
        
        StdRng::from_seed(seed_bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_voting_system() {
        let mut voting_system = VotingSystem::new();
        
        let current_time = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // 创建会话
        let session = voting_system.create_session(
            "test_session",
            current_time + 3600, // 1小时后
            current_time + 7200, // 2小时后
            vec!["user1".to_string(), "user2".to_string()]
        ).unwrap();
        
        assert_eq!(session.session_id, "test_session");
        assert_eq!(session.state, VotingSessionState::Created);
        
        // 提交第一个承诺，不应进入CommitPhase
        let _commitment1 = voting_system.submit_commitment(
            "test_session",
            "user1",
            b"vote for option 1"
        ).unwrap();
        
        let session = voting_system.get_session("test_session").unwrap();
        assert_eq!(session.state, VotingSessionState::Created);
        assert!(session.commitments.contains_key("user1"));

        // 提交第二个承诺，应进入CommitPhase
        let _commitment2 = voting_system.submit_commitment(
            "test_session",
            "user2",
            b"vote for option 2"
        ).unwrap();

        let session = voting_system.get_session("test_session").unwrap();
        assert_eq!(session.state, VotingSessionState::CommitPhase);
        assert!(session.commitments.contains_key("user2"));
    }

    #[test]
    fn test_multi_target_selector() {
        // 测试n选k算法
        let combinations = MultiTargetSelector::n_choose_k(4, 2).unwrap();
        assert_eq!(combinations.len(), 6); // C(4,2) = 6
        
        // 测试公平选择
        let participants = vec![
            "user1".to_string(),
            "user2".to_string(),
            "user3".to_string(),
            "user4".to_string(),
        ];
        
        let winners = MultiTargetSelector::fair_selection(&participants, 2, b"test_seed").unwrap();
        assert_eq!(winners.len(), 2);
        assert!(winners.iter().all(|w| participants.contains(w)));
    }

    #[test]
    fn test_user_permissions() {
        let mut voting_system = VotingSystem::new();
        
        let admin_permissions = UserPermissions {
            user_id: "admin".to_string(),
            token_balance: 1000,
            nft_ownership: vec!["nft1".to_string()],
            permission_level: PermissionLevel::Admin,
            permissions: HashMap::new(),
        };
        
        voting_system.set_user_permissions("admin", admin_permissions);
        
        assert!(voting_system.verify_user_permissions("admin", PermissionLevel::Basic));
        assert!(voting_system.verify_user_permissions("admin", PermissionLevel::Creator));
        assert!(voting_system.verify_user_permissions("admin", PermissionLevel::Admin));
        
        assert!(!voting_system.verify_user_permissions("nonexistent", PermissionLevel::Basic));
    }
}
