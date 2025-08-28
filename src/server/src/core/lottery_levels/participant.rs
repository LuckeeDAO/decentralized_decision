use serde::{Deserialize, Serialize};

/// 参与者信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParticipantInfo {
    pub address: String,
    pub balance: u128,
    pub staked_amount: u128,
    pub first_stake_time: u64,
    pub nft_types: Vec<String>,
    pub permission_level: String,
}


