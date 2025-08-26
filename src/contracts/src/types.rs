//! 智能合约类型定义

use cosmwasm_schema::{cw_serde, QueryResponses};
use cosmwasm_std::{Addr, Uint128, Timestamp};

#[cw_serde]
pub struct InstantiateMsg {
    pub admin: String,
    pub token_name: String,
    pub token_symbol: String,
    pub decimals: u8,
}

#[cw_serde]
pub enum ExecuteMsg {
    // 投票相关
    CreateVotingSession {
        session_id: String,
        title: String,
        description: String,
        options: Vec<String>,
        start_time: Timestamp,
        end_time: Timestamp,
    },
    // NFT批量铸造（仅用于CW721实现）
    BatchMint {
        recipients: Vec<String>,
    },
    // NFT带元数据铸造
    MintWithMetadata {
        recipient: String,
        token_uri: Option<String>,
        extension: Option<serde_json::Value>,
    },
    SubmitVote {
        session_id: String,
        option_index: u32,
    },
    FinalizeVoting {
        session_id: String,
    },
    
    // 代币相关
    Transfer {
        recipient: String,
        amount: Uint128,
    },
    Mint {
        recipient: String,
        amount: Uint128,
    },
    Burn {
        amount: Uint128,
    },
    // CW20发送与批量操作
    Send {
        contract: String,
        amount: Uint128,
        msg: Option<cosmwasm_std::Binary>,
    },
    BatchTransfer {
        recipients: Vec<String>,
        amounts: Vec<Uint128>,
    },
    BatchBurn {
        amounts: Vec<Uint128>,
    },
    // 授权与代理转账
    Approve {
        spender: String,
        amount: Uint128,
    },
    TransferFrom {
        owner: String,
        recipient: String,
        amount: Uint128,
    },
    // 质押与锁定
    Stake {
        amount: Uint128,
    },
    Unstake {
        amount: Uint128,
    },
    Lock {
        amount: Uint128,
    },
    Unlock {
        amount: Uint128,
    },
    ClaimReward {},
}

#[cw_serde]
#[derive(QueryResponses)]
pub enum QueryMsg {
    #[returns(VotingSessionResponse)]
    GetVotingSession { session_id: String },
    #[returns(Vec<VotingSessionResponse>)]
    ListVotingSessions {},
    #[returns(VotingResultResponse)]
    GetVotingResult { session_id: String },
    #[returns(BalanceResponse)]
    GetBalance { address: String },
    #[returns(TokenInfoResponse)]
    GetTokenInfo {},
    // 代币权限与账户查询
    #[returns(cw20::AllowanceResponse)]
    GetAllowance { owner: String, spender: String },
    #[returns(cw20::AllAccountsResponse)]
    GetAllAccounts { start_after: Option<String>, limit: Option<u32> },
    // NFT查询
    #[returns(cw721::OwnerOfResponse)]
    GetOwnerOf { token_id: String },
    #[returns(cw721::NftInfoResponse<serde_json::Value>)]
    GetNftInfo { token_id: String },
    #[returns(cw721::AllNftInfoResponse<serde_json::Value>)]
    GetAllNftInfo { token_id: String, include_expired: Option<bool> },
    // 质押状态查询
    #[returns(StakingInfo)]
    GetStakingInfo { address: String },
}

#[cw_serde]
pub struct VotingSessionResponse {
    pub session_id: String,
    pub title: String,
    pub description: String,
    pub options: Vec<String>,
    pub start_time: Timestamp,
    pub end_time: Timestamp,
    pub status: VotingStatus,
    pub total_votes: Uint128,
}

#[cw_serde]
pub struct VotingResultResponse {
    pub session_id: String,
    pub winning_option: Option<u32>,
    pub vote_counts: Vec<Uint128>,
    pub total_votes: Uint128,
}

#[cw_serde]
pub struct BalanceResponse {
    pub address: String,
    pub balance: Uint128,
}

#[cw_serde]
pub struct TokenInfoResponse {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
}

#[cw_serde]
pub struct StakingInfo {
    pub address: String,
    pub staked: Uint128,
    pub locked: Uint128,
    pub reward_accrued: Uint128,
    pub last_update: u64,
}

#[cw_serde]
pub enum VotingStatus {
    Active,
    Ended,
    Finalized,
}

#[cw_serde]
pub struct State {
    pub admin: Addr,
    pub token_name: String,
    pub token_symbol: String,
    pub decimals: u8,
    pub total_supply: Uint128,
}

#[cw_serde]
pub struct VotingSession {
    pub session_id: String,
    pub title: String,
    pub description: String,
    pub options: Vec<String>,
    pub start_time: Timestamp,
    pub end_time: Timestamp,
    pub status: VotingStatus,
    pub votes: Vec<Vote>,
}

#[cw_serde]
pub struct Vote {
    pub voter: Addr,
    pub option_index: u32,
    pub timestamp: Timestamp,
}
