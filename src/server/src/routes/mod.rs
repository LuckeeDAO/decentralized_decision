// 基础与状态路由
pub mod health;
pub mod state_metrics;

// IPFS 与扩展路由
pub mod ipfs_cache;
pub mod ipfs_ext;
pub mod upload;

// NFT 与抽奖路由
pub mod nft_types;
pub mod nft_ownership;
pub mod lottery_config;
pub mod levels;
pub mod nft_state;

// 权限与质押路由
pub mod permissions;
pub mod staking;
pub mod qualification;
pub mod stake_events;

// 核心功能路由
pub mod voting;
pub mod sync;
pub mod tools;
pub mod cache;
pub mod audit;
pub mod serials;

