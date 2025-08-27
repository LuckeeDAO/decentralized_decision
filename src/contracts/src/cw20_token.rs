//! CW20代币合约实现

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, Uint128, Addr,
    testing::mock_env, from_json,
};
use cosmwasm_std::StdError;
use cw_storage_plus::Map;
use cw20::TokenInfoResponse;
use cw20_base::{
    contract::{execute as cw20_execute, instantiate as cw20_instantiate, query as cw20_query},
    msg::{ExecuteMsg as Cw20BaseExecuteMsg, InstantiateMsg as Cw20BaseInstantiateMsg, QueryMsg as Cw20BaseQueryMsg},
};

use crate::types::{ExecuteMsg, InstantiateMsg, QueryMsg, StakingInfo};

// Staking storage: address -> (staked, locked, reward_accrued, last_update)
const STAKING: Map<&Addr, (Uint128, Uint128, Uint128, u64)> = Map::new("staking");

fn now(env: &Env) -> u64 { env.block.time.seconds() }

fn accrue_reward(
    staked: Uint128,
    reward_accrued: Uint128,
    last_update: u64,
    current: u64,
) -> (Uint128, u64, Uint128) {
    if current <= last_update { return (reward_accrued, last_update, staked); }
    let elapsed = current - last_update;
    // APR basis points env var is not available in contract; use fixed 1500 bps (15%) for demo
    let apr_bps: u128 = 1500;
    // reward = staked * apr_bps/10000 * elapsed/31536000
    let reward = staked.u128()
        .saturating_mul(apr_bps)
        .saturating_mul(elapsed as u128)
        / 10_000u128
        / 31_536_000u128;
    (reward_accrued + Uint128::from(reward), current, staked)
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // 初始化CW20基础合约
    let cw20_msg = Cw20BaseInstantiateMsg {
        name: msg.token_name,
        symbol: msg.token_symbol,
        decimals: msg.decimals,
        initial_balances: vec![], // 初始余额为空，后续通过mint添加
        mint: Some(cw20::MinterResponse {
            minter: msg.admin.clone(),
            cap: None, // 无上限
        }),
        marketing: None,
    };

    // 调用CW20基础合约的instantiate
    match cw20_instantiate(deps, env, info, cw20_msg) {
        Ok(_) => {},
        Err(e) => return Err(cosmwasm_std::StdError::generic_err(format!("CW20 instantiate failed: {}", e))),
    };

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("admin", msg.admin))
}

#[entry_point]
pub fn execute(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Transfer { recipient, amount } => {
            execute_transfer(deps, env, info, recipient, amount)
        }
        ExecuteMsg::Mint { recipient, amount } => {
            execute_mint(deps, env, info, recipient, amount)
        }
        ExecuteMsg::Burn { amount } => {
            execute_burn(deps, env, info, amount)
        }
        ExecuteMsg::Approve { spender, amount } => {
            execute_approve(deps, env, info, spender, amount)
        }
        ExecuteMsg::TransferFrom { owner, recipient, amount } => {
            execute_transfer_from(deps, env, info, owner, recipient, amount)
        }
        ExecuteMsg::Send { contract, amount, msg } => {
            execute_send(deps, env, info, contract, amount, msg)
        }
        ExecuteMsg::BatchTransfer { recipients, amounts } => {
            execute_batch_transfer(deps, env, info, recipients, amounts)
        }
        ExecuteMsg::BatchBurn { amounts } => {
            execute_batch_burn(deps, env, info, amounts)
        }
        ExecuteMsg::Stake { amount } => execute_stake(deps, env, info, amount),
        ExecuteMsg::Unstake { amount } => execute_unstake(deps, env, info, amount),
        ExecuteMsg::Lock { amount } => execute_lock(deps, env, info, amount),
        ExecuteMsg::Unlock { amount } => execute_unlock(deps, env, info, amount),
        ExecuteMsg::ClaimReward {} => execute_claim_reward(deps, env, info),
        _ => Ok(Response::new().add_attribute("method", "execute")),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetBalance { address } => {
            let balance = query_balance(deps, address)?;
            to_json_binary(&balance)
        }
        QueryMsg::GetTokenInfo {} => {
            let token_info = query_token_info(deps)?;
            to_json_binary(&token_info)
        }
        QueryMsg::GetAllowance { owner, spender } => {
            let resp = query_allowance(deps, owner, spender)?;
            to_json_binary(&resp)
        }
        QueryMsg::GetAllAccounts { start_after, limit } => {
            let resp = query_all_accounts(deps, start_after, limit)?;
            to_json_binary(&resp)
        }
        QueryMsg::GetStakingInfo { address } => {
            let info = query_staking_info(deps, address)?;
            to_json_binary(&info)
        }
        _ => to_json_binary(&"Unsupported query"),
    }
}

pub fn execute_transfer(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> StdResult<Response> {
    let cw20_msg = Cw20BaseExecuteMsg::Transfer {
        recipient: recipient.clone(),
        amount,
    };

    // 处理cw20_execute的返回结果
    match cw20_execute(deps, _env, info, cw20_msg) {
        Ok(_) => {},
        Err(e) => return Err(cosmwasm_std::StdError::generic_err(format!("CW20 transfer failed: {}", e))),
    };

    Ok(Response::new()
        .add_attribute("method", "transfer")
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount))
}

pub fn execute_approve(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    spender: String,
    amount: Uint128,
) -> StdResult<Response> {
    let cw20_msg = Cw20BaseExecuteMsg::IncreaseAllowance { spender: spender.clone(), amount, expires: None };
    cw20_execute(deps, _env, info, cw20_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW20 approve failed: {}", e)))?;
    Ok(Response::new()
        .add_attribute("method", "approve")
        .add_attribute("spender", spender)
        .add_attribute("amount", amount))
}

pub fn execute_transfer_from(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    owner: String,
    recipient: String,
    amount: Uint128,
) -> StdResult<Response> {
    let cw20_msg = Cw20BaseExecuteMsg::TransferFrom { owner: owner.clone(), recipient: recipient.clone(), amount };
    cw20_execute(deps, _env, info, cw20_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW20 transfer_from failed: {}", e)))?;
    Ok(Response::new()
        .add_attribute("method", "transfer_from")
        .add_attribute("owner", owner)
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount))
}

pub fn execute_mint(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    amount: Uint128,
) -> StdResult<Response> {
    let cw20_msg = Cw20BaseExecuteMsg::Mint {
        recipient: recipient.clone(),
        amount,
    };

    // 处理cw20_execute的返回结果
    match cw20_execute(deps, _env, info, cw20_msg) {
        Ok(_) => {},
        Err(e) => return Err(cosmwasm_std::StdError::generic_err(format!("CW20 mint failed: {}", e))),
    };

    Ok(Response::new()
        .add_attribute("method", "mint")
        .add_attribute("recipient", recipient)
        .add_attribute("amount", amount))
}

pub fn execute_burn(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    let cw20_msg = Cw20BaseExecuteMsg::Burn { amount };

    // 处理cw20_execute的返回结果
    match cw20_execute(deps, _env, info, cw20_msg) {
        Ok(_) => {},
        Err(e) => return Err(cosmwasm_std::StdError::generic_err(format!("CW20 burn failed: {}", e))),
    };

    Ok(Response::new()
        .add_attribute("method", "burn")
        .add_attribute("amount", amount))
}

pub fn query_balance(deps: Deps, address: String) -> StdResult<crate::types::BalanceResponse> {
    let cw20_msg = Cw20BaseQueryMsg::Balance {
        address: address.clone(),
    };

    // 获取查询结果并正确反序列化
    let response: Binary = cw20_query(deps, mock_env(), cw20_msg)?;
    let balance: cw20::BalanceResponse = from_json(&response)?;

    Ok(crate::types::BalanceResponse {
        address,
        balance: balance.balance,
    })
}

pub fn query_token_info(deps: Deps) -> StdResult<crate::types::TokenInfoResponse> {
    let cw20_msg = Cw20BaseQueryMsg::TokenInfo {};

    // 获取查询结果并正确反序列化
    let response: Binary = cw20_query(deps, mock_env(), cw20_msg)?;
    let token_info: TokenInfoResponse = from_json(&response)?;

    Ok(crate::types::TokenInfoResponse {
        name: token_info.name,
        symbol: token_info.symbol,
        decimals: token_info.decimals,
        total_supply: token_info.total_supply,
    })
}

pub fn execute_send(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    contract: String,
    amount: Uint128,
    msg: Option<Binary>,
) -> StdResult<Response> {
    let cw20_msg = Cw20BaseExecuteMsg::Send { contract: contract.clone(), amount, msg: msg.unwrap_or_else(Binary::default) };
    cw20_execute(deps, _env, info, cw20_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW20 send failed: {}", e)))?;
    Ok(Response::new()
        .add_attribute("method", "send")
        .add_attribute("contract", contract)
        .add_attribute("amount", amount))
}

pub fn execute_batch_transfer(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    recipients: Vec<String>,
    amounts: Vec<Uint128>,
) -> StdResult<Response> {
    if recipients.len() != amounts.len() {
        return Err(cosmwasm_std::StdError::generic_err("Recipients and amounts length mismatch"));
    }
    let mut count: u32 = 0;
    for (rcp, amt) in recipients.into_iter().zip(amounts.into_iter()) {
        let _ = execute_transfer(deps.branch(), env.clone(), info.clone(), rcp, amt)?;
        count = count.saturating_add(1);
    }
    let mut resp = Response::new();
    #[cfg(not(feature = "minimal_events"))]
    {
        resp = resp.add_attribute("method", "batch_transfer");
        resp = resp.add_attribute("items", count.to_string());
    }
    Ok(resp)
}

pub fn execute_batch_burn(
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amounts: Vec<Uint128>,
) -> StdResult<Response> {
    let mut count: u32 = 0;
    for amt in amounts.into_iter() {
        let _ = execute_burn(deps.branch(), env.clone(), info.clone(), amt)?;
        count = count.saturating_add(1);
    }
    let mut resp = Response::new();
    #[cfg(not(feature = "minimal_events"))]
    {
        resp = resp.add_attribute("method", "batch_burn");
        resp = resp.add_attribute("items", count.to_string());
    }
    Ok(resp)
}

pub fn query_allowance(deps: Deps, owner: String, spender: String) -> StdResult<cw20::AllowanceResponse> {
    let cw20_msg = Cw20BaseQueryMsg::Allowance { owner, spender };
    let response: Binary = cw20_query(deps, mock_env(), cw20_msg)?;
    let allowance: cw20::AllowanceResponse = from_json(&response)?;
    Ok(allowance)
}

pub fn query_all_accounts(
    deps: Deps,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<cw20::AllAccountsResponse> {
    let cw20_msg = Cw20BaseQueryMsg::AllAccounts { start_after, limit };
    let response: Binary = cw20_query(deps, mock_env(), cw20_msg)?;
    let accounts: cw20::AllAccountsResponse = from_json(&response)?;
    Ok(accounts)
}

fn must_addr(api: &dyn cosmwasm_std::Api, addr: &str) -> Result<Addr, StdError> {
    api.addr_validate(addr)
}

pub fn execute_stake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    // Transfer tokens from sender to contract itself to represent staking lock-in
    if amount.is_zero() { return Err(StdError::generic_err("amount must be > 0")); }
    // First update staking record
    let addr = info.sender.clone();
    let key = addr.clone();
    let (mut staked, locked, mut reward, mut last) = STAKING.may_load(deps.storage, &key)?.unwrap_or((Uint128::zero(), Uint128::zero(), Uint128::zero(), now(&env)));
    let (new_reward, new_last, _) = accrue_reward(staked, reward, last, now(&env));
    reward = new_reward; last = new_last;
    staked = staked + amount;
    STAKING.save(deps.storage, &key, &(staked, locked, reward, last))?;
    // Then move tokens into contract by transferring to self
    let contract_addr = env.contract.address.to_string();
    let res = execute_transfer(deps, env, info, contract_addr, amount)?;
    Ok(res.add_attribute("staking", "stake").add_attribute("amount", amount))
}

pub fn execute_unstake(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    if amount.is_zero() { return Err(StdError::generic_err("amount must be > 0")); }
    let addr = info.sender.clone();
    let key = addr.clone();
    let (mut staked, locked, mut reward, mut last) = STAKING.may_load(deps.storage, &key)?.unwrap_or((Uint128::zero(), Uint128::zero(), Uint128::zero(), now(&env)));
    let (new_reward, new_last, _) = accrue_reward(staked, reward, last, now(&env));
    reward = new_reward; last = new_last;
    if staked < amount { return Err(StdError::generic_err("insufficient staked")); }
    staked = staked.checked_sub(amount)?;
    STAKING.save(deps.storage, &key, &(staked, locked, reward, last))?;
    // transfer tokens back from contract to sender
    let cw20_msg = Cw20BaseExecuteMsg::Transfer { recipient: addr.to_string(), amount };
    cw20_execute(deps, env, info, cw20_msg)
        .map(|r| r.add_attribute("staking", "unstake").add_attribute("amount", amount))
        .map_err(|e| StdError::generic_err(format!("unstake transfer failed: {}", e)))
}

pub fn execute_lock(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    if amount.is_zero() { return Err(StdError::generic_err("amount must be > 0")); }
    let addr = info.sender.clone();
    let key = addr.clone();
    let (mut staked, mut locked, mut reward, mut last) = STAKING.may_load(deps.storage, &key)?.unwrap_or((Uint128::zero(), Uint128::zero(), Uint128::zero(), now(&env)));
    let (new_reward, new_last, _) = accrue_reward(staked, reward, last, now(&env));
    reward = new_reward; last = new_last;
    if staked < amount { return Err(StdError::generic_err("insufficient staked to lock")); }
    staked = staked.checked_sub(amount)?;
    locked = locked + amount;
    STAKING.save(deps.storage, &key, &(staked, locked, reward, last))?;
    Ok(Response::new().add_attribute("staking", "lock").add_attribute("amount", amount))
}

pub fn execute_unlock(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    amount: Uint128,
) -> StdResult<Response> {
    if amount.is_zero() { return Err(StdError::generic_err("amount must be > 0")); }
    let addr = info.sender;
    let key = addr.clone();
    let (mut staked, mut locked, mut reward, mut last) = STAKING.may_load(deps.storage, &key)?.unwrap_or((Uint128::zero(), Uint128::zero(), Uint128::zero(), now(&env)));
    let (new_reward, new_last, _) = accrue_reward(staked, reward, last, now(&env));
    reward = new_reward; last = new_last;
    if locked < amount { return Err(StdError::generic_err("insufficient locked to unlock")); }
    locked = locked.checked_sub(amount)?;
    staked = staked + amount;
    STAKING.save(deps.storage, &key, &(staked, locked, reward, last))?;
    Ok(Response::new().add_attribute("staking", "unlock").add_attribute("amount", amount))
}

pub fn execute_claim_reward(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
) -> StdResult<Response> {
    let addr = info.sender;
    let key = addr.clone();
    let (staked, locked, mut reward, mut last) = STAKING.may_load(deps.storage, &key)?.unwrap_or((Uint128::zero(), Uint128::zero(), Uint128::zero(), now(&env)));
    let (new_reward, new_last, _) = accrue_reward(staked, reward, last, now(&env));
    reward = new_reward; last = new_last;
    if reward.is_zero() {
        STAKING.save(deps.storage, &key, &(staked, locked, reward, last))?;
        return Ok(Response::new().add_attribute("staking", "claim_reward").add_attribute("amount", Uint128::zero()));
    }
    // Mint rewards to sender (requires minter privileges: admin is minter). Use mint to self by admin is enforced by cw20-base; here we assume contract is minter - for demo, we just reset accrued without minting new supply to avoid privilege.
    // For a real implementation, set contract as minter and mint to addr.
    let claimed = reward;
    reward = Uint128::zero();
    STAKING.save(deps.storage, &key, &(staked, locked, reward, last))?;
    Ok(Response::new().add_attribute("staking", "claim_reward").add_attribute("amount", claimed))
}

pub fn query_staking_info(deps: Deps, address: String) -> StdResult<StakingInfo> {
    let addr = must_addr(deps.api, &address)?;
    let (staked, locked, reward, last) = STAKING.may_load(deps.storage, &addr)?.unwrap_or((Uint128::zero(), Uint128::zero(), Uint128::zero(), 0));
    Ok(StakingInfo { address, staked, locked, reward_accrued: reward, last_update: last })
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmwasm_std::testing::{mock_dependencies, mock_env, mock_info};

    #[test]
    fn test_instantiate() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("creator", &[]);

        let msg = InstantiateMsg {
            admin: "admin".to_string(),
            token_name: "Test Token".to_string(),
            token_symbol: "TEST".to_string(),
            decimals: 6,
        };

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.attributes.len(), 2);
    }

    #[test]
    fn test_transfer() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate contract with admin as minter
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {
            admin: "admin".to_string(),
            token_name: "Test Token".to_string(),
            token_symbol: "TEST".to_string(),
            decimals: 6,
        };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint to sender so it has balance to transfer
        let mint_info = mock_info("admin", &[]);
        let mint_msg = ExecuteMsg::Mint {
            recipient: "sender".to_string(),
            amount: Uint128::new(200),
        };
        execute(deps.as_mut(), env.clone(), mint_info, mint_msg).unwrap();

        // now transfer from sender to recipient
        let transfer_info = mock_info("sender", &[]);
        let transfer_msg = ExecuteMsg::Transfer {
            recipient: "recipient".to_string(),
            amount: Uint128::new(100),
        };

        let res = execute(deps.as_mut(), env, transfer_info, transfer_msg).unwrap();
        assert_eq!(res.attributes.len(), 3);
    }

    #[test]
    fn test_approve_and_transfer_from() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {
            admin: "admin".to_string(),
            token_name: "Test Token".to_string(),
            token_symbol: "TEST".to_string(),
            decimals: 6,
        };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint to owner
        let mint_info = mock_info("admin", &[]);
        let mint_msg = ExecuteMsg::Mint { recipient: "owner".to_string(), amount: Uint128::new(200) };
        execute(deps.as_mut(), env.clone(), mint_info, mint_msg).unwrap();

        // owner approves spender
        let approve_info = mock_info("owner", &[]);
        let approve_msg = ExecuteMsg::Approve { spender: "spender".to_string(), amount: Uint128::new(150) };
        execute(deps.as_mut(), env.clone(), approve_info, approve_msg).unwrap();

        // spender transfers from owner to recipient
        let tf_info = mock_info("spender", &[]);
        let tf_msg = ExecuteMsg::TransferFrom { owner: "owner".to_string(), recipient: "rcp".to_string(), amount: Uint128::new(100) };
        let res = execute(deps.as_mut(), env.clone(), tf_info, tf_msg).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "transfer_from"));

        // query allowance
        let allowance = query_allowance(deps.as_ref(), "owner".to_string(), "spender".to_string()).unwrap();
        assert_eq!(allowance.allowance, Uint128::new(50));

        // list accounts
        let accounts = query_all_accounts(deps.as_ref(), None, Some(10)).unwrap();
        assert!(accounts.accounts.len() >= 2);
    }

    #[test]
    fn test_send_and_batch_ops() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "Token".to_string(), token_symbol: "TOK".to_string(), decimals: 6 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint to alice
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("admin", &[]),
            ExecuteMsg::Mint { recipient: "alice".to_string(), amount: Uint128::new(300) }
        ).unwrap();

        // send from alice to contractX
        let res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("alice", &[]),
            ExecuteMsg::Send { contract: "contractx".to_string(), amount: Uint128::new(50), msg: None }
        ).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "send"));

        // batch transfer from alice to bob/charlie
        let res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("alice", &[]),
            ExecuteMsg::BatchTransfer {
                recipients: vec!["bob".to_string(), "charlie".to_string()],
                amounts: vec![Uint128::new(60), Uint128::new(40)],
            }
        ).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "batch_transfer"));

        // batch burn from alice
        let res = execute(
            deps.as_mut(),
            env,
            mock_info("alice", &[]),
            ExecuteMsg::BatchBurn { amounts: vec![Uint128::new(10), Uint128::new(5)] }
        ).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "batch_burn"));
    }

    #[test]
    fn test_stake_lock_unlock_unstake_and_claim() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "Token".to_string(), token_symbol: "TOK".to_string(), decimals: 6 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint to alice
        execute(
            deps.as_mut(),
            env.clone(),
            mock_info("admin", &[]),
            ExecuteMsg::Mint { recipient: "alice".to_string(), amount: Uint128::new(1_000) }
        ).unwrap();

        // alice stakes 400
        let _ = execute(
            deps.as_mut(), env.clone(), mock_info("alice", &[]), ExecuteMsg::Stake { amount: Uint128::new(400) }
        ).unwrap();

        // lock 100 of the staked
        let _ = execute(
            deps.as_mut(), env.clone(), mock_info("alice", &[]), ExecuteMsg::Lock { amount: Uint128::new(100) }
        ).unwrap();

        // unlock 50 back to staked
        let _ = execute(
            deps.as_mut(), env.clone(), mock_info("alice", &[]), ExecuteMsg::Unlock { amount: Uint128::new(50) }
        ).unwrap();

        // query staking info
        let info = query_staking_info(deps.as_ref(), "alice".to_string()).unwrap();
        assert_eq!(info.staked, Uint128::new(350));
        assert_eq!(info.locked, Uint128::new(50));

        // claim reward (may be zero in mocked env time)
        let _ = execute(
            deps.as_mut(), env.clone(), mock_info("alice", &[]), ExecuteMsg::ClaimReward {}
        ).unwrap();

        // unstake 200
        let _ = execute(
            deps.as_mut(), env, mock_info("alice", &[]), ExecuteMsg::Unstake { amount: Uint128::new(200) }
        ).unwrap();

        // verify staking reduced
        let info2 = query_staking_info(deps.as_ref(), "alice".to_string()).unwrap();
        assert_eq!(info2.staked, Uint128::new(150));
    }

    #[test]
    fn test_query_balance_under_500ms() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "Token".to_string(), token_symbol: "TOK".to_string(), decimals: 6 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();
        execute(
            deps.as_mut(), env.clone(), mock_info("admin", &[]), ExecuteMsg::Mint { recipient: "alice".to_string(), amount: Uint128::new(1_000) }
        ).unwrap();
        let start = std::time::Instant::now();
        let _ = query_balance(deps.as_ref(), "alice".to_string()).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_millis(500));
    }
}
