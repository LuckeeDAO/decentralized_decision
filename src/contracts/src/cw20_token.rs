//! CW20代币合约实现

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, Uint128,
    testing::mock_env, from_json,
};
use cw20::TokenInfoResponse;
use cw20_base::{
    contract::{execute as cw20_execute, instantiate as cw20_instantiate, query as cw20_query},
    msg::{ExecuteMsg as Cw20BaseExecuteMsg, InstantiateMsg as Cw20BaseInstantiateMsg, QueryMsg as Cw20BaseQueryMsg},
};

use crate::types::{ExecuteMsg, InstantiateMsg, QueryMsg};

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
        let info = mock_info("sender", &[]);

        let msg = ExecuteMsg::Transfer {
            recipient: "recipient".to_string(),
            amount: Uint128::new(100),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.attributes.len(), 3);
    }
}
