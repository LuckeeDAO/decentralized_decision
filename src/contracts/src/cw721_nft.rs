//! CW721 NFT合约实现

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, from_json, testing::mock_env,
};
use cw721_base::{
    entry::{execute as cw721_execute, instantiate as cw721_instantiate, query as cw721_query},
    msg::{ExecuteMsg as Cw721BaseExecuteMsg, InstantiateMsg as Cw721BaseInstantiateMsg, QueryMsg as Cw721BaseQueryMsg},
    Extension,
};

use crate::types::{ExecuteMsg, InstantiateMsg, QueryMsg};

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    // 初始化CW721基础合约
    let cw721_msg = Cw721BaseInstantiateMsg {
        name: msg.token_name,
        symbol: msg.token_symbol,
        minter: msg.admin.clone(),
    };

    // 调用CW721基础合约的instantiate
    cw721_instantiate(deps, env, info, cw721_msg)?;

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
        ExecuteMsg::Mint { recipient, amount: _ } => {
            // 对于NFT，我们忽略amount参数，因为每个NFT都是唯一的
            execute_mint_nft(deps, env, info, recipient)
        }
        _ => Ok(Response::new().add_attribute("method", "execute")),
    }
}

#[entry_point]
pub fn query(deps: Deps, _env: Env, msg: QueryMsg) -> StdResult<Binary> {
    match msg {
        QueryMsg::GetTokenInfo {} => {
            let token_info = query_token_info(deps)?;
            to_json_binary(&token_info)
        }
        _ => to_json_binary(&"Unsupported query"),
    }
}

pub fn execute_mint_nft(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
) -> StdResult<Response> {
    // 生成唯一的token ID
    let token_id = format!("nft_{}", recipient);
    
    let cw721_msg = Cw721BaseExecuteMsg::Mint {
        token_id: token_id.clone(),
        owner: recipient.clone(),
        token_uri: Some("https://example.com/metadata.json".to_string()),
        extension: Extension::default(),
    };

    cw721_execute(deps, _env, info, cw721_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW721 mint failed: {}", e)))?;

    Ok(Response::new()
        .add_attribute("method", "mint_nft")
        .add_attribute("recipient", recipient)
        .add_attribute("token_id", token_id))
}

pub fn query_token_info(deps: Deps) -> StdResult<crate::types::TokenInfoResponse> {
    let cw721_msg = Cw721BaseQueryMsg::ContractInfo {};

    // 获取查询结果并正确反序列化
    let response: Binary = cw721_query(deps, mock_env(), cw721_msg)?;
    let contract_info: cw721::ContractInfoResponse = from_json(&response)?;

    Ok(crate::types::TokenInfoResponse {
        name: contract_info.name,
        symbol: contract_info.symbol,
        decimals: 0, // NFT没有小数位
        total_supply: cosmwasm_std::Uint128::new(0), // 这里应该查询实际的供应量
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
            token_name: "Test NFT".to_string(),
            token_symbol: "TNFT".to_string(),
            decimals: 0,
        };

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.attributes.len(), 2);
    }

    #[test]
    fn test_mint_nft() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("minter", &[]);

        let msg = ExecuteMsg::Mint {
            recipient: "recipient".to_string(),
            amount: cosmwasm_std::Uint128::new(1),
        };

        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.attributes.len(), 3);
    }
}
