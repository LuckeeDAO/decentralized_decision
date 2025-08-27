//! 基于比特承诺模型的去中心化投票系统 - 智能合约模块
//! 
//! 实现CW20代币合约和CW721 NFT合约

pub mod cw20_token;
pub mod cw721_nft;
pub mod voting_contract;
pub mod types;

use cosmwasm_std::{entry_point, Binary, Deps, DepsMut, Env, MessageInfo, Response, StdResult};
use cw2::set_contract_version;

const CONTRACT_NAME: &str = "luckee-voting-contracts";
const CONTRACT_VERSION: &str = env!("CARGO_PKG_VERSION");

#[entry_point]
pub fn instantiate(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Binary,
) -> StdResult<Response> {
    set_contract_version(_deps.storage, CONTRACT_NAME, CONTRACT_VERSION)?;
    Ok(Response::new().add_attribute("method", "instantiate"))
}

#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: Binary,
) -> StdResult<Response> {
    Ok(Response::new().add_attribute("method", "execute"))
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, _msg: Binary) -> StdResult<Binary> {
    Ok(Binary::default())
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
        let msg = Binary::default();

        let res = instantiate(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages.len(), 0);
    }

    #[test]
    fn test_execute() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let info = mock_info("creator", &[]);
        let msg = Binary::default();

        let res = execute(deps.as_mut(), env, info, msg).unwrap();
        assert_eq!(res.messages.len(), 0);
    }

    #[test]
    fn test_query() {
        let deps = mock_dependencies();
        let env = mock_env();
        let msg = Binary::default();

        let res = query(deps.as_ref(), env, msg).unwrap();
        assert_eq!(res, Binary::default());
    }

    use cw_multi_test::{App, Contract, ContractWrapper, Executor};

    fn cw20_contract() -> Box<dyn Contract<cosmwasm_std::Empty>> {
        let c = ContractWrapper::new(
            crate::cw20_token::execute,
            crate::cw20_token::instantiate,
            crate::cw20_token::query,
        );
        Box::new(c)
    }

    fn cw721_contract() -> Box<dyn Contract<cosmwasm_std::Empty>> {
        let c = ContractWrapper::new(
            crate::cw721_nft::execute,
            crate::cw721_nft::instantiate,
            crate::cw721_nft::query,
        );
        Box::new(c)
    }

    #[test]
    fn test_token_nft_interaction_in_same_app() {
        let mut app = App::default();
        let cw20_id = app.store_code(cw20_contract());
        let cw721_id = app.store_code(cw721_contract());

        // instantiate CW20
        let cw20_addr = app
            .instantiate_contract(
                cw20_id,
                cosmwasm_std::Addr::unchecked("creator"),
                &crate::types::InstantiateMsg { admin: "admin".into(), token_name: "LUCKEE".into(), token_symbol: "LKE".into(), decimals: 6 },
                &[],
                "cw20",
                None,
            )
            .unwrap();

        // instantiate CW721
        let cw721_addr = app
            .instantiate_contract(
                cw721_id,
                cosmwasm_std::Addr::unchecked("creator"),
                &crate::types::InstantiateMsg { admin: "admin".into(), token_name: "NFT".into(), token_symbol: "NFT".into(), decimals: 0 },
                &[],
                "cw721",
                None,
            )
            .unwrap();

        // Mint fungible tokens to alice via admin
        app.execute_contract(
            cosmwasm_std::Addr::unchecked("admin"),
            cw20_addr.clone(),
            &crate::types::ExecuteMsg::Mint { recipient: "alice".into(), amount: cosmwasm_std::Uint128::new(1_000) },
            &[],
        ).unwrap();

        // Mint NFT to alice via admin
        app.execute_contract(
            cosmwasm_std::Addr::unchecked("admin"),
            cw721_addr.clone(),
            &crate::types::ExecuteMsg::Mint { recipient: "alice".into(), amount: cosmwasm_std::Uint128::new(1) },
            &[],
        ).unwrap();

        // Transfer NFT from alice to bob
        app.execute_contract(
            cosmwasm_std::Addr::unchecked("alice"),
            cw721_addr.clone(),
            &crate::types::ExecuteMsg::Transfer { recipient: "bob".into(), amount: cosmwasm_std::Uint128::new(1) },
            &[],
        ).unwrap();

        // Approve and transfer_from CW20 from alice to bob
        app.execute_contract(
            cosmwasm_std::Addr::unchecked("alice"),
            cw20_addr.clone(),
            &crate::types::ExecuteMsg::Approve { spender: "spender".into(), amount: cosmwasm_std::Uint128::new(300) },
            &[],
        ).unwrap();
        app.execute_contract(
            cosmwasm_std::Addr::unchecked("spender"),
            cw20_addr.clone(),
            &crate::types::ExecuteMsg::TransferFrom { owner: "alice".into(), recipient: "bob".into(), amount: cosmwasm_std::Uint128::new(200) },
            &[],
        ).unwrap();

        // Cross-contract attempt: send CW20 to CW721 should fail (no receiver), validating error path
        let res = app.execute_contract(
            cosmwasm_std::Addr::unchecked("alice"),
            cw20_addr.clone(),
            &crate::types::ExecuteMsg::Send { contract: cw721_addr.to_string(), amount: cosmwasm_std::Uint128::new(10), msg: None },
            &[],
        );
        assert!(res.is_err());
    }
}
