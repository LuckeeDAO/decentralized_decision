//! 投票合约实现

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, Addr,
};
use serde::{Serialize, Deserialize};

use crate::types::{ExecuteMsg, InstantiateMsg, QueryMsg};

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct VotingContractState {
    pub admin: Addr,
}

#[entry_point]
pub fn instantiate(
    deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    msg: InstantiateMsg,
) -> StdResult<Response> {
    let state = VotingContractState {
        admin: Addr::unchecked(msg.admin.clone()),
    };

    deps.storage.set(b"state", &to_json_binary(&state)?);

    Ok(Response::new()
        .add_attribute("method", "instantiate")
        .add_attribute("admin", msg.admin))
}

#[entry_point]
pub fn execute(
    _deps: DepsMut,
    _env: Env,
    _info: MessageInfo,
    _msg: ExecuteMsg,
) -> StdResult<Response> {
    Ok(Response::new().add_attribute("method", "execute"))
}

#[entry_point]
pub fn query(_deps: Deps, _env: Env, _msg: QueryMsg) -> StdResult<Binary> {
    to_json_binary(&"Unsupported query")
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
}
