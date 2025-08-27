//! CW721 NFT合约实现

use cosmwasm_std::{
    entry_point, to_json_binary, Binary, Deps, DepsMut, Env, MessageInfo,
    Response, StdResult, from_json, testing::mock_env, Storage,
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
    mut deps: DepsMut,
    env: Env,
    info: MessageInfo,
    msg: ExecuteMsg,
) -> StdResult<Response> {
    match msg {
        ExecuteMsg::Mint { recipient, amount: _ } => {
            // 对于NFT，我们忽略amount参数，因为每个NFT都是唯一的
            execute_mint_nft(deps, env, info, recipient)
        }
        ExecuteMsg::BatchMint { recipients } => {
            let mut count: u32 = 0;
            for r in recipients.into_iter() {
                let r_clone = r.clone();
                execute_mint_nft(deps.branch(), env.clone(), info.clone(), r_clone)?;
                count = count.saturating_add(1);
            }
            let mut resp = Response::new();
            #[cfg(not(feature = "minimal_events"))]
            {
                resp = resp.add_attribute("method", "batch_mint_nft");
                resp = resp.add_attribute("items", count.to_string());
            }
            Ok(resp)
        }
        // 支持转移与销毁
        ExecuteMsg::Transfer { recipient, amount: _ } => {
            // 查找发送者持有的第一个token并转移
            let token_id = find_first_token_of(deps.as_ref(), info.sender.to_string())
                .map_err(|e| cosmwasm_std::StdError::generic_err(e))?
                .ok_or_else(|| cosmwasm_std::StdError::generic_err("No token to transfer"))?;
            execute_transfer_nft(deps, env, info, token_id, recipient)
        }
        // 带元数据的铸造
        ExecuteMsg::MintWithMetadata { recipient, token_uri, extension } => {
            execute_mint_nft_with_meta(deps, env, info, recipient, token_uri, extension)
        }
        // Send与BatchTransfer通过多次Transfer实现
        ExecuteMsg::Send { contract, amount: _, msg: _ } => {
            let token_id = find_first_token_of(deps.as_ref(), info.sender.to_string())
                .map_err(|e| cosmwasm_std::StdError::generic_err(e))?
                .ok_or_else(|| cosmwasm_std::StdError::generic_err("No token to send"))?;
            // 在NFT场景下，将contract参数视为接收地址
            execute_transfer_nft(deps, env, info, token_id, contract)
        }
        ExecuteMsg::BatchTransfer { recipients, amounts: _ } => {
            let mut count: u32 = 0;
            for r in recipients.into_iter() {
                let token_id = find_first_token_of(deps.as_ref(), info.sender.to_string())
                    .map_err(|e| cosmwasm_std::StdError::generic_err(e))?
                    .ok_or_else(|| cosmwasm_std::StdError::generic_err("No token to transfer"))?;
                let r_clone = r.clone();
                execute_transfer_nft(deps.branch(), env.clone(), info.clone(), token_id, r_clone)?;
                count = count.saturating_add(1);
            }
            let mut resp = Response::new();
            #[cfg(not(feature = "minimal_events"))]
            {
                resp = resp.add_attribute("method", "batch_transfer_nft");
                resp = resp.add_attribute("items", count.to_string());
            }
            Ok(resp)
        }
        ExecuteMsg::Burn { amount: _ } => {
            let token_id = find_first_token_of(deps.as_ref(), info.sender.to_string())
                .map_err(|e| cosmwasm_std::StdError::generic_err(e))?
                .ok_or_else(|| cosmwasm_std::StdError::generic_err("No token to burn"))?;
            execute_burn_nft(deps, env, info, token_id)
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
        QueryMsg::GetOwnerOf { token_id } => {
            let resp = query_owner_of(deps, token_id)?;
            to_json_binary(&resp)
        }
        QueryMsg::GetNftInfo { token_id } => {
            let resp = query_nft_info(deps, token_id)?;
            to_json_binary(&resp)
        }
        QueryMsg::GetAllNftInfo { token_id, include_expired } => {
            let resp = query_all_nft_info(deps, token_id, include_expired)?;
            to_json_binary(&resp)
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
    // 生成唯一的token ID（基于全局自增nonce）
    let nonce = next_nonce(deps.storage)?;
    let token_id = format!("nft_{}_{}", recipient, nonce);
    
    // 最小化链上存储：默认不写入任何外部URL，仅在需要时通过 MintWithMetadata 传入 ipfs://CID
    let cw721_msg = Cw721BaseExecuteMsg::Mint {
        token_id: token_id.clone(),
        owner: recipient.clone(),
        token_uri: None,
        extension: Extension::default(),
    };

    cw721_execute(deps, _env, info, cw721_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW721 mint failed: {}", e)))?;

    Ok(Response::new()
        .add_attribute("method", "mint_nft")
        .add_attribute("recipient", recipient)
        .add_attribute("token_id", token_id))
}

pub fn execute_mint_nft_with_meta(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    recipient: String,
    token_uri: Option<String>,
    _extension: Option<serde_json::Value>,
) -> StdResult<Response> {
    let nonce = next_nonce(deps.storage)?;
    let token_id = format!("nft_{}_{}", recipient, nonce);

    // 仅允许存储 ipfs://CID 或裸 CID，避免长URL上链
    fn normalize_ipfs_uri(uri_opt: Option<String>) -> Option<String> {
        match uri_opt {
            None => None,
            Some(u) => {
                let trimmed = u.trim();
                if trimmed.is_empty() { return None; }
                if trimmed.starts_with("ipfs://") {
                    return Some(trimmed.to_string());
                }
                // 简单CID形式：不包含冒号且不包含斜杠，长度在合理范围内
                if !trimmed.contains(":") && !trimmed.contains('/') && trimmed.len() >= 32 {
                    return Some(format!("ipfs://{}", trimmed));
                }
                // 其他URL一律拒绝，转为不写入，避免冗长上链数据
                None
            }
        }
    }

    let cw721_msg = Cw721BaseExecuteMsg::Mint {
        token_id: token_id.clone(),
        owner: recipient.clone(),
        token_uri: normalize_ipfs_uri(token_uri),
        // 目前使用默认扩展类型（Empty），若需自定义扩展需调整合约泛型
        extension: Extension::default(),
    };

    cw721_execute(deps, _env, info, cw721_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW721 mint failed: {}", e)))?;

    Ok(Response::new()
        .add_attribute("method", "mint_nft_with_metadata")
        .add_attribute("recipient", recipient)
        .add_attribute("token_id", token_id))
}

fn next_nonce(storage: &mut dyn Storage) -> StdResult<u64> {
    const KEY: &[u8] = b"nft_nonce";
    let current = storage.get(KEY).map(|b| {
        let mut arr = [0u8; 8];
        arr.copy_from_slice(&b);
        u64::from_le_bytes(arr)
    }).unwrap_or(0);
    let next = current.wrapping_add(1);
    storage.set(KEY, &next.to_le_bytes());
    Ok(next)
}

pub fn execute_transfer_nft(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    token_id: String,
    recipient: String,
) -> StdResult<Response> {
    let cw721_msg = Cw721BaseExecuteMsg::TransferNft { recipient: recipient.clone(), token_id: token_id.clone() };
    cw721_execute(deps, _env, info, cw721_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW721 transfer failed: {}", e)))?;
    Ok(Response::new()
        .add_attribute("method", "transfer_nft")
        .add_attribute("recipient", recipient)
        .add_attribute("token_id", token_id))
}

pub fn execute_burn_nft(
    deps: DepsMut,
    _env: Env,
    info: MessageInfo,
    token_id: String,
) -> StdResult<Response> {
    let cw721_msg = Cw721BaseExecuteMsg::Burn { token_id: token_id.clone() };
    cw721_execute(deps, _env, info, cw721_msg)
        .map_err(|e| cosmwasm_std::StdError::generic_err(format!("CW721 burn failed: {}", e)))?;
    Ok(Response::new()
        .add_attribute("method", "burn_nft")
        .add_attribute("token_id", token_id))
}

pub fn query_owner_of(deps: Deps, token_id: String) -> StdResult<cw721::OwnerOfResponse> {
    let cw721_msg = Cw721BaseQueryMsg::OwnerOf { token_id, include_expired: None }; 
    let response: Binary = cw721_query(deps, mock_env(), cw721_msg)?;
    let owner: cw721::OwnerOfResponse = from_json(&response)?;
    Ok(owner)
}

pub fn query_nft_info(deps: Deps, token_id: String) -> StdResult<cw721::NftInfoResponse<serde_json::Value>> {
    let cw721_msg = Cw721BaseQueryMsg::NftInfo { token_id };
    let response: Binary = cw721_query(deps, mock_env(), cw721_msg)?;
    let info: cw721::NftInfoResponse<serde_json::Value> = from_json(&response)?;
    Ok(info)
}

pub fn query_all_nft_info(
    deps: Deps,
    token_id: String,
    include_expired: Option<bool>,
) -> StdResult<cw721::AllNftInfoResponse<serde_json::Value>> {
    let cw721_msg = Cw721BaseQueryMsg::AllNftInfo { token_id, include_expired };
    let response: Binary = cw721_query(deps, mock_env(), cw721_msg)?;
    let info: cw721::AllNftInfoResponse<serde_json::Value> = from_json(&response)?;
    Ok(info)
}

pub fn query_tokens_of_owner(
    deps: Deps,
    owner: String,
    start_after: Option<String>,
    limit: Option<u32>,
) -> StdResult<cw721::TokensResponse> {
    let cw721_msg = Cw721BaseQueryMsg::Tokens { owner, start_after, limit };
    let response: Binary = cw721_query(deps, mock_env(), cw721_msg)?;
    let tokens: cw721::TokensResponse = from_json(&response)?;
    Ok(tokens)
}

fn find_first_token_of(deps: Deps, owner: String) -> Result<Option<String>, String> {
    match query_tokens_of_owner(deps, owner, None, Some(1)) {
        Ok(resp) => Ok(resp.tokens.into_iter().next()),
        Err(e) => Err(e.to_string()),
    }
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

        // instantiate contract with admin as minter
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {
            admin: "admin".to_string(),
            token_name: "Test NFT".to_string(),
            token_symbol: "TNFT".to_string(),
            decimals: 0,
        };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint by admin (minter)
        let mint_info = mock_info("admin", &[]);
        let msg = ExecuteMsg::Mint {
            recipient: "recipient".to_string(),
            amount: cosmwasm_std::Uint128::new(1),
        };

        let res = execute(deps.as_mut(), env, mint_info, msg).unwrap();
        assert_eq!(res.attributes.len(), 3);
    }

    #[test]
    fn test_transfer_and_burn_nft() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate with admin
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg {
            admin: "admin".to_string(),
            token_name: "Test NFT".to_string(),
            token_symbol: "TNFT".to_string(),
            decimals: 0,
        };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint to owner
        let mint_info = mock_info("admin", &[]);
        let msg = ExecuteMsg::Mint { recipient: "owner".to_string(), amount: cosmwasm_std::Uint128::new(1) };
        execute(deps.as_mut(), env.clone(), mint_info, msg).unwrap();

        // transfer by owner to new_owner
        let transfer_info = mock_info("owner", &[]);
        let transfer_msg = ExecuteMsg::Transfer { recipient: "new_owner".to_string(), amount: cosmwasm_std::Uint128::new(1) };
        let res = execute(deps.as_mut(), env.clone(), transfer_info, transfer_msg).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "transfer_nft"));

        // query tokens of new_owner and assert one exists
        let tokens = query_tokens_of_owner(deps.as_ref(), "new_owner".to_string(), None, Some(10)).unwrap();
        assert_eq!(tokens.tokens.len(), 1);
        let token_id = tokens.tokens[0].clone();

        // burn by new owner
        let burn_info = mock_info("new_owner", &[]);
        let burn_msg = ExecuteMsg::Burn { amount: cosmwasm_std::Uint128::new(1) };
        let res = execute(deps.as_mut(), env.clone(), burn_info, burn_msg).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "burn_nft"));

        // verify token no longer owned (tokens list empty)
        let tokens_after = query_tokens_of_owner(deps.as_ref(), "new_owner".to_string(), None, Some(10)).unwrap();
        assert!(tokens_after.tokens.iter().find(|t| *t == &token_id).is_none());
    }

    #[test]
    fn test_send_and_batch_transfer_nft() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate with admin
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "Test NFT".to_string(), token_symbol: "tnft".to_string(), decimals: 0 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // mint two NFTs to alice
        execute(deps.as_mut(), env.clone(), mock_info("admin", &[]), ExecuteMsg::Mint { recipient: "alice".to_string(), amount: cosmwasm_std::Uint128::new(1) }).unwrap();
        execute(deps.as_mut(), env.clone(), mock_info("admin", &[]), ExecuteMsg::Mint { recipient: "alice".to_string(), amount: cosmwasm_std::Uint128::new(1) }).unwrap();

        // send one to bob (map contract to recipient in NFT context)
        let res = execute(deps.as_mut(), env.clone(), mock_info("alice", &[]), ExecuteMsg::Send { contract: "bobwallet".to_string(), amount: cosmwasm_std::Uint128::new(1), msg: None }).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "transfer_nft"));

        // batch transfer: alice sends remaining NFTs one by one to [c1, c2] (second may fail if none left; we mint third to ensure)
        execute(deps.as_mut(), env.clone(), mock_info("admin", &[]), ExecuteMsg::Mint { recipient: "alice".to_string(), amount: cosmwasm_std::Uint128::new(1) }).unwrap();
        let res = execute(deps.as_mut(), env, mock_info("alice", &[]), ExecuteMsg::BatchTransfer { recipients: vec!["charlie1".to_string(), "charlie2".to_string()], amounts: vec![cosmwasm_std::Uint128::new(1), cosmwasm_std::Uint128::new(1)] }).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "batch_transfer_nft"));
    }

    #[test]
    fn test_batch_mint_nft() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        // instantiate with admin
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "TNFT".to_string(), token_symbol: "TN".to_string(), decimals: 0 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // batch mint by admin
        let res = execute(
            deps.as_mut(),
            env.clone(),
            mock_info("admin", &[]),
            ExecuteMsg::BatchMint { recipients: vec!["user1".to_string(), "user2".to_string(), "user3".to_string()] }
        ).unwrap();
        assert!(res.attributes.iter().any(|a| a.key == "method" && a.value == "batch_mint_nft"));

        // verify each has at least one token
        for u in ["user1", "user2", "user3"].iter() {
            let tokens = query_tokens_of_owner(deps.as_ref(), (*u).to_string(), None, Some(10)).unwrap();
            assert_eq!(tokens.tokens.len(), 1);
        }
    }

    #[test]
    fn test_mint_with_metadata_only_accepts_ipfs_cid() {
        let mut deps = mock_dependencies();
        let env = mock_env();

        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "TNFT".to_string(), token_symbol: "TN".to_string(), decimals: 0 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();

        // Accepts ipfs://CID
        let res1 = execute(
            deps.as_mut(), env.clone(), mock_info("admin", &[]),
            ExecuteMsg::MintWithMetadata { recipient: "u1".to_string(), token_uri: Some("ipfs://bafybeigdyrzt".to_string()), extension: None }
        ).unwrap();
        assert!(res1.attributes.iter().any(|a| a.key == "method" && a.value == "mint_nft_with_metadata"));

        // Accepts bare CID -> normalized to ipfs://CID
        let res2 = execute(
            deps.as_mut(), env.clone(), mock_info("admin", &[]),
            ExecuteMsg::MintWithMetadata { recipient: "u2".to_string(), token_uri: Some("bafybeigdyrztcidonlyvalue_______________________".to_string()), extension: None }
        ).unwrap();
        assert!(res2.attributes.iter().any(|a| a.key == "method" && a.value == "mint_nft_with_metadata"));

        // Reject http URL by normalizing to None; still mints but without token_uri
        let res3 = execute(
            deps.as_mut(), env, mock_info("admin", &[]),
            ExecuteMsg::MintWithMetadata { recipient: "u3".to_string(), token_uri: Some("https://example.com/too/long".to_string()), extension: None }
        ).unwrap();
        assert!(res3.attributes.iter().any(|a| a.key == "method" && a.value == "mint_nft_with_metadata"));
    }

    #[test]
    fn test_perf_mint_under_3s() {
        let mut deps = mock_dependencies();
        let env = mock_env();
        let init_info = mock_info("creator", &[]);
        let init_msg = InstantiateMsg { admin: "admin".to_string(), token_name: "TNFT".to_string(), token_symbol: "TN".to_string(), decimals: 0 };
        instantiate(deps.as_mut(), env.clone(), init_info, init_msg).unwrap();
        let start = std::time::Instant::now();
        let _ = execute(deps.as_mut(), env, mock_info("admin", &[]), ExecuteMsg::Mint { recipient: "u".to_string(), amount: cosmwasm_std::Uint128::new(1) }).unwrap();
        assert!(start.elapsed() < std::time::Duration::from_secs(3));
    }
}
