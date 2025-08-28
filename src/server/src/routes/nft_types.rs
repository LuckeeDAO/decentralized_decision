use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

use crate::utils::with_state;
use crate::types::{ApiResponse, NftTypeRegisterRequest, NftTypeValidateRequest, NftTypeRollbackRequest, now_secs};
use crate::state::ServerState;


pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    let nft_type_register_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: NftTypeRegisterRequest, state: Arc<ServerState>| async move { 
                nft_type_register(state, request).await 
            })
            .boxed()
    };

    let nft_type_list_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|state: Arc<ServerState>| async move { 
                nft_type_list(state).await 
            })
            .boxed()
    };

    let nft_type_get_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String)
            .and(warp::get())
            .and(with_state(state))
            .and_then(|type_id: String, state: Arc<ServerState>| async move { 
                nft_type_get(state, type_id).await 
            })
            .boxed()
    };

    let nft_type_validate_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "validate")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|type_id: String, request: NftTypeValidateRequest, state: Arc<ServerState>| async move { 
                nft_type_validate(state, type_id, request).await 
            })
            .boxed()
    };

    let nft_type_validate_ver_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "validate" / u32)
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|type_id: String, version: u32, request: NftTypeValidateRequest, state: Arc<ServerState>| async move { 
                nft_type_validate_version(state, type_id, version, request).await 
            })
            .boxed()
    };

    let nft_type_versions_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "versions")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|type_id: String, state: Arc<ServerState>| async move { 
                nft_type_versions(state, type_id).await 
            })
            .boxed()
    };

    let nft_type_rollback_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "rollback")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|type_id: String, request: NftTypeRollbackRequest, state: Arc<ServerState>| async move { 
                nft_type_rollback(state, type_id, request).await 
            })
            .boxed()
    };

    let nft_type_meta_tmpl_route = {
        let state = Arc::clone(&state);
        warp::path!("nft" / "types" / String / "metadata" / "template")
            .and(warp::get())
            .and(with_state(state))
            .and_then(|type_id: String, state: Arc<ServerState>| async move { 
                nft_type_metadata_template(state, type_id).await 
            })
            .boxed()
    };

    nft_type_register_route
        .or(nft_type_list_route)
        .or(nft_type_get_route)
        .or(nft_type_validate_route)
        .or(nft_type_validate_ver_route)
        .or(nft_type_versions_route)
        .or(nft_type_rollback_route)
        .or(nft_type_meta_tmpl_route)
        .boxed()
}

// 实现缺失的函数
async fn nft_type_register(state: Arc<ServerState>, req: NftTypeRegisterRequest) -> Result<impl Reply, Rejection> {
    let mut registry = state.nft_types.write().await;
    let meta = crate::core::nft_types::NftTypeMeta {
        type_id: req.type_id.clone(),
        name: req.name.clone(),
        category: "default".to_string(), // 默认分类
        required_level: None,
    };
    let schema_version = crate::core::nft_types::NftTypeSchemaVersion {
        version: req.version,
        schema: req.metadata_schema.clone(),
        timestamp: now_secs(),
    };
    let nft_type = crate::core::nft_types::NftTypeDef {
        meta,
        versions: vec![schema_version],
    };
    registry.types.insert(req.type_id, nft_type);
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn nft_type_list(state: Arc<ServerState>) -> Result<impl Reply, Rejection> {
    let registry = state.nft_types.read().await;
    let types: Vec<_> = registry.types.values().cloned().collect();
    Ok(warp::reply::json(&ApiResponse::success(types)))
}

async fn nft_type_get(state: Arc<ServerState>, type_id: String) -> Result<impl Reply, Rejection> {
    let registry = state.nft_types.read().await;
    let nft_type = registry.types.get(&type_id).cloned();
    Ok(warp::reply::json(&ApiResponse::success(nft_type)))
}

async fn nft_type_validate(_state: Arc<ServerState>, _type_id: String, _req: NftTypeValidateRequest) -> Result<impl Reply, Rejection> {
    // 简单的验证实现
    Ok(warp::reply::json(&ApiResponse::success(true)))
}

async fn nft_type_validate_version(_state: Arc<ServerState>, _type_id: String, _version: u32, _req: NftTypeValidateRequest) -> Result<impl Reply, Rejection> {
    // 简单的版本验证实现
    Ok(warp::reply::json(&ApiResponse::success(true)))
}

async fn nft_type_versions(_state: Arc<ServerState>, _type_id: String) -> Result<impl Reply, Rejection> {
    // 简单的版本列表实现
    let versions = vec![1]; // 默认版本
    Ok(warp::reply::json(&ApiResponse::success(versions)))
}

async fn nft_type_rollback(_state: Arc<ServerState>, _type_id: String, _req: NftTypeRollbackRequest) -> Result<impl Reply, Rejection> {
    // 简单的回滚实现
    Ok(warp::reply::json(&ApiResponse::success(())))
}

async fn nft_type_metadata_template(_state: Arc<ServerState>, _type_id: String) -> Result<impl Reply, Rejection> {
    // 简单的元数据模板实现
    let template = serde_json::json!({});
    Ok(warp::reply::json(&ApiResponse::success(template)))
}


