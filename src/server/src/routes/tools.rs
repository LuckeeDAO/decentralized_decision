use crate::state::ServerState;
use crate::types::ApiResponse;
use crate::utils::with_state;
use jsonschema::{Draft, JSONSchema};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use warp::{Filter, Rejection, Reply};

/// JSON Schema 校验请求
#[derive(Debug, Deserialize)]
pub struct SchemaValidateRequest {
    pub schema: serde_json::Value,
    pub data: serde_json::Value,
}

/// JSON Schema 校验响应
#[derive(Debug, Serialize)]
pub struct SchemaValidateResponse {
    pub valid: bool,
    pub errors: Vec<String>,
}

/// JSON Schema 校验
pub fn validate_json_schema(_state: Arc<ServerState>, req: SchemaValidateRequest) -> impl Reply {
    match JSONSchema::options().with_draft(Draft::Draft7).compile(&req.schema) {
        Ok(compiled) => {
            let result = compiled.validate(&req.data);
            match result {
                Ok(_) => warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: true, errors: vec![] })),
                Err(errors) => {
                    let errs = errors.map(|e| e.to_string()).collect::<Vec<_>>();
                    warp::reply::json(&ApiResponse::success(SchemaValidateResponse { valid: false, errors: errs }))
                }
            }
        }
        Err(e) => warp::reply::json(&ApiResponse::<()>::error(e.to_string())),
    }
}

/// 读取某token元数据版本列表
pub async fn list_metadata_versions(state: Arc<ServerState>, token_id: String) -> Result<impl Reply, Rejection> {
    let reg = state.metadata_versions.read().await;
    let list = reg.get(&token_id).cloned().unwrap_or_default();
    Ok(warp::reply::json(&ApiResponse::success(list)))
}

/// 创建工具路由
pub fn routes(state: Arc<ServerState>) -> warp::filters::BoxedFilter<(impl Reply,)> {
    // Schema校验
    let schema_validate_route = {
        let state = Arc::clone(&state);
        warp::path!("schema" / "validate")
            .and(warp::post())
            .and(warp::body::json())
            .and(with_state(state))
            .and_then(|request: SchemaValidateRequest, state: Arc<ServerState>| async move { 
                Ok::<_, Rejection>(validate_json_schema(state, request))
            })
            .boxed()
    };

    // 元数据版本列表
    let meta_versions_route = {
        let state = Arc::clone(&state);
        warp::path!("metadata" / String / "versions")
            .and(warp::get())
            .and(warp::any().map(move || Arc::clone(&state)))
            .and_then(|token_id: String, state: Arc<ServerState>| async move { list_metadata_versions(state, token_id).await })
            .boxed()
    };

    schema_validate_route
        .or(meta_versions_route)
        .boxed()
}
