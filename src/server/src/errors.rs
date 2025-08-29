use std::convert::Infallible;
use warp::{Rejection, Reply};
use tracing::error;

use crate::types::ApiResponse;
use warp::reject::Reject;

#[derive(Debug)]
pub enum ServerError {
    ServiceUnavailable,
    BadRequest,
}

impl Reject for ServerError {}

pub async fn handle_rejection(err: Rejection) -> Result<impl Reply, Infallible> {
    let (code, message) = if err.is_not_found() {
        (warp::http::StatusCode::NOT_FOUND, "Not Found")
    } else if err.find::<warp::reject::PayloadTooLarge>().is_some() {
        (warp::http::StatusCode::BAD_REQUEST, "Payload too large")
    } else {
        error!("未处理的错误: {:?}", err);
        (warp::http::StatusCode::INTERNAL_SERVER_ERROR, "Internal Server Error")
    };
    let response = ApiResponse::<()>::error(message.to_string());
    Ok(warp::reply::with_status(warp::reply::json(&response), code))
}


