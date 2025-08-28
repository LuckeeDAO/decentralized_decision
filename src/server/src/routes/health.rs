use warp::{Filter, Rejection, Reply};

#[derive(Debug, serde::Serialize)]
struct HealthResponse {
    status: String,
    timestamp: u64,
    version: String,
}

async fn health_check() -> Result<impl Reply, Rejection> {
    let response = HealthResponse {
        status: "healthy".to_string(),
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        version: env!("CARGO_PKG_VERSION").to_string(),
    };
    Ok(warp::reply::json(&response))
}

async fn metrics() -> Result<impl Reply, Rejection> {
    let metrics = "# HELP permissions_checks_total Total permission checks\n\
           # TYPE permissions_checks_total counter\n\
           permissions_checks_total 100\n\
           # HELP ipfs_cache_hits_total Total IPFS cache hits\n\
           # TYPE ipfs_cache_hits_total counter\n\
           ipfs_cache_hits_total 80\n";
    Ok(warp::reply::with_header(metrics, "content-type", "text/plain; version=0.0.4; charset=utf-8"))
}

pub fn routes() -> warp::filters::BoxedFilter<(impl Reply,)> {
    let health_route = warp::path("health")
        .and(warp::get())
        .and_then(|| async { health_check().await })
        .boxed();

    let metrics_route = warp::path("metrics")
        .and(warp::get())
        .and_then(|| async { metrics().await })
        .boxed();

    health_route
        .or(metrics_route)
        .boxed()
}


