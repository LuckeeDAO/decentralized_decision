use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::RwLock;
use std::sync::Arc;
use std::env;

#[allow(dead_code)]
pub trait CacheStore<V: Clone + Send + Sync + 'static>: Send + Sync {
    fn get(&self, key: &str) -> Option<V>;
    fn put(&self, key: &str, val: V);
    #[allow(dead_code)]
    fn invalidate(&self, key: &str);
    #[allow(dead_code)]
    fn clear(&self);
}

pub struct InMemoryTtlCache<V: Clone + Send + Sync + 'static> {
    ttl: Duration,
    store: RwLock<HashMap<String, (V, Instant)>>,
}

impl<V: Clone + Send + Sync + 'static> InMemoryTtlCache<V> {
    pub fn new(ttl_secs: u64) -> Self {
        Self { ttl: Duration::from_secs(ttl_secs), store: RwLock::new(HashMap::new()) }
    }
}

impl<V: Clone + Send + Sync + 'static> CacheStore<V> for InMemoryTtlCache<V> {
    fn get(&self, key: &str) -> Option<V> {
        if let Ok(map) = self.store.read() {
            if let Some((v, ts)) = map.get(key) {
                if ts.elapsed() <= self.ttl { return Some(v.clone()); }
            }
        }
        None
    }
    fn put(&self, key: &str, val: V) {
        if let Ok(mut map) = self.store.write() {
            map.insert(key.to_string(), (val, Instant::now()));
        }
    }
    fn invalidate(&self, key: &str) {
        if let Ok(mut map) = self.store.write() { map.remove(key); }
    }
    fn clear(&self) {
        if let Ok(mut map) = self.store.write() { map.clear(); }
    }
}

/// 空实现：禁用缓存时使用
#[allow(dead_code)]
pub struct NullCache<V: Clone + Send + Sync + 'static>(std::marker::PhantomData<V>);
impl<V: Clone + Send + Sync + 'static> NullCache<V> { pub fn new() -> Self { Self(std::marker::PhantomData) } }
impl<V: Clone + Send + Sync + 'static> CacheStore<V> for NullCache<V> {
    fn get(&self, _key: &str) -> Option<V> { None }
    fn put(&self, _key: &str, _val: V) {}
    fn invalidate(&self, _key: &str) {}
    fn clear(&self) {}
}

/// 失效事件监听（预留给 iAgent/分布式）
#[allow(dead_code)]
pub trait InvalidationListener: Send + Sync {
    fn on_invalidate(&self, _key: &str) {}
}

#[allow(dead_code)]
#[derive(Debug)]
pub enum CacheBackend {
    InMem,
    Redis,
    Agent,
    Disabled,
}

#[allow(dead_code)]
pub fn select_backend_from_env() -> CacheBackend {
    match env::var("CACHE_ENABLED").unwrap_or_else(|_| "true".into()).to_lowercase().as_str() {
        "false" | "0" | "no" => return CacheBackend::Disabled,
        _ => {}
    }
    match env::var("CACHE_BACKEND").unwrap_or_else(|_| "inmem".into()).to_lowercase().as_str() {
        "inmem" => CacheBackend::InMem,
        "redis" => CacheBackend::Redis,
        "agent" => CacheBackend::Agent,
        _ => CacheBackend::InMem,
    }
}

/// 简单工厂：当前仅返回内存TTL或空实现；Redis/Agent 后端留待后续实现
#[allow(dead_code)]
pub fn build_cache_from_env<V: Clone + Send + Sync + 'static>() -> Arc<dyn CacheStore<V>> {
    let ttl_secs: u64 = env::var("CACHE_TTL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    match select_backend_from_env() {
        CacheBackend::Disabled => Arc::new(NullCache::new()),
        CacheBackend::InMem => Arc::new(InMemoryTtlCache::new(ttl_secs)),
        CacheBackend::Redis | CacheBackend::Agent => {
            eprintln!("[cache] backend not implemented; fallback to in-memory TTL");
            Arc::new(InMemoryTtlCache::new(ttl_secs))
        }
    }
}

/// 缓存管理器
pub struct CacheManager {
    #[allow(dead_code)]
    backend: CacheBackend,
}

impl CacheManager {
    pub fn new() -> Self {
        Self {
            backend: select_backend_from_env(),
        }
    }

    #[allow(dead_code)]
    pub fn get_backend(&self) -> &CacheBackend {
        &self.backend
    }

    #[allow(dead_code)]
    pub fn is_enabled(&self) -> bool {
        !matches!(self.backend, CacheBackend::Disabled)
    }
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}


