#![allow(dead_code)]
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use std::env;
use redis::{Client, Connection, Commands};
use serde::{Serialize, Deserialize};

/// 缓存存储接口
pub trait CacheStore<V: Clone + Send + Sync + 'static>: Send + Sync {
    fn get(&self, key: &str) -> Option<V>;
    fn put(&self, key: &str, val: V);
    fn invalidate(&self, key: &str);
    fn clear(&self);
}

/// 内存缓存实现
pub struct InMemoryTtlCache<V: Clone + Send + Sync + 'static> {
    data: Arc<std::sync::RwLock<HashMap<String, (V, std::time::Instant)>>>,
    ttl: Duration,
}

impl<V: Clone + Send + Sync + 'static> InMemoryTtlCache<V> {
    pub fn new(ttl_secs: u64) -> Self {
        Self {
            data: Arc::new(std::sync::RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    #[allow(dead_code)]
    fn cleanup_expired(&self) {
        if let Ok(mut data) = self.data.write() {
            let now = std::time::Instant::now();
            data.retain(|_, (_, timestamp)| now.duration_since(*timestamp) < self.ttl);
        }
    }
}

impl<V: Clone + Send + Sync + 'static> CacheStore<V> for InMemoryTtlCache<V> {
    fn get(&self, key: &str) -> Option<V> {
        if let Ok(data) = self.data.read() {
            let now = std::time::Instant::now();
            if let Some((value, timestamp)) = data.get(key) {
                if now.duration_since(*timestamp) < self.ttl {
                    return Some(value.clone());
                }
            }
        }
        None
    }

    fn put(&self, key: &str, val: V) {
        if let Ok(mut data) = self.data.write() {
            data.insert(key.to_string(), (val, std::time::Instant::now()));
        }
    }

    fn invalidate(&self, key: &str) {
        if let Ok(mut data) = self.data.write() {
            data.remove(key);
        }
    }

    fn clear(&self) {
        if let Ok(mut data) = self.data.write() {
            data.clear();
        }
    }
}

/// 缓存管理器
pub struct CacheManager {
    memory_cache: Arc<InMemoryTtlCache<String>>,
    redis_cache: Option<Arc<RedisCache<String>>>,
}

impl CacheManager {
    pub fn new() -> Self {
        Self {
            memory_cache: Arc::new(InMemoryTtlCache::new(300)), // 5分钟TTL
            redis_cache: None,
        }
    }

    pub fn with_redis(redis_url: &str, ttl_secs: u64) -> Result<Self, redis::RedisError> {
        let redis_cache = Arc::new(RedisCache::new(redis_url, ttl_secs)?);
        Ok(Self {
            memory_cache: Arc::new(InMemoryTtlCache::new(ttl_secs)),
            redis_cache: Some(redis_cache),
        })
    }

    pub async fn get(&self, key: &str) -> Option<String> {
        // 先尝试内存缓存
        if let Some(value) = self.memory_cache.get(key) {
            return Some(value);
        }

        // 如果内存缓存没有，尝试Redis缓存
        if let Some(redis_cache) = &self.redis_cache {
            if let Some(value) = redis_cache.get(key) {
                // 将值存入内存缓存
                self.memory_cache.put(key, value.clone());
                return Some(value);
            }
        }

        None
    }

    pub async fn put(&self, key: &str, value: String) {
        // 同时存入内存和Redis缓存
        self.memory_cache.put(key, value.clone());
        if let Some(redis_cache) = &self.redis_cache {
            let _ = redis_cache.put(key, value);
        }
    }

    pub async fn invalidate(&self, key: &str) {
        self.memory_cache.invalidate(key);
        if let Some(redis_cache) = &self.redis_cache {
            redis_cache.invalidate(key);
        }
    }

    pub async fn clear(&self) {
        self.memory_cache.clear();
        if let Some(redis_cache) = &self.redis_cache {
            redis_cache.clear();
        }
    }

    /// 检查缓存是否启用
    pub fn is_enabled(&self) -> bool {
        true // 总是启用
    }

    /// 获取缓存后端类型
    pub fn get_backend(&self) -> &'static str {
        if self.redis_cache.is_some() {
            "redis"
        } else {
            "memory"
        }
    }
}

/// Redis缓存实现
pub struct RedisCache<V: Clone + Send + Sync + 'static> {
    client: Client,
    ttl: Duration,
    _phantom: std::marker::PhantomData<V>,
}

impl<V: Clone + Send + Sync + 'static> RedisCache<V> {
    pub fn new(redis_url: &str, ttl_secs: u64) -> Result<Self, redis::RedisError> {
        let client = Client::open(redis_url)?;
        Ok(Self {
            client,
            ttl: Duration::from_secs(ttl_secs),
            _phantom: std::marker::PhantomData,
        })
    }

    fn get_connection(&self) -> Result<Connection, redis::RedisError> {
        self.client.get_connection()
    }
}

impl<V: Clone + Send + Sync + 'static> CacheStore<V> for RedisCache<V> 
where 
    V: Serialize + for<'de> Deserialize<'de>,
{
    fn get(&self, key: &str) -> Option<V> {
        let mut conn = match self.get_connection() {
            Ok(conn) => conn,
            Err(_) => return None,
        };
        
        // 直接使用 from_str 反序列化
        match conn.get::<&str, String>(key) {
            Ok(data) => serde_json::from_str(&data).ok(),
            Err(_) => None,
        }
    }

    fn put(&self, key: &str, val: V) {
        let mut conn = match self.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        
        // 序列化并存储数据
        if let Ok(data) = serde_json::to_string(&val) {
            let _: Result<(), redis::RedisError> = conn.set_ex(key, data, self.ttl.as_secs() as u64);
        }
    }

    fn invalidate(&self, key: &str) {
        let mut conn = match self.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        
        let _: Result<(), redis::RedisError> = conn.del(key);
    }

    fn clear(&self) {
        let mut conn = match self.get_connection() {
            Ok(conn) => conn,
            Err(_) => return,
        };
        
        // 使用 FLUSHDB 命令清空当前数据库
        let _ = redis::cmd("FLUSHDB").execute(&mut conn);
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

/// 缓存工厂：支持Redis后端
pub fn build_cache_from_env<V: Clone + Send + Sync + 'static>() -> Arc<dyn CacheStore<V>> 
where 
    V: Serialize + for<'de> Deserialize<'de>,
{
    let ttl_secs: u64 = env::var("CACHE_TTL_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(5);
    match select_backend_from_env() {
        CacheBackend::Disabled => Arc::new(NullCache::new()),
        CacheBackend::InMem => Arc::new(InMemoryTtlCache::new(ttl_secs)),
        CacheBackend::Redis => {
            let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
            match RedisCache::new(&redis_url, ttl_secs) {
                Ok(cache) => Arc::new(cache),
                Err(_) => {
                    eprintln!("Failed to connect to Redis, falling back to in-memory cache");
                    Arc::new(InMemoryTtlCache::new(ttl_secs))
                }
            }
        }
        CacheBackend::Agent => {
            eprintln!("Agent cache not implemented yet, falling back to in-memory cache");
            Arc::new(InMemoryTtlCache::new(ttl_secs))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test(flavor = "current_thread")] 
    async fn test_in_memory_cache() {
        let cache = InMemoryTtlCache::<String>::new(1);
        
        cache.put("test_key", "test_value".to_string());
        // 等待异步写入完成
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(cache.get("test_key"), Some("test_value".to_string()));
        
        cache.invalidate("test_key");
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        assert_eq!(cache.get("test_key"), None);
    }

    #[tokio::test(flavor = "current_thread")] 
    async fn test_null_cache() {
        let cache = NullCache::<String>::new();
        
        cache.put("test_key", "test_value".to_string());
        assert_eq!(cache.get("test_key"), None);
    }
}


