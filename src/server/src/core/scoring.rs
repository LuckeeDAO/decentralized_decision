//! 参与者算分系统
//!
//! 提供 `ParticipantScorer` 接口、若干内置算分器、组合算分器与工厂。

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;
use super::cache::CacheStore;

/// 算分配置（可扩展的通用KV）
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScoringConfig {
    pub scorer: String,                 // e.g. "balance", "stake_time", "nft_holdings", "composite"
    pub params: HashMap<String, f64>,   // 简化为数值型参数
    pub children: Vec<ScoringConfig>,   // 组合算分器的子配置
}

/// 算分上下文（从外部系统或预聚合中传入）
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScoringContext {
    pub attributes: HashMap<String, f64>, // 例如：balance、stake_time_days、nft_count
}

/// 算分结果（包含原始分与归一化分）
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq)]
pub struct ScoreResult {
    pub raw: f64,
    pub normalized: f64,
}

/// 参与者算分接口
pub trait ParticipantScorer: Send + Sync {
    fn score(&self, ctx: &ScoringContext) -> ScoreResult;
}

/// 基于余额的算分器
pub struct BalanceScorer { pub min: f64, pub max: f64 }
impl ParticipantScorer for BalanceScorer {
    fn score(&self, ctx: &ScoringContext) -> ScoreResult {
        let bal = *ctx.attributes.get("balance").unwrap_or(&0.0);
        let raw = bal.max(0.0);
        let denom = (self.max - self.min).max(1e-9);
        let normalized = ((raw - self.min) / denom).clamp(0.0, 1.0);
        ScoreResult { raw, normalized }
    }
}

/// 基于质押时间（天）的算分器
pub struct StakeTimeScorer { pub max_days: f64 }
impl ParticipantScorer for StakeTimeScorer {
    fn score(&self, ctx: &ScoringContext) -> ScoreResult {
        let days = *ctx.attributes.get("stake_time_days").unwrap_or(&0.0);
        let raw = days.max(0.0);
        let normalized = (raw / self.max_days.max(1e-9)).clamp(0.0, 1.0);
        ScoreResult { raw, normalized }
    }
}

/// 基于NFT持有数量的算分器
pub struct NftHoldingScorer { pub max_count: f64 }
impl ParticipantScorer for NftHoldingScorer {
    fn score(&self, ctx: &ScoringContext) -> ScoreResult {
        let cnt = *ctx.attributes.get("nft_count").unwrap_or(&0.0);
        let raw = cnt.max(0.0);
        let normalized = (raw / self.max_count.max(1e-9)).clamp(0.0, 1.0);
        ScoreResult { raw, normalized }
    }
}

/// 组合算分器：对子算分器进行加权求和并再归一化
pub struct CompositeScorer {
    pub items: Vec<(Box<dyn ParticipantScorer>, f64)>, // (scorer, weight)
}
impl ParticipantScorer for CompositeScorer {
    fn score(&self, ctx: &ScoringContext) -> ScoreResult {
        if self.items.is_empty() {
            return ScoreResult { raw: 0.0, normalized: 0.0 };
        }
        let mut weighted = 0.0;
        let mut total_w = 0.0;
        for (sc, w) in &self.items {
            let s = sc.score(ctx);
            weighted += s.normalized * *w;
            total_w += *w;
        }
        let normalized = if total_w > 0.0 { (weighted / total_w).clamp(0.0, 1.0) } else { 0.0 };
        // 将归一化分映射为原始分（此处简化为相同数值）
        ScoreResult { raw: normalized, normalized }
    }
}

/// 工厂：从配置构建算分器
pub struct ScorerFactory;
impl ScorerFactory {
    #[allow(dead_code)]
    pub fn build(cfg: &ScoringConfig) -> Result<Box<dyn ParticipantScorer>, String> {
        match cfg.scorer.as_str() {
            "balance" => {
                let min = *cfg.params.get("min").unwrap_or(&0.0);
                let max = *cfg.params.get("max").unwrap_or(&1000.0);
                if max <= min { return Err("balance scorer参数错误：max必须大于min".into()); }
                Ok(Box::new(BalanceScorer { min, max }))
            }
            "stake_time" => {
                let max_days = *cfg.params.get("max_days").unwrap_or(&365.0);
                Ok(Box::new(StakeTimeScorer { max_days }))
            }
            "nft_holdings" => {
                let max_count = *cfg.params.get("max_count").unwrap_or(&100.0);
                Ok(Box::new(NftHoldingScorer { max_count }))
            }
            "composite" => {
                // 读取每个子配置的weight参数
                let mut items = Vec::new();
                for child in &cfg.children {
                    let w = *child.params.get("weight").unwrap_or(&1.0);
                    let sc = Self::build(child)?;
                    items.push((sc, w));
                }
                Ok(Box::new(CompositeScorer { items }))
            }
            _ => Err(format!("未知scorer: {}", cfg.scorer)),
        }
    }

    /// 基础参数校验（非JSON Schema简化版）
    #[allow(dead_code)]
    pub fn validate(cfg: &ScoringConfig) -> Result<(), String> {
        match cfg.scorer.as_str() {
            "balance" => {
                let max = *cfg.params.get("max").unwrap_or(&1000.0);
                let min = *cfg.params.get("min").unwrap_or(&0.0);
                if max <= min { return Err("balance: max 必须大于 min".into()); }
                Ok(())
            }
            "stake_time" => {
                let max_days = *cfg.params.get("max_days").unwrap_or(&365.0);
                if max_days <= 0.0 { return Err("stake_time: max_days 必须大于 0".into()); }
                Ok(())
            }
            "nft_holdings" => {
                let max_count = *cfg.params.get("max_count").unwrap_or(&100.0);
                if max_count < 0.0 { return Err("nft_holdings: max_count 不可为负".into()); }
                Ok(())
            }
            "composite" => {
                if cfg.children.is_empty() { return Err("composite: children 不可为空".into()); }
                for child in &cfg.children { Self::validate(child)?; }
                Ok(())
            }
            other => Err(format!("未知scorer: {}", other)),
        }
    }
}

/// 简单的批量算分与缓存（进程内）
#[allow(dead_code)]
#[derive(Default)]
pub struct ScoreCache { store: HashMap<String, ScoreResult> }
impl ScoreCache {
    #[allow(dead_code)]
    pub fn get_or_compute(
        &mut self,
        pid: &str,
        ctx: &ScoringContext,
        scorer: &dyn ParticipantScorer,
    ) -> ScoreResult {
        if let Some(s) = self.store.get(pid) { return s.clone(); }
        let s = scorer.score(ctx);
        self.store.insert(pid.to_string(), s.clone());
        s
    }
}

/// 带TTL的批量算分缓存
#[allow(dead_code)]
pub struct TtlScoreCache {
    ttl: Duration,
    store: HashMap<String, (ScoreResult, Instant)>,
    hit_count: u64,
    miss_count: u64,
}

impl TtlScoreCache {
    #[allow(dead_code)]
    pub fn new_ttl(ttl_secs: u64) -> Self {
        Self { ttl: Duration::from_secs(ttl_secs), store: HashMap::new(), hit_count: 0, miss_count: 0 }
    }

    #[allow(dead_code)]
    fn get(&mut self, pid: &str) -> Option<ScoreResult> {
        if let Some((res, ts)) = self.store.get(pid) {
            if ts.elapsed() <= self.ttl { return Some(res.clone()); }
        }
        None
    }

    #[allow(dead_code)]
    fn put(&mut self, pid: &str, res: ScoreResult) {
        self.store.insert(pid.to_string(), (res, Instant::now()));
    }

    /// 批量算分（带TTL缓存）。输入为 pid -> ScoringContext
    #[allow(dead_code)]
    pub fn batch_score(
        &mut self,
        inputs: &HashMap<String, ScoringContext>,
        scorer: &dyn ParticipantScorer,
    ) -> HashMap<String, ScoreResult> {
        let mut out = HashMap::new();
        for (pid, ctx) in inputs {
            if let Some(cached) = self.get(pid) {
                self.hit_count += 1;
                out.insert(pid.clone(), cached);
                continue;
            }
            self.miss_count += 1;
            let res = scorer.score(ctx);
            self.put(pid, res.clone());
            out.insert(pid.clone(), res);
        }
        out
    }
}

impl TtlScoreCache {
    #[allow(dead_code)]
    pub fn counters(&self) -> (u64, u64) { (self.hit_count, self.miss_count) }

    #[allow(dead_code)]
    pub fn reset_counters(&mut self) { self.hit_count = 0; self.miss_count = 0; }
}

/// 基于通用缓存抽象的批量算分辅助
#[allow(dead_code)]
pub struct CachedScoringHelper<C: CacheStore<ScoreResult>> {
    pub cache: Arc<C>,
}

impl<C: CacheStore<ScoreResult>> CachedScoringHelper<C> {
    #[allow(dead_code)]
    pub fn new(cache: Arc<C>) -> Self { Self { cache } }

    /// key 设计建议：participant_id + ":" + cfg_version_hash
    #[allow(dead_code)]
    pub fn batch_score_with_cache(
        &self,
        inputs: &HashMap<String, (ScoringContext, String)>, // pid -> (ctx, cfg_version)
        scorer: &dyn ParticipantScorer,
    ) -> HashMap<String, ScoreResult> {
        let mut out = HashMap::new();
        for (pid, (ctx, cfg_ver)) in inputs {
            let key = format!("{}:{}", pid, cfg_ver);
            if let Some(hit) = self.cache.get(&key) {
                out.insert(pid.clone(), hit);
                continue;
            }
            let res = scorer.score(ctx);
            self.cache.put(&key, res.clone());
            out.insert(pid.clone(), res);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core::cache::InMemoryTtlCache;

    #[test]
    fn test_build_and_score() {
        let cfg = ScoringConfig { scorer: "composite".into(), params: HashMap::new(), children: vec![
            ScoringConfig { scorer: "balance".into(), params: HashMap::from([("min".into(), 0.0), ("max".into(), 1000.0), ("weight".into(), 0.7)]), children: vec![] },
            ScoringConfig { scorer: "stake_time".into(), params: HashMap::from([("max_days".into(), 365.0), ("weight".into(), 0.3)]), children: vec![] },
        ]};
        let scorer = ScorerFactory::build(&cfg).unwrap();
        let ctx = ScoringContext { attributes: HashMap::from([
            ("balance".into(), 500.0),
            ("stake_time_days".into(), 180.0),
        ]) };
        let s = scorer.score(&ctx);
        assert!(s.normalized > 0.4 && s.normalized < 0.9);
    }

    #[test]
    fn test_validate_configs() {
        let ok = ScoringConfig { scorer: "balance".into(), params: HashMap::from([
            ("min".into(), 0.0), ("max".into(), 100.0)
        ]), children: vec![] };
        assert!(ScorerFactory::validate(&ok).is_ok());

        let bad = ScoringConfig { scorer: "balance".into(), params: HashMap::from([
            ("min".into(), 100.0), ("max".into(), 50.0)
        ]), children: vec![] };
        assert!(ScorerFactory::validate(&bad).is_err());

        let comp = ScoringConfig { scorer: "composite".into(), params: HashMap::new(), children: vec![
            ScoringConfig { scorer: "stake_time".into(), params: HashMap::from([
                ("max_days".into(), 365.0), ("weight".into(), 1.0)
            ]), children: vec![] }
        ]};
        assert!(ScorerFactory::validate(&comp).is_ok());
    }

    #[test]
    fn test_batch_scoring_with_ttl_cache() {
        let cfg = ScoringConfig { scorer: "stake_time".into(), params: HashMap::from([
            ("max_days".into(), 365.0)
        ]), children: vec![] };
        let scorer = ScorerFactory::build(&cfg).unwrap();
        let mut cache = TtlScoreCache::new_ttl(1); // 1s TTL

        let inputs = HashMap::from([
            ("u1".into(), ScoringContext { attributes: HashMap::from([("stake_time_days".into(), 30.0)]) }),
            ("u2".into(), ScoringContext { attributes: HashMap::from([("stake_time_days".into(), 180.0)]) }),
        ]);

        let r1 = cache.batch_score(&inputs, scorer.as_ref());
        let r2 = cache.batch_score(&inputs, scorer.as_ref());
        // 命中缓存，结果一致
        assert_eq!(r1.get("u1").unwrap().normalized, r2.get("u1").unwrap().normalized);
    }

    #[test]
    fn test_cached_scoring_helper_with_store() {
        let cfg = ScoringConfig { scorer: "balance".into(), params: HashMap::from([
            ("min".into(), 0.0), ("max".into(), 1000.0)
        ]), children: vec![] };
        let scorer = ScorerFactory::build(&cfg).unwrap();

        let cache: Arc<InMemoryTtlCache<ScoreResult>> = Arc::new(InMemoryTtlCache::new(5));
        let helper = CachedScoringHelper::new(cache.clone());

        let inputs = HashMap::from([
            ("p1".into(), (ScoringContext { attributes: HashMap::from([("balance".into(), 200.0)]) }, "v1".into())),
            ("p2".into(), (ScoringContext { attributes: HashMap::from([("balance".into(), 800.0)]) }, "v1".into())),
        ]);

        let r1 = helper.batch_score_with_cache(&inputs, scorer.as_ref());
        let r2 = helper.batch_score_with_cache(&inputs, scorer.as_ref());

        assert_eq!(r1.get("p1").unwrap().normalized, r2.get("p1").unwrap().normalized);
    }

    #[test]
    fn test_batch_scoring_perf_1k_under_2s() {
        let cfg = ScoringConfig { scorer: "stake_time".into(), params: HashMap::from([
            ("max_days".into(), 365.0)
        ]), children: vec![] };
        let scorer = ScorerFactory::build(&cfg).unwrap();
        let mut cache = TtlScoreCache::new_ttl(2);

        let mut inputs: HashMap<String, ScoringContext> = HashMap::new();
        for i in 0..1000 {
            inputs.insert(format!("u{}", i), ScoringContext { attributes: HashMap::from([
                ("stake_time_days".into(), (i % 365) as f64)
            ]) });
        }

        let start = Instant::now();
        let res = cache.batch_score(&inputs, scorer.as_ref());
        assert_eq!(res.len(), 1000);
        let elapsed = start.elapsed();
        assert!(elapsed.as_secs_f64() < 2.0, "1k batch scoring took {:?}", elapsed);
    }

    #[test]
    fn test_batch_scoring_cache_hit_rate_and_10k_under_15s() {
        let cfg = ScoringConfig { scorer: "balance".into(), params: HashMap::from([
            ("min".into(), 0.0), ("max".into(), 100000.0)
        ]), children: vec![] };
        let scorer = ScorerFactory::build(&cfg).unwrap();
        let mut cache = TtlScoreCache::new_ttl(60);

        // prepare 10k
        let mut inputs: HashMap<String, ScoringContext> = HashMap::new();
        for i in 0..10_000 {
            inputs.insert(format!("u{}", i), ScoringContext { attributes: HashMap::from([
                ("balance".into(), (i * 7 % 100_000) as f64)
            ]) });
        }

        // first run
        let start1 = Instant::now();
        let r1 = cache.batch_score(&inputs, scorer.as_ref());
        assert_eq!(r1.len(), 10_000);
        let t1 = start1.elapsed();

        // second run should be mostly hits
        let start2 = Instant::now();
        cache.reset_counters();
        let r2 = cache.batch_score(&inputs, scorer.as_ref());
        let _t2 = start2.elapsed();
        assert_eq!(r2.len(), 10_000);

        // perf gates（首轮在阈值内；二轮主要以命中率衡量，避免偶发抖动影响）
        assert!(t1.as_secs_f64() < 15.0, "10k first batch took {:?}", t1);

        // hit rate >= 80%
        let (hits, misses) = cache.counters();
        let total = hits + misses;
        assert!(total > 0);
        let hit_rate = hits as f64 / total as f64;
        assert!(hit_rate >= 0.80, "hit rate {:.2}% (<80%)", hit_rate * 100.0);
    }
}


