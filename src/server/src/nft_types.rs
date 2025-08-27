//! NFT 类型接口与注册表

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

/// 类型元信息
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftTypeMeta {
    pub type_id: String,
    pub name: String,
    pub category: String, // 抽奖、彩票、分配、治理等
    /// 最低权限等级要求: basic/creator/admin（可选）
    #[serde(default)]
    pub required_level: Option<String>,
}

/// 某版本Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftTypeSchemaVersion {
    pub version: u32,
    pub schema: serde_json::Value,
    pub timestamp: u64,
}

/// 类型定义：包含元信息与多版本Schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NftTypeDef {
    pub meta: NftTypeMeta,
    pub versions: Vec<NftTypeSchemaVersion>,
}

/// 类型注册表：type_id -> 定义
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct NftTypeRegistry {
    pub types: HashMap<String, NftTypeDef>,
}

impl NftTypeRegistry {
    pub fn new() -> Self { Self { types: HashMap::new() } }

    pub fn list(&self) -> Vec<NftTypeMeta> {
        self.types.values().map(|d| d.meta.clone()).collect()
    }

    pub fn get(&self, type_id: &str) -> Option<NftTypeDef> {
        self.types.get(type_id).cloned()
    }

    pub fn register_or_update(&mut self, meta: NftTypeMeta, schema: serde_json::Value, now: u64) -> &NftTypeDef {
        let entry = self.types.entry(meta.type_id.clone()).or_insert(NftTypeDef { meta: meta.clone(), versions: Vec::new() });
        let next_ver: u32 = entry.versions.last().map(|v| v.version + 1).unwrap_or(1);
        entry.meta = meta;
        entry.versions.push(NftTypeSchemaVersion { version: next_ver, schema, timestamp: now });
        entry
    }

    pub fn list_versions(&self, type_id: &str) -> Option<Vec<(u32, u64)>> {
        self.types.get(type_id).map(|def| def.versions.iter().map(|v| (v.version, v.timestamp)).collect())
    }

    pub fn get_schema_by_version(&self, type_id: &str, version: u32) -> Option<serde_json::Value> {
        self.types.get(type_id).and_then(|def| def.versions.iter().find(|v| v.version == version).map(|v| v.schema.clone()))
    }

    pub fn rollback_to_version(&mut self, type_id: &str, version: u32) -> Result<&NftTypeDef, String> {
        let def = self.types.get_mut(type_id).ok_or_else(|| "未找到类型".to_string())?;
        // 确认存在该版本
        if !def.versions.iter().any(|v| v.version == version) {
            return Err("版本未找到".to_string());
        }
        def.versions.retain(|v| v.version <= version);
        Ok(def)
    }
}

/// NFT 类型插件接口（插件化扩展）
pub trait NftTypePlugin: Send + Sync {
    /// 自定义的元数据附加校验（在Schema校验之后调用）
    fn on_validate_metadata(&self, _metadata: &serde_json::Value) -> Result<(), String> { Ok(()) }
    /// 配置存储前的业务校验钩子（如抽奖配置的业务规则）
    fn on_before_store_config(&self, _config: &serde_json::Value) -> Result<(), String> { Ok(()) }
}

/// 空实现（默认插件）
pub struct NoopPlugin;
impl NftTypePlugin for NoopPlugin {}

/// 插件注册表：type_id -> 插件实例
#[derive(Default, Clone)]
pub struct NftTypePluginRegistry {
    pub plugins: HashMap<String, Arc<dyn NftTypePlugin>>,
}

impl NftTypePluginRegistry {
    pub fn new() -> Self { Self { plugins: HashMap::new() } }

    pub fn register(&mut self, type_id: String, plugin: Arc<dyn NftTypePlugin>) {
        self.plugins.insert(type_id, plugin);
    }

    pub fn get(&self, type_id: &str) -> Option<Arc<dyn NftTypePlugin>> {
        self.plugins.get(type_id).cloned()
    }
}

/// NFT 类型接口设计：抽象统一访问与校验能力
pub trait TypeInterface {
    /// 返回类型ID
    #[allow(dead_code)]
    fn type_id(&self) -> &str;
    /// 返回类型元信息
    #[allow(dead_code)]
    fn meta(&self) -> &NftTypeMeta;
    /// 返回最新的Schema（若存在）
    fn latest_schema(&self) -> Option<&serde_json::Value>;
    /// 使用最新Schema校验给定元数据
    #[allow(dead_code)]
    fn validate_with_latest(&self, data: &serde_json::Value) -> Result<(), Vec<String>>;
}

impl TypeInterface for NftTypeDef {
    fn type_id(&self) -> &str { &self.meta.type_id }
    fn meta(&self) -> &NftTypeMeta { &self.meta }
    fn latest_schema(&self) -> Option<&serde_json::Value> { self.versions.last().map(|v| &v.schema) }
    fn validate_with_latest(&self, data: &serde_json::Value) -> Result<(), Vec<String>> {
        if let Some(schema) = self.latest_schema() {
            match jsonschema::JSONSchema::options().with_draft(jsonschema::Draft::Draft7).compile(schema) {
                Ok(compiled) => match compiled.validate(data) {
                    Ok(()) => Ok(()),
                    Err(errors) => Err(errors.map(|e| e.to_string()).collect()),
                },
                Err(e) => Err(vec![e.to_string()]),
            }
        } else {
            Err(vec!["类型未包含schema".to_string()])
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    fn sample_schema_v1() -> serde_json::Value {
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "prize": {"type": "integer"}
            },
            "required": ["name", "prize"]
        })
    }

    fn sample_schema_v2() -> serde_json::Value {
        serde_json::json!({
            "$schema": "http://json-schema.org/draft-07/schema#",
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "prize": {"type": "integer"},
                "category": {"type": "string"}
            },
            "required": ["name", "prize"]
        })
    }

    #[test]
    fn test_registry_register_version_and_rollback() {
        let mut reg = NftTypeRegistry::new();
        let meta = NftTypeMeta { type_id: "lottery".into(), name: "抽奖".into(), category: "抽奖".into(), required_level: Some("creator".into()) };
        let now = 1_700_000_000u64;

        // register v1
        let def = reg.register_or_update(meta.clone(), sample_schema_v1(), now);
        assert_eq!(def.meta.type_id, "lottery");
        assert_eq!(def.versions.len(), 1);
        assert_eq!(def.versions[0].version, 1);

        // register v2
        let def2 = reg.register_or_update(meta.clone(), sample_schema_v2(), now + 10);
        assert_eq!(def2.versions.len(), 2);
        assert_eq!(def2.versions[1].version, 2);

        // list versions
        let vers = reg.list_versions("lottery").unwrap();
        assert_eq!(vers.len(), 2);

        // rollback to v1
        let rolled = reg.rollback_to_version("lottery", 1).unwrap();
        assert_eq!(rolled.versions.len(), 1);
        assert_eq!(rolled.versions[0].version, 1);
    }

    #[test]
    fn test_schema_validation() {
        let mut reg = NftTypeRegistry::new();
        let meta = NftTypeMeta { type_id: "lottery".into(), name: "抽奖".into(), category: "抽奖".into(), required_level: None };
        let _ = reg.register_or_update(meta.clone(), sample_schema_v1(), 1_700_000_000);
        let def = reg.get("lottery").unwrap();

        // valid data
        let data_ok = serde_json::json!({"name": "A", "prize": 100});
        assert!(def.validate_with_latest(&data_ok).is_ok());

        // invalid data: missing prize
        let data_bad = serde_json::json!({"name": "A"});
        assert!(def.validate_with_latest(&data_bad).is_err());
    }
}

