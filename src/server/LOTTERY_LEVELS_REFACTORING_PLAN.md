# Lottery Levels 模块重构计划

## 📋 文件概览

**文件路径**: `src/server/src/core/lottery_levels.rs`  
**当前行数**: 800行  
**主要功能**: 抽奖等级系统的核心实现  
**重构目标**: 拆分为5个独立模块，每个模块职责单一

## 🔍 当前结构分析

### 1. 数据结构定义 (约150行)
- `LotteryLevel` - 抽奖等级主结构体
- `LevelParameters` - 等级参数配置
- `SelectionAlgorithm` - 选择算法枚举
- `LevelPermissions` - 等级权限要求
- `LevelStatus` - 等级状态枚举
- `ParticipantInfo` - 参与者信息结构

### 2. 验证器模块 (约220行)
- `LevelValidator` - 等级数据验证器
- JSON Schema 验证逻辑
- 业务规则验证
- 算法参数验证

### 3. 管理器模块 (约200行)
- `LevelManager` - 等级管理器
- CRUD 操作实现
- 优先级管理
- 状态更新逻辑

### 4. 参与者管理 (约100行)
- 参与者资格验证
- 权限检查逻辑
- 余额和时间验证

### 5. 测试代码 (约130行)
- 单元测试
- 集成测试
- 测试数据构建

## 🎯 重构目标

### 1. 模块化设计
- 每个模块职责单一
- 模块间依赖关系清晰
- 接口设计稳定

### 2. 代码质量提升
- 提高可读性和可维护性
- 支持独立测试
- 便于代码审查

### 3. 团队协作优化
- 支持并行开发
- 减少代码冲突
- 提高开发效率

## 🏗️ 重构后结构设计

```
src/server/src/core/lottery_levels/
├── mod.rs              # 模块导出和公共接口
├── types.rs            # 数据结构定义
├── validator.rs        # 验证器实现
├── manager.rs          # 管理器实现
├── participant.rs      # 参与者管理
└── tests/              # 测试模块
    ├── mod.rs
    ├── types_tests.rs
    ├── validator_tests.rs
    ├── manager_tests.rs
    └── participant_tests.rs
```

## 📝 详细拆分方案

### 模块1: `types.rs` (约150行)

**职责**: 定义所有核心数据结构

**包含内容**:
```rust
// 核心数据结构
pub struct LotteryLevel { ... }
pub struct LevelParameters { ... }
pub enum SelectionAlgorithm { ... }
pub struct LevelPermissions { ... }
pub enum LevelStatus { ... }
pub struct ParticipantInfo { ... }

// 实现方法
impl fmt::Display for LevelStatus { ... }
impl Default for LotteryLevel { ... }
```

**依赖关系**: 无外部依赖，纯数据结构

### 模块2: `validator.rs` (约220行)

**职责**: 等级数据验证和业务规则检查

**包含内容**:
```rust
pub struct LevelValidator {
    schema: JSONSchema,
}

impl LevelValidator {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> { ... }
    pub fn validate(&self, level: &LotteryLevel) -> Result<(), Vec<String>> { ... }
    fn validate_business_rules(&self, level: &LotteryLevel) -> Result<(), Vec<String>> { ... }
    fn validate_algorithm_params(&self, params: &LevelParameters) -> Result<(), Vec<String>> { ... }
}
```

**依赖关系**: 依赖 `types.rs` 中的数据结构

### 模块3: `manager.rs` (约200行)

**职责**: 等级管理器的核心业务逻辑

**包含内容**:
```rust
pub struct LevelManager {
    levels: HashMap<String, LotteryLevel>,
    validator: LevelValidator,
}

impl LevelManager {
    pub fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync + 'static>> { ... }
    pub fn upsert_level(&mut self, level: LotteryLevel) -> Result<(), Vec<String>> { ... }
    pub fn get_level(&self, id: &str) -> Option<&LotteryLevel> { ... }
    pub fn get_all_levels(&self) -> Vec<&LotteryLevel> { ... }
    pub fn get_active_levels(&self) -> Vec<&LotteryLevel> { ... }
    pub fn get_levels_by_priority(&self) -> Vec<&LotteryLevel> { ... }
    pub fn delete_level(&mut self, id: &str) -> bool { ... }
    pub fn update_level_status(&mut self, id: &str, status: LevelStatus) -> Result<(), String> { ... }
}
```

**依赖关系**: 依赖 `types.rs` 和 `validator.rs`

### 模块4: `participant.rs` (约100行)

**职责**: 参与者资格验证和管理

**包含内容**:
```rust
// 参与者验证逻辑
pub fn validate_participant_eligibility(
    level: &LotteryLevel,
    participant: &ParticipantInfo,
) -> Result<(), Vec<String>> { ... }

// 参与者相关的辅助函数
pub fn check_balance_requirement(participant: &ParticipantInfo, required: u128) -> Result<(), String> { ... }
pub fn check_stake_requirement(participant: &ParticipantInfo, required: u128) -> Result<(), String> { ... }
pub fn check_holding_time_requirement(participant: &ParticipantInfo, required: u64) -> Result<(), String> { ... }
pub fn check_nft_requirements(participant: &ParticipantInfo, required: &[String]) -> Result<(), Vec<String>> { ... }
pub fn check_blacklist_whitelist(participant: &ParticipantInfo, permissions: &LevelPermissions) -> Result<(), Vec<String>> { ... }
```

**依赖关系**: 依赖 `types.rs`

### 模块5: `mod.rs` (约30行)

**职责**: 模块导出和公共接口

**包含内容**:
```rust
// 模块声明
mod types;
mod validator;
mod manager;
mod participant;

// 公共导出
pub use types::*;
pub use validator::LevelValidator;
pub use manager::LevelManager;
pub use participant::validate_participant_eligibility;

// 测试模块
#[cfg(test)]
mod tests;
```

## 🚀 实施步骤

### 阶段1: 创建目录结构 (1天)
1. 创建 `src/server/src/core/lottery_levels/` 目录
2. 创建所有必要的文件
3. 设置基本的模块结构

### 阶段2: 数据结构迁移 (1天)
1. 创建 `types.rs` 文件
2. 移动所有数据结构定义
3. 移动相关的实现方法
4. 确保编译通过

### 阶段3: 验证器迁移 (1天)
1. 创建 `validator.rs` 文件
2. 移动 `LevelValidator` 结构体和实现
3. 更新导入引用
4. 确保编译通过

### 阶段4: 管理器迁移 (1天)
1. 创建 `manager.rs` 文件
2. 移动 `LevelManager` 结构体和实现
3. 更新导入引用
4. 确保编译通过

### 阶段5: 参与者模块迁移 (1天)
1. 创建 `participant.rs` 文件
2. 移动参与者验证逻辑
3. 重构为独立的函数
4. 确保编译通过

### 阶段6: 模块导出和测试 (1天)
1. 创建 `mod.rs` 文件
2. 设置正确的模块导出
3. 移动和重构测试代码
4. 确保所有测试通过

### 阶段7: 清理和优化 (1天)
1. 删除原始的 `lottery_levels.rs` 文件
2. 更新所有外部导入引用
3. 运行完整的测试套件
4. 代码审查和优化

## ⚠️ 注意事项

### 1. 依赖管理
- 确保模块间的依赖关系清晰
- 避免循环依赖
- 合理使用 `pub(crate)` 和 `pub` 可见性

### 2. 接口设计
- 保持现有的公共API不变
- 合理设计模块间的通信方式
- 考虑错误处理和类型安全

### 3. 测试维护
- 确保拆分后所有测试仍然通过
- 更新测试的导入路径
- 保持测试的完整性和准确性

### 4. 向后兼容
- 保持现有的公共接口不变
- 逐步迁移内部实现
- 提供迁移指南

## 📊 预期收益

### 1. 代码质量提升
- **可读性**: 每个文件职责单一，更容易理解
- **可维护性**: 修改某个功能时影响范围更小
- **可测试性**: 每个模块可以独立测试

### 2. 开发效率提升
- **并行开发**: 不同开发者可以同时修改不同模块
- **代码审查**: 代码审查更容易聚焦
- **冲突减少**: Git合并冲突减少

### 3. 架构优化
- **模块化**: 更清晰的模块边界
- **依赖管理**: 更清晰的依赖关系
- **接口设计**: 更稳定的公共接口

## 📝 总结

`lottery_levels.rs` 的重构是一个高价值的项目，将显著提升代码质量和开发效率。建议按照上述计划分阶段实施，每个阶段完成后都要进行充分测试，确保功能完整性和向后兼容性。

重构完成后，代码将更加清晰、可维护，符合单一职责原则，有助于项目的长期发展。
