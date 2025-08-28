# 服务器代码结构说明

## 代码拆分完成状态

### ✅ 已完成的拆分

#### 核心模块
- **`state.rs`** - 包含 `ServerState` 结构体和状态初始化逻辑
- **`types.rs`** - 包含 `ApiResponse<T>` 和各种请求/响应类型定义
- **`errors.rs`** - 包含 `handle_rejection` 错误处理函数
- **`utils.rs`** - 包含 `with_state` 等工具函数

#### 路由模块 (按功能分组)

**基础与状态路由**
- `health.rs` - 健康检查和基础指标
- `state_metrics.rs` - 状态指标和告警

**IPFS 与扩展路由**
- `ipfs_cache.rs` - IPFS缓存管理
- `ipfs_ext.rs` - IPFS扩展功能
- `upload.rs` - 文件上传

**NFT 与抽奖路由**
- `nft_types.rs` - NFT类型管理
- `nft_ownership.rs` - NFT所有权管理
- `lottery_config.rs` - 抽奖配置管理
- `levels.rs` - 抽奖等级管理
- `nft_state.rs` - NFT状态管理

**权限与质押路由**
- `permissions.rs` - 权限管理
- `staking.rs` - 质押管理
- `qualification.rs` - 资格管理
- `stake_events.rs` - 质押事件

**核心功能路由**
- `voting.rs` - 投票系统
- `sync.rs` - 同步功能
- `tools.rs` - 工具函数
- `cache.rs` - 缓存管理
- `serials.rs` - 序号管理

#### 测试目录
- `tests/unit_tests.rs` - 单元测试
- `tests/integration_tests.rs` - 集成测试
- `tests/test_helpers.rs` - 测试辅助函数

### 🔧 主要改进

1. **状态管理优化**: 将 `ServerState` 的创建逻辑移到 `state.rs` 中，提供 `ServerState::new()` 工厂函数
2. **main.rs 简化**: 移除了大量状态初始化代码，现在只负责服务器启动和路由配置
3. **模块组织**: 按功能对路由模块进行分组，使结构更清晰
4. **依赖管理**: 优化了模块间的导入关系

### 📁 文件结构

```
src/server/src/
├── main.rs              # 服务器主程序（已简化）
├── state.rs             # 服务器状态管理
├── types.rs             # 类型定义
├── errors.rs            # 错误处理
├── utils.rs             # 工具函数
├── core/                # 核心业务逻辑
├── routes/              # 路由模块
│   ├── mod.rs          # 路由模块导出
│   ├── health.rs       # 健康检查
│   ├── state_metrics.rs # 状态指标
│   ├── ipfs_cache.rs   # IPFS缓存
│   ├── ipfs_ext.rs     # IPFS扩展
│   ├── upload.rs       # 文件上传
│   ├── nft_types.rs    # NFT类型
│   ├── nft_ownership.rs # NFT所有权
│   ├── lottery_config.rs # 抽奖配置
│   ├── levels.rs       # 抽奖等级
│   ├── permissions.rs  # 权限管理
│   ├── staking.rs      # 质押管理
│   ├── qualification.rs # 资格管理
│   ├── voting.rs       # 投票系统
│   ├── sync.rs         # 同步功能
│   ├── tools.rs        # 工具函数
│   ├── cache.rs        # 缓存管理
│   ├── nft_state.rs    # NFT状态
│   ├── stake_events.rs # 质押事件
│   └── serials.rs      # 序号管理
└── tests/               # 测试目录
    ├── mod.rs          # 测试模块导出
    ├── unit_tests.rs   # 单元测试
    ├── integration_tests.rs # 集成测试
    └── test_helpers.rs # 测试辅助函数
```

### 🚀 使用说明

1. **启动服务器**: 直接运行 `cargo run` 即可启动
2. **添加新路由**: 在 `routes/` 目录下创建新文件，并在 `routes/mod.rs` 中导出
3. **状态管理**: 通过 `ServerState::new()` 创建新的服务器状态
4. **错误处理**: 使用 `handle_rejection` 统一处理错误

### 📝 注意事项

- 所有路由模块都应该使用 `with_state` 来获取服务器状态
- 新增类型定义应放在 `types.rs` 中
- 错误处理应通过 `errors.rs` 中的函数进行
- 测试文件中的导入路径已正确配置
