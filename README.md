# 基于比特承诺模型的去中心化投票系统

> 用词规范：请参阅《[项目术语表](doc/项目术语表.md)》以确保术语统一。

## 项目概述

本项目实现了一个基于比特承诺模型的去中心化投票系统，采用NFT类型驱动架构，支持多种去中心化应用场景，第一期重点实现去中心化抽奖功能。

### 核心特性

- **NFT类型驱动**：通过不同NFT类型控制应用场景，支持抽奖、彩票、分配、治理等
- **比特承诺协议**：确保投票隐私保护，支持承诺-揭示两阶段流程
- **代币权限控制**：基于$LUCKEE代币的权限管理，支持多级权限（基础、创建者、管理员）
- **多等级选择**：支持多组多目标选择（n选k组合）
- **iAgent自动化**：自动化承诺与揭示流程，支持多种触发策略
- **去中心化存储**：IPFS + 区块链双重保障，链上存储摘要，IPFS存储明细

### 技术栈

- **后端核心**：Rust + WebAssembly (wasm-pack)
- **区块链平台**：Injective Protocol (CosmWasm)
- **智能合约**：Rust (CosmWasm) + CW20/CW721标准
- **存储方案**：IPFS + 链上哈希验证 (CID存储)
- **前端框架**：React + TypeScript + Web3.js
- **开发工具**：cargo, wasm-pack, cosmwasm-cli, ipfs-cli

## 快速开始

### 环境要求

- Rust 1.70+
- Node.js 18+
- IPFS节点（可选）
- Injective CLI（可选）

### 安装依赖

```bash
# 安装Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# 安装wasm-pack
cargo install wasm-pack

# 安装项目依赖
cargo build
```

### 构建项目

```bash
# 使用构建脚本
./build.sh

# 或手动构建
cargo build --release
```

### 运行服务器

```bash
# 设置环境变量
export RUST_LOG=info
export PORT=8080

# 运行服务器
cargo run --bin server
```

### 运行测试

```bash
# 运行所有测试
cargo test

# 运行特定模块测试
cargo test --package luckee-voting-wasm
cargo test --package luckee-voting-server
```

## 项目结构

```
├── src/                    # 源代码目录
│   ├── wasm/              # WebAssembly核心模块
│   │   ├── src/
│   │   │   ├── crypto.rs   # 密码学工具库
│   │   │   ├── commitment.rs # 比特承诺协议
│   │   │   ├── voting.rs   # 投票系统核心
│   │   │   ├── types.rs    # 数据类型定义
│   │   │   └── utils.rs    # 工具函数
│   │   └── Cargo.toml
│   ├── server/            # HTTP服务器
│   │   ├── src/main.rs    # 服务器主程序
│   │   └── Cargo.toml
│   ├── contracts/         # 智能合约
│   │   ├── src/
│   │   │   ├── cw20_token.rs # CW20代币合约
│   │   │   ├── cw721_nft.rs  # CW721 NFT合约
│   │   │   └── voting_contract.rs # 投票合约
│   │   └── Cargo.toml
│   ├── ipfs/              # IPFS存储模块
│   │   ├── src/
│   │   │   ├── client.rs  # IPFS客户端
│   │   │   ├── storage.rs # 存储实现
│   │   │   └── types.rs   # IPFS类型
│   │   └── Cargo.toml
│   └── sdk/               # 客户端SDK
├── doc/                   # 技术文档
├── dev/                   # 开发文档
├── config/                # 配置文件
├── dist/                  # 构建输出
├── Cargo.toml            # 工作空间配置
├── build.sh              # 构建脚本
└── README.md             # 项目说明
```

## API文档

### 投票会话管理

#### 创建投票会话

```http
POST /sessions
Content-Type: application/json

{
  "session_id": "session_123",
  "commit_deadline": 1640995200,
  "reveal_deadline": 1641081600,
  "participants": ["user1", "user2", "user3"]
}
```

#### 提交承诺

```http
POST /sessions/{session_id}/commitments
Content-Type: application/json

{
  "session_id": "session_123",
  "user_id": "user1",
  "message": "vote_data"
}
```

#### 提交揭示

```http
POST /sessions/{session_id}/reveals
Content-Type: application/json

{
  "session_id": "session_123",
  "user_id": "user1",
  "message": "vote_data",
  "randomness": "hex_encoded_randomness"
}
```

#### 获取会话信息

```http
GET /sessions/{session_id}
```

#### 计算投票结果

```http
POST /sessions/{session_id}/results
```

### 健康检查

```http
GET /health
```

### 指标监控

```http
GET /metrics
```

## 开发指南

### 代码规范

- 遵循Rust官方代码规范
- 使用`cargo fmt`格式化代码
- 使用`cargo clippy`进行代码检查
- 所有公共API必须有文档注释

### 测试规范

- 单元测试覆盖率 > 90%
- 集成测试覆盖主要功能
- 性能测试验证关键指标
- 安全测试确保系统安全

### 提交规范

- 使用语义化提交信息
- 每个提交只包含一个功能或修复
- 提交前运行所有测试
- 代码审查通过后合并

## 部署指南

### Docker部署

```bash
# 构建镜像
docker build -t luckee-voting .

# 运行容器
docker run -p 8080:8080 luckee-voting
```

### 生产环境部署

1. 配置环境变量
2. 设置IPFS节点
3. 部署智能合约
4. 启动服务器
5. 配置监控和日志

## 监控和运维

### 健康检查

- 服务器健康状态：`/health`
- 系统指标：`/metrics`
- 日志监控：结构化JSON日志

### 性能监控

- 请求响应时间
- 并发连接数
- 内存使用情况
- CPU使用率

### 告警配置

- 服务不可用告警
- 性能指标告警
- 错误率告警
- 资源使用告警

## 安全考虑

### 密码学安全

- 使用标准密码学库
- 定期更新依赖
- 密钥管理最佳实践
- 随机数生成安全

### 网络安全

- HTTPS/TLS加密
- CORS配置
- 请求限流
- 输入验证

### 智能合约安全

- 代码审计
- 形式化验证
- 测试覆盖
- 升级机制

## 贡献指南

1. Fork项目
2. 创建功能分支
3. 提交更改
4. 创建Pull Request
5. 代码审查
6. 合并到主分支

## 许可证

MIT License

## 联系方式

- 项目主页：https://github.com/luckee-dao/decentralized_decision
- 问题反馈：https://github.com/luckee-dao/decentralized_decision/issues
- 技术讨论：https://github.com/luckee-dao/decentralized_decision/discussions

## 更新日志

### v0.1.0 (2024-01-XX)

- 初始版本发布
- 实现比特承诺协议
- 实现投票系统核心功能
- 实现HTTP服务器
- 实现IPFS存储模块
- 实现智能合约基础框架
