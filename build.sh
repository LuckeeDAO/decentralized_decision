#!/bin/bash

# 基于比特承诺模型的去中心化投票系统 - 构建脚本

set -e

echo "🚀 开始构建投票系统..."

# 检查Rust环境
if ! command -v cargo &> /dev/null; then
    echo "❌ 错误: 未找到cargo，请先安装Rust"
    exit 1
fi

# 检查wasm-pack
if ! command -v wasm-pack &> /dev/null; then
    echo "📦 安装wasm-pack..."
    cargo install wasm-pack
fi

# 清理之前的构建
echo "🧹 清理之前的构建..."
cargo clean

# 检查代码格式
echo "🔍 检查代码格式..."
cargo fmt --all -- --check

# 运行clippy检查
echo "🔍 运行clippy检查..."
cargo clippy --all-targets --all-features -- -D warnings

# 运行测试
echo "🧪 运行测试..."
cargo test --all

# 构建WebAssembly模块
echo "🔨 构建WebAssembly模块..."
cd src/wasm
wasm-pack build --target web --out-dir ../../dist/wasm
cd ../..

# 构建服务器
echo "🔨 构建服务器..."
cargo build --release --bin server

# 构建智能合约
echo "🔨 构建智能合约..."
cd src/contracts
cargo build --release
cd ../..

# 创建发布目录
echo "📁 创建发布目录..."
mkdir -p dist/{bin,contracts,wasm,config}

# 复制二进制文件
echo "📋 复制二进制文件..."
cp target/release/server dist/bin/

# 复制WebAssembly文件
echo "📋 复制WebAssembly文件..."
cp -r src/wasm/pkg/* dist/wasm/

# 复制配置文件
echo "📋 复制配置文件..."
cp -r config/* dist/config/ 2>/dev/null || true

# 创建版本信息
echo "📝 创建版本信息..."
cat > dist/VERSION << EOF
版本: $(cargo metadata --format-version 1 | jq -r '.packages[0].version')
构建时间: $(date)
Git提交: $(git rev-parse HEAD 2>/dev/null || echo "未知")
EOF

# 创建启动脚本
echo "📝 创建启动脚本..."
cat > dist/start.sh << 'EOF'
#!/bin/bash

# 设置环境变量
export RUST_LOG=info
export PORT=${PORT:-8080}

# 启动服务器
echo "🚀 启动投票系统服务器..."
./bin/server
EOF

chmod +x dist/start.sh

# 创建Dockerfile
echo "📝 创建Dockerfile..."
cat > dist/Dockerfile << 'EOF'
FROM rust:1.70 as builder

WORKDIR /app
COPY . .

RUN cargo build --release --bin server

FROM debian:bullseye-slim

RUN apt-get update && apt-get install -y \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY --from=builder /app/target/release/server /app/server
COPY --from=builder /app/dist/config /app/config

EXPOSE 8080

ENV RUST_LOG=info
ENV PORT=8080

CMD ["./server"]
EOF

echo "✅ 构建完成！"
echo "📦 发布文件位于: dist/"
echo "🚀 运行命令: cd dist && ./start.sh"
