# @ikenxuan/watermark

一个基于 Rust (napi-rs) 编写的高性能水印处理库。

## 安装

由于本库底层使用了 Rust 编译的原生模块，因此我们在发布时已经为你预编译了各种平台下的二进制文件。你只需要像安装普通包一样安装即可，npm/pnpm 会根据你的操作系统和 CPU 架构**自动下载对应的原生二进制子包**。

```bash
npm install @ikenxuan/watermark
# 或者
pnpm add @ikenxuan/watermark
```

### 支持的平台

目前预编译的二进制包支持以下架构：
- Windows x64 (`win32-x64-msvc`)
- macOS ARM64 / M1/M2 (`darwin-arm64`)
- Linux x64 (`linux-x64-gnu`)
- Linux ARM64 (`linux-arm64-gnu`)

## 许可证

MIT