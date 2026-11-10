# CPPlayer-Plugins-KMP-Next

CPPlayer KMP 当前插件市场分发仓库。

## 目录地址

```text
https://raw.githubusercontent.com/Aurora-Nasa-1/CPPlayer-Plugins-KMP-Next/main/index.json
```

`CPPlayer-Plugins-KMP` 已回退为上一版快照；`CPPlayer-Plugins` 继续服务已发行的旧客户端。
新构建默认使用本仓库。

## 约束

- 只收录遵循 `kmp-sdk-v1` 契约的插件。
- 目录中的 `version`、`apiVersion`、`minHostApiVersion`、`runtime` 必须与包内
  `manifest.json` 逐项一致。缺省字段按 `1` 处理。
- 发布前必须运行：

```text
python scripts/validate_catalog.py --verify-packages
```

校验器只下载并检查 ZIP，不执行插件代码。CI 在每次 push 时同时核对目录与发布包。

协议与联网规则见 [PROTOCOL.md](PROTOCOL.md)。插件元数据与校验工具采用 Apache-2.0。
