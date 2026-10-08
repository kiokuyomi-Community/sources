# KiokuYomi Community Sources

本仓库提供可供 KiokuYomi 导入的可选加密规则集合，通过 GitHub Releases 分发。

本仓库不托管漫画或视频内容。使用者应仅访问已获授权的内容，并遵守适用法律及相关服务条款。

## 手动添加订阅

在 KiokuYomi 的规则集合／远程规则导入入口粘贴 HTTPS 集合链接，检查导入预览后自行确认。

**综合集合（不含成人来源）：**

```text
https://github.com/kiokuyomi-Community/sources/releases/latest/download/general.json
```

**完整集合（可能包含成人来源；使用者需符合适用年龄及法律要求）：**

```text
https://github.com/kiokuyomi-Community/sources/releases/latest/download/all.json
```

GitHub raw 备用集合入口：

```text
https://raw.githubusercontent.com/kiokuyomi-Community/sources/main/general.json
https://raw.githubusercontent.com/kiokuyomi-Community/sources/main/all.json
```

## 旧订阅地址兼容

GitHub 分发渠道是新增入口，已有订阅无需切换地址、重新导入或重装 App。
旧订阅地址及其分发链保持不变，包括：

```text
https://sources.kiokuyomi.com/general.json
https://sources.kiokuyomi.com/all.json
https://rooou.github.io/kiokuyomi-sources/all.json
https://raw.githubusercontent.com/ROOOU/kiokuyomi-sources/main/all.json
```

## 反馈与移除请求

版本、导入问题或移除请求，请通过[仓库 Issues](https://github.com/kiokuyomi-Community/sources/issues) 提交。
权利方请提供规则 ID、涉及的权利及可核实的请求依据；不要在公开 Issue 上传身份证明、
账号凭据、私密材料或受版权保护的完整内容。移除需同步正式上游及相应分发渠道，而不只是改 README。

仅用于有权访问的内容。规则加密和项目分离并不替代授权、版权及平台政策要求。

## 开发文档

分发架构、兼容性细节、发布流程和本地验证方式见 [开发与维护说明](docs/DEVELOPMENT.md)。
