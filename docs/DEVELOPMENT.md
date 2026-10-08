# 开发与维护说明

[返回 README](../README.md)

## 分发架构

本仓库不启用 GitHub Pages，也不制作规则目录官网。Git 仓库保存导入索引和分发工具；
GitHub Releases 保存已经发布的加密 `.kyyrule` 与 `.kyybundle` 文件。
不存放漫画／视频内容、明文规则、可执行扩展、账号凭据、Cookie、Token、解密密钥或签名私钥。

## 索引与旧入口兼容

集合入口随发布更新，但集合内每个包的 URL 绑定具体 Release 标签，防止更新过程中混用版本。
`sources.json` 是**新仓库内** `all.json` 的兼容别名。
旧仓库中同名的 `sources.json` 是另一种发现目录格式，本项目不会改写它。
App 原有的大小、SHA-256、签名、解密及锁定规则校验继续生效。

既有 `/v1/rule-catalog`、`/v1/rule-packages/<release>/<id>.kyyrule`、
`/v1/rule-bundles/<release>/<channel>.kyybundle` 和 `/rules/<id>` 分发链仍保持原样。
老 `sources.json` 发现目录入口及其 Pages/raw 镜像也不受影响。
保留域名用于兼容不等于新建目录网站；本仓库新增的是 GitHub 分发渠道。

## 发布与更新边界

1. 原有私有规则审核、签名、加密与正式发布流程保持不变。
2. 本仓库只读取已公开发布的集合及加密包；不访问私有规则源码、不解密、不重新签名。
3. 完整／综合集合的版本及子集必须一致；每个包和集合包的字节数及 SHA-256 必须匹配。
4. 发布前重新读取上游集合，避免同步途中发生版本切换。
5. 文件上传到草稿 Release，GitHub 返回的每个附件 SHA-256 都验证通过才公开并切换 latest。
6. Release 公开后再更新 main 上的集合索引。拒绝序号回退、同序号换内容及改写已公开附件。
7. GitHub Actions 每 6 小时同步一次，也可以在 Actions 手动执行；失败时旧入口和上一个 Release 不变。

该同步工具只校验包的加密／签名**结构**及完整性，并不声称完成密码学签名验证；
密码学验证与解密仍由 App 原有导入链完成。没有把测试密钥或生产密钥放进此仓库。

## 本地验证

以下命令在仓库根目录执行。

需要 Python 3.11+、curl；发布还需要 GitHub CLI。没有第三方 Python 依赖。

```sh
python3 -m unittest discover -s tests -v
python3 scripts/mirror_release.py --output dist/preview
# 只有显式指定 --publish 才会写入 GitHub Releases：
python3 scripts/mirror_release.py --output dist/release --publish
```

每次运行使用空的输出目录；准备后若要发布请使用另一个空输出目录重新运行。`dist/` 不提交。仅 `all.json`、`general.json`、`sources.json`、
`publication.json` 四个元数据文件在发布成功后更新到 Git。本仓库的 `GITHUB_TOKEN` 只需
`contents: write`，不需要 App 仓库 Token、Cloudflare 密钥、App 签名证书或 App Store Connect 凭据。
