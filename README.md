# shou 瓜田 · NIST FIPS 与 FIDO2+ 认证设备信任库

本仓库通过 GitHub Actions 每周两次自动从 **NIST CMVP 官网**与 **FIDO 联盟官方 MDS3（Metadata Service v3）**同步有效期内的 FIPS 140-2 / FIPS 140-3 硬件安全密钥，筛选其中明确支持 **FIDO2 及以上协议（`FIDO_2_0` / `FIDO_2_1`）**且通过认证的型号，下载并导出对应型号 ID（`AAGUID`）、认证根证书与提取后的公钥，供 shou瓜田主站后端 `fido_attestation_trust` 直接引用或核验更新。

## 自动验证机制与数据来源

1. **NIST CMVP 官方有效模块库**：抓取 `csrc.nist.gov` 当前处于 `Active` 状态的硬件／混合模块清单及各证书详情页，提取证书编号、FIPS 版本（`140-2` / `140-3`）、安全等级（Overall / Physical Level）、`Sunset Date` 与安全策略 PDF 链接，并利用 [data/nist-cache.json](data/nist-cache.json) 做增量缓存。
2. **FIDO 联盟 MDS3 加密验签**：每次运行下载 `https://mds.fidoalliance.org/`（原 `mds3.fidoalliance.org` 永久跳转目标）的签章 JWT（BLOB），**严格校验证书链与数字签名**后才解析载荷；链必须有效锚定至本仓库固定存放的官方 GlobalSign 根证书（[roots/globalsign-root-r3.pem](roots/globalsign-root-r3.pem) 与 [roots/globalsign-root-r46.pem](roots/globalsign-root-r46.pem)）且叶证书主题匹配 `mds.fidoalliance.org`。
3. **严格交叉匹配**：
   - 仅保留协议包含 `fido2` 且 `authenticatorGetInfo.versions` 含 `FIDO_2_*` 及以上版本、非内置（外置硬件）、拥有完整认证状态（排除 `REVOKED`、`NOT_FIDO_CERTIFIED` 或存在密钥泄露／旁路警告）的型号。
   - **绝不将未取得 FIPS 认证的普通消费级密钥误标为 FIPS 设备**：除非经过 [mappings/curated-overrides.json](mappings/curated-overrides.json) 人工核验映射或同时满足 MDS3 FIPS 声明、规范化厂商与产品线一致且对应 NIST 证书仍处于有效期内，否则不会进入最终信任列表。

## 目录与输出文件

| 路径 | 说明 |
| --- | --- |
| `roots/` | 固定并校验过 SHA-256 指纹的官方 GlobalSign Root CA 证书 |
| `certs/` | 导出且经校验证书格式的厂商 Attestation 根证书（`.pem`） |
| `pubkeys/` | 从对应根证书提取的标准 SPKI 格式公钥（`.pub.pem`） |
| `data/fips-fido2-devices.json` | 完整设备清单（含 NIST 证书细节、FIDO2 版本、AAGUID、证书与公钥指纹及 PEM） |
| `data/shougt-fido-attestation-trust.yaml` | 可直接接入主站后端 `config.yaml` 中 `fido_attestation_trust` 的配置片段 |
| `data/shougt-fido-attestation-trust.json` | 同上 JSON 格式 |
| `data/nist-fido-candidates.json` | NIST 官网当前有效的硬件安全令牌／智能卡候选汇总 |
| `data/unmatched-review.json` | 待人工复核队列（如暂缺在期 NIST 匹配的预览设备或尚无 MDS AAGUID 的新证） |

## 已同步的在期 FIPS + FIDO2+ 设备清单

<!-- DEVICES_TABLE_START -->
| 型号名称 | 厂商 | AAGUID | FIPS 证书 | FIDO2 版本 / 等级 | 有效期至 | 根证书 / 公钥数 |
| --- | --- | --- | --- | --- | --- | --- |
| （待首次同步生成） | - | - | - | - | - | - |
<!-- DEVICES_TABLE_END -->

## 本地运行与自动化调度

- **自动运行**：[.github/workflows/sync-fips-fido.yml](.github/workflows/sync-fips-fido.yml) 每周一、周四 UTC `03:17` 自动执行（亦可在 GitHub Actions 页面手动触发 `workflow_dispatch`），仅在证书、公钥或设备清单发生实际变化时自动提交。
- **本地执行**：

```powershell
python -m pip install -r requirements.txt
python -m unittest discover -s tests -v
python -m src.sync
python -m src.validate
```

本项目遵循 GPLv3 开源协议（见 [LICENSE](LICENSE)）。
