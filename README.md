# shou 瓜田 · NIST FIPS 与 FIDO2+ 认证设备信任库

本仓库通过 GitHub Actions 每周两次自动从 **NIST CMVP 官网**与 **FIDO 联盟官方 MDS3（Metadata Service v3）**同步通过 FIPS 140-2 / FIPS 140-3 验证的硬件安全密钥，筛选其中明确支持 **FIDO2 及以上协议（`FIDO_2_0` / `FIDO_2_1`）**且通过认证的型号，下载并导出对应型号 ID（`AAGUID`）、认证根证书与提取后的公钥，供 shou瓜田主站后端 `fido_attestation_trust` 直接引用或核验更新。

## 自动验证机制与数据来源

1. **NIST CMVP 官方模块库与审理清单**：
   - 抓取 `csrc.nist.gov` 当前处于 `Active` 状态的 **FIPS 140-3** 硬件／混合模块。
   - 同时抓取自 2026-09-21 NIST 日落后由 `Active` 整体转入 `Historical` 的**非吊销 FIPS 140-2** 硬件／混合模块（例如 FEITIAN `#4422` / `#3979`、YubiKey 5.4 `#3914`、Thales `#4517`、HID `#3882` / `#3854` 等），并严格排除 `Revoked` 证书与历史 140-3 证书。
   - 同步抓取官方 **MIP（Modules In Process）**与 **IUT（Implementation Under Test）**清单，辅助核验已搭载经验证 FIPS 140-3 安全芯片平台且正在取证的政府／企业级密钥（如 Hirsch uTrust FIDO2 / Gov 系列、Swissbit iShield Key 2 FIPS）。
2. **FIDO 联盟 MDS3 加密验签**：每次运行下载 `https://mds.fidoalliance.org/`（原 `mds3.fidoalliance.org` 永久跳转目标）的签章 JWT（BLOB），**严格校验证书链与数字签名**后才解析载荷；链必须有效锚定至本仓库固定存放的官方 GlobalSign 根证书（[roots/globalsign-root-r3.pem](roots/globalsign-root-r3.pem) 与 [roots/globalsign-root-r46.pem](roots/globalsign-root-r46.pem)）且叶证书主题匹配 `mds.fidoalliance.org`。
3. **严格交叉匹配**：
   - 仅保留协议包含 `fido2` 且 `authenticatorGetInfo.versions` 含 `FIDO_2_*` 及以上版本、非内置（外置硬件）、拥有完整认证状态（排除 `REVOKED`、`NOT_FIDO_CERTIFIED` 或存在密钥泄露／旁路警告）的型号。
   - **绝不将未取得 FIPS 认证的普通消费级密钥误标为 FIPS 设备**：除非经过 [mappings/curated-overrides.json](mappings/curated-overrides.json) 人工核验映射或同时满足 MDS3 FIPS 声明、规范化厂商与产品线一致且对应 NIST 证书仍为 `Active` 或非吊销 `Historical FIPS 140-2`，否则不会进入最终信任列表；其中 Overall Level 1 仅保留在设备台账，不纳入要求 Level 2+ 的 `shougt-fido-attestation-trust` 配置。

## 目录与输出文件

| 路径 | 说明 |
| --- | --- |
| `roots/` | 固定并校验过 SHA-256 指纹的官方 GlobalSign Root CA 证书 |
| `certs/` | 导出且经校验证书格式的厂商 Attestation 根证书（`.pem`） |
| `pubkeys/` | 从对应根证书提取的标准 SPKI 格式公钥（`.pub.pem`） |
| `data/fips-fido2-devices.json` | 完整设备清单（含 NIST 证书细节、FIDO2 版本、AAGUID、证书与公钥指纹及 PEM） |
| `data/shougt-fido-attestation-trust.yaml` | 可直接接入主站后端 `config.yaml` 中 `fido_attestation_trust` 的配置片段（Level 2+） |
| `data/shougt-fido-attestation-trust.json` | 同上 JSON 格式（Level 2+） |
| `data/nist-fido-candidates.json` | NIST 官网符合条件的硬件安全令牌／智能卡候选汇总（140-3 Active 与非吊销 140-2 Historical） |
| `data/nist-in-process.json` | NIST CMVP 官方 MIP / IUT 审理中的 FIDO／安全密钥候选清单 |
| `data/unmatched-review.json` | 待人工复核队列（未匹配 MDS FIPS 条目、已知 FIPS 厂商未匹配硬件、预览或尚无 MDS AAGUID 的新证） |

## 已同步的 FIPS + FIDO2+ 设备清单

<!-- DEVICES_TABLE_START -->
| 型号名称 | 厂商 | AAGUID | FIPS 证书 | FIDO2 版本 / 等级 | 有效期至 | 根证书 / 公钥数 |
| --- | --- | --- | --- | --- | --- | --- |
| HID Crescendo 4000 FIPS | HID Global | `8eec9bf9-486c-46da-9a67-1fbb4f66b9ed` | [#5390](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5390) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1 / `FIDO_CERTIFIED_L2` | 2031-07-09 | 1 组 |
| HID Crescendo Key V3 FIPS | HID Global | `19bca99b-7c09-44fe-a969-8cba45764542` | [#5028](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5028) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1 / `FIDO_CERTIFIED_L2` | 2030-06-17 | 1 组 |
| OneSpan DIGIPASS FX1-C | OneSpan NV | `30b5035e-d297-4ff1-020b-addc96ba6a98` | [#5048](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5048) (FIPS 140-3 L3) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2029-03-10 | 1 组 |
| OneSpan DIGIPASS FX2-A | OneSpan NV | `30b5035e-d297-4ff2-010b-addc96ba6a98` | [#5048](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5048) (FIPS 140-3 L3) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2029-03-10 | 2 组 |
| YubiKey 5 FIPS Series | Yubico, Inc. | `57f7de54-c807-4eab-b1c6-1c9be7984e92` | [#5291](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2031-05-21 | 6 组 |
| YubiKey 5 FIPS Series (Enterprise Profile) | Yubico, Inc. | `905b4cb4-ed6f-4da9-92fc-45e0d4e9b5c7` | [#5291](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2031-05-21 | 6 组 |
| YubiKey 5 FIPS Series with Lightning | Yubico, Inc. | `7b96457d-e3cd-432b-9ceb-c9fdd7ef7432` | [#5291](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2031-05-21 | 6 组 |
| YubiKey 5 FIPS Series with Lightning (Enterprise Profile) | Yubico, Inc. | `3a662962-c6d4-4023-bebb-98ae92e78e20` | [#5291](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2031-05-21 | 6 组 |
| YubiKey 5 FIPS Series with NFC | Yubico, Inc. | `fcc0118f-cd45-435b-8da1-9782b2da0715` | [#5291](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2031-05-21 | 6 组 |
| YubiKey 5 FIPS Series with NFC (Enterprise Profile) | Yubico, Inc. | `79f3c8ba-9e35-484b-8f47-53a5a0f5c630` | [#5291](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5291) (FIPS 140-3 L2) | FIDO_2_0, FIDO_2_1, FIDO_2_1_PRE / `FIDO_CERTIFIED_L2` | 2031-05-21 | 6 组 |
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
