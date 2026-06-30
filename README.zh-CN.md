# ChameleonUltra-COS

ChameleonUltra-COS 是 Chameleon Ultra 固件与 CLI 的非官方第三方 fork。该项目保留原 Chameleon Ultra 项目的 Git 历史与 GPL-3.0 授权，并在此基础上加入实验性的 COS 风格 ISO14443-A CPU 卡模拟能力。

本项目不是官方 Chameleon Ultra 项目，也不代表 RfidResearchGroup、Proxgrind、官方经销商、支付网络、交通系统运营方、门禁厂商、发卡方或任何第三方的官方支持、认可、赞助或合作关系。

## 本 Fork 增加的能力

- 与原 EMV/HF14A-4 行为互斥的 COS 模拟模式。
- 每个 slot 独立的 COS 文件系统，包含 MF/DF/EF。
- Binary EF 与定长线性记录 EF。
- APDU 文件选择、`READ BINARY`、`UPDATE BINARY`、`READ RECORD`、`UPDATE RECORD`、可配置 `APPEND RECORD` 行为。
- 简易 `GET CHALLENGE` 与占位认证响应。
- 与 COS slot 数据耦合的 UID/ATQA/SAK/ATS 配置。
- 用于 COS 配置、文件管理、记录管理、存储查看、直接 APDU 测试的 CLI 命令。

## 使用限制

本项目仅可用于你拥有或已获得明确授权的卡片、读卡器、系统和数据上的研究、互操作测试与开发。

不得将本项目用于：

- 绕过支付、票务、门禁、身份、考勤、会员权益或其他授权系统。
- 未经许可模拟第三方凭据。
- 存储、上传、分享真实生产卡片 dump、密钥、认证材料、个人数据或受保护数据。
- 规避技术保护措施，或违反法律、合同、服务条款、无线电管理规定。

本仓库不提供密钥、受保护卡片数据、商业卡片 dump，也不提供未授权访问说明。

## 与上游项目的关系

上游项目：

- Chameleon Ultra: https://github.com/RfidResearchGroup/ChameleonUltra
- 上游 Wiki: https://github.com/RfidResearchGroup/ChameleonUltra/wiki
- 上游文档仓库: https://github.com/RfidResearchGroup/ChameleonUltraDocs

本 fork 的问题请在本仓库反馈。只有能够在未修改的上游项目中复现的问题，才适合反馈给上游维护者。

## 许可证

本项目使用 GNU General Public License version 3。详见 [LICENSE](LICENSE)。

原 Chameleon Ultra 代码和本 fork 的修改均按 GPL-3.0 继承发布，除非具体文件另有说明。贡献归属以 Git 历史为准。

其他声明见 [NOTICE.md](NOTICE.md)。

## 风险声明

本软件不提供任何形式的担保。刷写非官方固件可能导致设备数据丢失、行为异常、需要 DFU/恢复流程，或短时间不可用。

COS 实现是实验性的，不应被视为安全芯片、生产卡操作系统、支付产品、票务产品、身份产品或门禁产品。

完整免责声明见 [DISCLAIMER.md](DISCLAIMER.md)。

## 安全问题

如果发现安全问题，请遵循 [SECURITY.md](SECURITY.md)。不要在公开 issue 中发布可利用细节、密钥、真实卡片数据或敏感信息。

## 支持

支持范围见 [SUPPORT.md](SUPPORT.md)。本项目不为未授权访问、凭据克隆、票务/支付/门禁绕过、真实卡片 dump、密钥或个人数据处理提供支持。
