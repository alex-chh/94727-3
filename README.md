# AD CS ESC1 漏洞驗證環境

本專案旨在提供一個標準化的 AD CS (Active Directory Certificate Services) 漏洞驗證流程，協助企業評估 EDR 系統對憑證濫用攻擊的偵測與防禦能力。

## 主要內容

- **[ESC1_Validation_Guide.md](./ESC1_Validation_Guide.md)**: 完整的操作手冊，包含：
    - 如何在 AD CS 建立易受攻擊的 ESC1 範本。
    - 如何使用 Certify 與 Rubeus 進行模擬攻擊。
    - 如何透過 Windows Event Logs (4886, 4887, 4768) 與 ETW 驗證 EDR 有效性。

## 環境需求

- **AD CS 主機**: Windows Server (已安裝 Enterprise CA)。
- **攻擊測試機**: 能夠連線至 AD CS 的 Windows 端點。
- **測試工具**:
    - [Certify](https://github.com/GhostPack/Certify) (漏洞掃描與憑證申請)
    - [Rubeus](https://github.com/GhostPack/Rubeus) (Kerberos 票據操作)

## 驗證目標

1.  確認 EDR 是否能偵測 `Certify` 或 `Rubeus` 的執行或記憶體注入行為。
2.  確認 SIEM 是否能關聯出異常的憑證申請事件 (Event ID 4886/4887) 與後續的 TGT 請求 (Event ID 4768)。

> **警告**: 本專案內容僅供授權測試與教育用途，請勿用於未經授權的環境。
