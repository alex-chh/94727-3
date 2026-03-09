# AD CS ESC1 漏洞驗證指南

本文件提供 ESC1 (AD CS Certificate Abuse) 的「環境前置條件」與「偵測驗證」流程，用於評估 EDR/SIEM 對憑證濫用攻擊鏈的可視性與告警品質。

注意：本文件以防禦與稽核驗證為目的，第二階段以「要做的驗證動作」描述，不包含可直接複製執行的攻擊指令。

## 環境資訊

- AD CS 主機 (CA Server): 10.0.0.206 (SME-SWP-W-AD)
- CA 名稱: sme-SME-SWP-W-AD-CA
- 測試端點: 10.0.0.x (具備憑證列舉與 PKINIT 測試能力)
- 目標: 驗證 EDR 是否能在 CA/DC/端點三方串起攻擊鏈

---

## IMPORTANT：啟用稽核日誌 (AD CS 主機端)

若不啟用以下稽核原則，您將無法在 Windows Event Log 中看到關鍵事件 (4886/4887/4768 等)，導致 EDR/SIEM 驗證失真。

### 啟用 CA 稽核與系統稽核

- 在 AD CS 主機執行 certsrv.msc，CA Properties → Auditing 勾選 Issue and manage certificate requests，重啟 CertSvc

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service CertSvc
```

- 在 OS 層級開啟進階稽核：

```powershell
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

---

## 第一階段：啟用 ESC1 前置條件 (AD CS 主機端)

以下為最小條件集合，用於建立「可被 ESC1 濫用」的範本。

- certtmpl.msc → Duplicate "User" (Windows Server 2003 Enterprise)
- General: Template display name = ESC1
- Request Handling: Allow private key to be exported
- Subject Name: Supply in the request (ENROLLEE_SUPPLIES_SUBJECT)
- Extensions → Application Policies: 包含 Client Authentication (1.3.6.1.5.5.7.3.2)
- Security: 加入 Domain Users，勾 Read/Enroll (不勾 Write 權限，以免形成 ESC4)
- Issuance Requirements: 確認未勾 Manager approval

- certsrv.msc → Certificate Templates → New → Certificate Template to Issue → ESC1

---

## 第二階段：攻擊鏈驗證動作 (測試機端)

本階段的重點是「做出可被偵測的動作」，然後在 CA/DC/端點三側對應到事件與遙測。

### 2.1 憑證環境列舉 (Enumeration)

動作：在測試端點列舉 CA 與可用的範本（確認 ESC1 範本存在與可被一般使用者註冊）。

預期事件：
- CA (Security): 通常不會產生 4886/4887（因為沒有送出申請）
- DC (Security): 可能出現 4769 (Kerberos Service Ticket) 或 LDAP 相關存取事件，取決於您的稽核與工具實作
- 端點 (Security): 4688 (Process Creation) 取決於是否啟用 Audit Process Creation
- 端點 (Sysmon, 若有): 1 (Process Create), 3 (Network Connect), 7 (Image Load) 視組態而定

### 2.2 憑證申請與簽發 (Certificate Request/Issuance)

動作：以低權限使用者身分，透過 ESC1 範本提交憑證申請，並在申請內容中帶入目標高權身分資訊 (例如 UPN)。

預期事件：
- CA (Security):
  - 4886：CA 收到憑證申請 (RequestId/Requester/Template/時間點)
  - 4887：CA 簽發憑證 (RequestId/Requester/Subject/時間點)
- 注意：Windows CA 設計限制，4886/4887 的 Attributes 欄位通常不會包含 SAN，即使 AuditFilter=127
- 端點 (Security/Sysmon): 同 2.1，並伴隨對 CA 的網路連線遙測

### 2.3 使用憑證進行 PKINIT 取得 TGT (Kerberos)

動作：使用前一步取得的憑證，向 KDC 以 PKINIT 方式申請 TGT，並將票據注入或用於後續存取。

預期事件：
- DC (Security):
  - 4768：Kerberos TGT request（若為 PKINIT，事件內容會反映憑證登入的特徵）
  - 4769：後續可能出現 Service Ticket requests（視您後續存取哪些服務）
- 端點 (Security/Sysmon): 進程與網路連線遙測（對 DC/88 等）

### 2.4 驗證高權存取 (Post-Auth Validation)

動作：使用取得的身分/票據對高權資源進行驗證性存取（例如列舉 DC 的管理分享）。

預期事件：
- DC (Security):
  - 4624：成功登入 (常見為 Logon Type 3/9，視存取方式)
  - 5140：Network Share Object Access（若啟用並存取分享，如 \\DC\c$）
  - 4672：Special privileges assigned to new logon（不一定每次都有，取決於情境）

---

## 第三階段：如何證明「高權身分被寫進憑證」

因 Windows Event Log 通常不在 4886/4887 直接呈現 SAN，建議用下列方法佐證。

### 3.1 直接查詢 CA 資料庫 (最直觀)

- certsrv.msc → Issued Certificates → 找到對應 RequestId 的憑證 → Details → Subject Alternative Name
- 預期：可看到 Principal Name=目標 UPN (例如 Administrator@sme.local)

### 3.2 解析憑證本身的 SAN (端點側佐證)

如果您手上是 Base64 的 PFX/PKCS#12，可用 PowerShell 解析 SAN：

```powershell
# 將 Base64 PFX 內容置於 $b64，並提供 PFX 密碼
$pfxBytes = [Convert]::FromBase64String($b64)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxBytes, $pfxPassword)
$sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
[System.Security.Cryptography.AsnEncodedData]::new($sanExt.Oid,$sanExt.RawData).Format($true)
```

---

## 結論：事件在 ESC1 偵測中的定位

- 4886/4887：CA 端的事實紀錄，提供 Requester/Template/RequestId/時間點，做為攻擊鏈關聯座標（但通常不直接給 SAN）
- 4768：DC 端的行為落地，代表憑證被拿去做 PKINIT 申請 TGT，是最穩的行為指標
- 偵測品質：以 4768 為主錨點，再用 4886/4887 的 RequestId/時間窗與 CA DB/憑證內容佐證 SAN，能形成高可信度的 ESC1 攻擊鏈告警
