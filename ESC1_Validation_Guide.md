# AD CS ESC1 漏洞驗證指南

本文件提供 ESC1 (AD CS Certificate Abuse) 的「環境前置條件」與「偵測驗證」流程，用於評估 EDR/SIEM 對憑證濫用攻擊鏈的可視性與告警品質。

注意：本文件以防禦與稽核驗證為目的；第二階段描述可重現的驗證步驟與證據收集點，但不提供可直接複製執行的攻擊指令字串。

## 環境資訊

- AD CS 主機 (CA Server): 10.0.0.206 (SME-SWP-W-AD)
- CA 名稱: sme-SME-SWP-W-AD-CA
- 測試端點: 10.0.0.x (具備憑證列舉與 PKINIT 測試能力)
- 目標: 驗證 EDR 是否能在 CA/DC/端點三方串起攻擊鏈

---

## IMPORTANT：啟用稽核日誌 (AD CS 主機端)

若不啟用以下稽核原則，您將無法在 Windows Event Log 中看到關鍵事件 (4886/4887/4768 等)，導致 EDR/SIEM 驗證失真。

### 啟用 CA 稽核與系統稽核

1) 在 AD CS 主機開啟 certsrv.msc，CA Properties → Auditing 勾選 Issue and manage certificate requests，並重啟 CertSvc。

2) 設定 CA 稽核濾器並重啟服務：

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service CertSvc
```

3) 在 OS 層級開啟進階稽核：

```powershell
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

若您也要驗證 5140（存取分享），需另外啟用 File Share 稽核（是否出現依環境而定）：

```powershell
auditpol /set /subcategory:"File Share" /success:enable /failure:enable
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

### 2.0 本輪測試要記錄的資訊（後面關聯用）

在開始前，先決定並記錄：

- Requester（低權限帳號）：例如 SME\aduser
- 目標高權身分：例如 Administrator@sme.local
- 目標範本：ESC1
- 測試開始時間：例如 (Get-Date)

在憑證申請成功後，再補記：

- RequestId（CA 回覆的 Request ID）
- 憑證檔案/輸出（PFX/PKCS#12/PEM/密碼）保存位置

### 2.1 憑證環境列舉 (Enumeration)

步驟：

1) 在測試端點使用您內部核准的列舉方式，查詢該 CA 上可用範本與可註冊權限。
2) 確認 ESC1 範本存在，且一般使用者具備 Enroll 權限。
3) 保存列舉輸出（作為變更/對照基線）。

預期事件：

- CA (Security): 通常不會產生 4886/4887（因為沒有送出申請）
- DC (Security): 可能出現 4769 (Kerberos Service Ticket) 或 LDAP 相關存取事件，取決於您的稽核與工具實作
- 端點 (Security): 4688 (Process Creation) 取決於是否啟用 Audit Process Creation
- 端點 (Sysmon, 若有): 1 (Process Create), 3 (Network Connect), 7 (Image Load) 視組態而定

### 2.2 憑證申請與簽發 (Certificate Request/Issuance)

步驟：

1) 以 Requester（低權限帳號）在測試端點對 CA 發起憑證申請。
2) 申請時指定目標範本為 ESC1。
3) 在申請內容中帶入目標高權身分資訊（例如 UPN = Administrator@sme.local）。
4) CA 回覆成功後，記錄 RequestId，並保存憑證輸出（PFX/PEM/密碼）。

預期事件：

- CA (Security):
  - 4886：CA 收到憑證申請 (RequestId/Requester/Template/時間點)
  - 4887：CA 簽發憑證 (RequestId/Requester/Subject/時間點)
- 注意：Windows CA 設計限制，4886/4887 的 Attributes 欄位通常不會包含 SAN，即使 AuditFilter=127
- 端點 (Security/Sysmon): 同 2.1，並伴隨對 CA 的網路連線遙測

### 2.3 使用憑證進行 PKINIT 取得 TGT (Kerberos)

步驟：

1) 以 2.2 取得的憑證輸出為材料，對 KDC 進行 PKINIT，申請目標高權身分的 TGT。
2) 依您的測試目標，選擇：
   - 將票據注入到目前登入 session（方便後續驗證性存取）
   - 或僅輸出票據並保存（方便離線分析與 SIEM 關聯）

預期事件：

- DC (Security):
  - 4768：Kerberos TGT request（若為 PKINIT，事件內容會反映憑證登入的特徵）
  - 4769：後續可能出現 Service Ticket requests（視您後續存取哪些服務）
- 端點 (Security/Sysmon): 進程與網路連線遙測（對 DC/88 等）

### 2.4 驗證高權存取 (Post-Auth Validation)

步驟：

1) 使用 2.3 的身分/票據對高權資源做「最小化」驗證（例如讀取 DC 管理分享或查詢受限資源）。
2) 保存驗證命令與輸出（證明已能以高權身分存取）。

預期事件：

- DC (Security):
  - 4624：成功登入 (常見為 Logon Type 3/9，視存取方式)
  - 5140：Network Share Object Access（若已啟用 File Share 稽核，且存取分享，如 \\DC\c$）
  - 4672：Special privileges assigned to new logon（不一定每次都有，取決於情境）

---
【核心判斷】
你要的是「指令 vs 事件」的直接對照表，而不是冗長的驗證流程。

【指令與事件對照表】

| 指令 | 預期事件 | 主機位置 | 關鍵欄位 |
|------|----------|----------|----------|
| `Certify.exe enum-templates /ca:10.0.0.206\sme-SME-SWP-W-AD-CA /vulnerable` | 通常無 4886/4887 | CA | N/A |
| | 可能 4769 (Kerberos Service Ticket) | DC | 取決於工具實作 |
| | 4688 (Process Creation) | 測試機 | 需啟用 Process Auditing |
| `Certify.exe request /ca:10.0.0.206\sme-SME-SWP-W-AD-CA /template:ESC1 /upn:Administrator@sme.local` | **4886** (憑證申請) | CA | RequestId, Requester, Template |
| | **4887** (憑證簽發) | CA | RequestId, Requester, Subject |
| `Rubeus.exe asktgt /user:Administrator /certificate:[...] /ptt` | **4768** (Kerberos TGT Request - PKINIT) | DC | Certificate Information, TargetUserName |
| `dir \\10.0.0.206\c$` (或其他存取) | **4624** (成功登入) | DC | Logon Type 3/9, TargetUserName |
| | **5140** (Network Share Access) | DC | 需啟用 File Share Auditing |

【Windows 設計限制】
- 4886/4887 的 Attributes 欄位**不會記錄 SAN** (Subject Alternative Name)
- 要確認 SAN=Administrator@sme.local，必須：
  1. 查 CA 資料庫：certsrv.msc → Issued Certificates → Details → Subject Alternative Name
  2. 或解析憑證檔案本身

【驗證要點】
- 檢查 4887 的 Requester (低權限) vs Subject (高權限) 的矛盾
- 用 4768 的 Certificate Information + 時間窗，關聯到 4886/4887 的 RequestId
- 這是 ESC1 偵測的核心：低權限申請高權憑證 → 用憑證做 PKINIT → 成功存取高權資源

---

## 第二階段快速取證：PowerShell 範本 (Get-WinEvent)

目的：直接從 CA/DC 拉出「本輪測試」的關鍵事件，避免手動翻 Event Viewer。

使用方式：

- 建議在 CA 上跑 CA 事件（4886/4887），在 DC 上跑 DC 事件（4768/4624/5140），可避免遠端讀取權限/WinRM/防火牆等變因。
- 若要跨主機遠端查詢，需具備遠端讀取 Security Log 的權限與連線條件。

### A) 在 CA 主機上抓 4886/4887

```powershell
$start = (Get-Date).AddMinutes(-60)
$ids = 4886,4887

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $start } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    [pscustomobject]@{
      TimeCreated = $_.TimeCreated
      EventId     = $_.Id
      RequestId   = $data['RequestId']
      Requester   = $data['Requester']
      Subject     = $data['Subject']
      Disposition = $data['Disposition']
    }
  } |
  Sort-Object TimeCreated
```

若您已記錄 RequestId，可加速過濾：

```powershell
$rid = '7'
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4886,4887; StartTime = (Get-Date).AddHours(-6) } |
  Where-Object { $_.ToXml() -match "<Data Name=\"RequestId\">$rid</Data>" }
```

### B) 在 DC 主機上抓 4768/4624/5140

```powershell
$start = (Get-Date).AddMinutes(-60)
$ids = 4768,4624,5140

Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = $ids; StartTime = $start } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }

    [pscustomobject]@{
      TimeCreated   = $_.TimeCreated
      EventId       = $_.Id
      TargetUser    = $data['TargetUserName']
      TargetDomain  = $data['TargetDomainName']
      IpAddress     = $data['IpAddress']
      LogonType     = $data['LogonType']
      ShareName     = $data['ShareName']
      ServiceName   = $data['ServiceName']
      TicketOptions = $data['TicketOptions']
    }
  } |
  Sort-Object TimeCreated
```

提示：

- 4768 的欄位名稱會依版本/情境略有差異，必要時請直接輸出 $_.Message 做人工比對。
- 5140 只有在啟用 File Share 稽核且真的有分享存取時才會出現。

---

## 第三階段：如何證明「高權身分被寫進憑證」

因 Windows Event Log 通常不在 4886/4887 直接呈現 SAN，建議用下列方法佐證。

### 3.1 直接查詢 CA 資料庫 (最直觀)

- certsrv.msc → Issued Certificates → 找到對應 RequestId 的憑證 → Details → Subject Alternative Name
- 預期：可看到 Principal Name=目標 UPN (例如 Administrator@sme.local)

### 3.2 解析憑證本身的 SAN (端點側佐證)

如果您手上是 Base64 的 PFX/PKCS#12，可用 PowerShell 解析 SAN：

```powershell
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
