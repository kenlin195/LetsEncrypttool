# 可直接交給下一台 Codex 的接手提示詞

請將下列內容作為新 Codex 工作的第一則訊息：

```text
請承接「MSTECH IIS SSL 自動更新工具」專案。這是 Windows Server 2016+、IIS 10、win-acme 與 Let’s Encrypt 的 WPF 工具，目前顯示版本為 1.1v，Windows/FileVersion 為 1.1.0.0。

在採取任何修改前，請先完整閱讀：
1. Mstech.IisSslManager/AGENTS.md
2. Mstech.IisSslManager/README.md
3. Mstech.IisSslManager/CHANGELOG.md
4. 移交文件/00-接手前先讀.md 至 05-移交內容與雜湊.md

先不要修改程式。請先盤點檔案並執行 Release build、12 項 smoke tests、CertificateRetention.ps1 parser check，回報是否符合移交基準。這個資料夾目前不是 Git repository，不要假設有版本歷史，也不要未經我同意上傳到 GitHub 或外部服務。

必須保留三階段 gate、UAC typed allow-list worker、request SHA-256/result HMAC、受保護 Staging PFX、Production backup/rollback、簽發後 IIS/憑證獨立驗證、SYSTEM 單一續期動作及舊憑證 fail-closed 清理。不得為了簡化而弱化 AGENTS.md 的安全不變條件。

目前自動測試已通過，但尚未完成真實 Windows Server＋公開網域的完整端到端驗收。請勿宣稱已完成生產驗收；下一階段依 03-Windows-Server實機驗收清單.md 進行。任何修改都要更新 CHANGELOG、補測試、重新建置並產生新的 ZIP/SHA-256。
```

## 如果只是處理「測試字樣」

可追加：

```text
請只改善容易誤解的文案：將「固定測試版本／下載經測試版本」改成「已驗證的固定版本」，並清楚說明不是試用版。不要移除 Let’s Encrypt Staging、測試憑證及任何正式簽發前 gate。修改後更新版本紀錄並重跑全部測試與 UI 檢查。
```

## 如果要開始實機驗收

可追加：

```text
這次只做診斷與驗收規劃，除非我逐項明確授權，不要實際修改 IIS、LocalMachine 憑證、Task Scheduler、HKCU Run 或執行 Production ACME。先依 03 清單盤點測試機、測試 Site、網域、備份與復原條件。
```
