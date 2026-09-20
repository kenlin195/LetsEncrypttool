# LetsEncrypttool

名世科技有限公司製作的 **MSTECH IIS SSL 自動更新工具**，目前版本 **v1.3 / 1.3.0.0**。

以 WPF / .NET 10 搭配固定版本 win-acme，協助 Windows Server 的本機 IIS 進行 Let's Encrypt 憑證申請、HTTPS Binding 更新與 SYSTEM 背景續期。

## 文件入口

- [完整操作與維護說明](Mstech.IisSslManager/README.md)
- [版本紀錄](Mstech.IisSslManager/CHANGELOG.md)
- [PDF 安裝操作說明書（v1.2 基本流程）](Mstech.IisSslManager/output/pdf/MSTECH-IIS-SSL-v1.2-安裝操作說明書.pdf)；v1.3 新功能與差異請看目前 README。
- [程式維護安全規則](Mstech.IisSslManager/AGENTS.md)
- [Windows Server 實機驗收清單](移交文件/03-Windows-Server實機驗收清單.md)
- [第三方參考來源及 SHA-256](references/README.md)

## 建置與測試

使用 Windows x64、.NET 10 SDK。在儲存庫根目錄執行：

```powershell
dotnet build .\Mstech.IisSslManager\Mstech.IisSslManager.csproj -c Release -p:TreatWarningsAsErrors=true
dotnet run --project .\Mstech.IisSslManager.SmokeTests\Mstech.IisSslManager.SmokeTests.csproj -c Release -p:TreatWarningsAsErrors=true
```

目前開發機基準為 **0 warning / 0 error、18/18 smoke tests 通過**。離線 WPF 測試使用合成資料，不代表已完成 Windows Server、UAC、真實 IIS 或 ACME 端到端驗收。

建立 self-contained Windows x64 執行包：

```powershell
Set-Location .\Mstech.IisSslManager
powershell -NoProfile -ExecutionPolicy Bypass -File .\build-release.ps1
```

發行包輸出至主專案的 `artifacts`，不提交 Git。既有同名發行包會保留；重新封裝時可另指定專案內的 `-OutputRoot`。

## 儲存範圍

本庫保存主程式、測試、Logo、PDF、維護文件及參考來源資訊。`bin`、`obj`、發行 ZIP、第三方 ZIP、執行紀錄、實際 ACME 帳號／續期設定、憑證與私鑰均不納入 Git；原有本機檔案不會因此刪除。

`移交文件/` 與 `SOURCE-FILES.sha256.txt` 保留最初 1.1v 移交歷史。當中的舊版本、測試數量、「尚未建立 Git」及逐檔雜湊不是目前 v1.3 的狀態；以 Git commit、目前專案 README、AGENTS 及 CHANGELOG 為準。

儲存庫初始設定為私人；未經業主要求，不變更公開性，也不加入新的開源授權。本工具與 win-acme / Let's Encrypt 的權利與關係請參閱[第三方聲明](Mstech.IisSslManager/THIRD-PARTY-NOTICES.txt)。
