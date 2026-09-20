# MSTECH IIS SSL 自動更新工具：專案維護記憶

本檔是給未來 Codex／維護者的必要上下文。修改此目錄內任何程式前，先完整閱讀本檔、`README.md` 與 `CHANGELOG.md`。不要為了簡化程式而移除安全閘門或 fail-closed 行為。

完整移交入口位於目前工作區的 `../開發移交資料/00-接手前先讀.md`；若從開發移交 ZIP 解壓，則讀取 `../移交文件/00-接手前先讀.md`。

## 產品與版本

- 產品：MSTECH IIS SSL 自動更新工具。
- 目前使用者顯示版本：`v1.3`。沿用業主的 `v` 前綴格式，不要退回先前的 `1.1v`。
- Windows／.NET 數字版本：`1.3.0.0`；NuGet/semantic `<Version>`：`1.3.0`。
- 支援：Windows Server 2016／2019／2022／2025 x64 Desktop Experience、IIS 10、本機 IIS、一般網域、同一網站 SAN 多網域、HTTP-01。
- 不支援：Wildcard、DNS-01、Server Core、跨 IIS 網站 SAN、Central Certificate Store、遠端 IIS、自動修改 CDN/WAF/Load Balancer。
- 本專案未做程式碼簽章；發行前不得宣稱已有可信任 publisher。

## 固定外部元件

- win-acme：`2.2.9.1701 x64 trimmed`。
- Download URL、ZIP SHA-256、`wacs.exe` SHA-256 定義於 `Services/WinAcmeModels.cs` 的 `WinAcmeRecommendedRelease`。
- ZIP SHA-256：`F4DC3B144841FFDBA391CE168C273D7A686D45A359075E30EE4BF4EE186857D6`。
- EXE SHA-256：`FDFF5C5612E0BCBC8ABA52720E5D37E5C3821267179E2FA7341084148AD4B1EA`。
- 不可只更新版本字串或下載網址。更新 win-acme 必須重新核對官方來源、兩個雜湊、CLI 參數、settings schema、renewal schema、排程名稱與完整 smoke／實機測試，並在 `CHANGELOG.md` 記錄。

## 不可破壞的安全不變條件

1. 一般介面以 `asInvoker` 啟動；需要權限時交由 Windows UAC，程式永遠不接收、保存或記錄管理員密碼。
2. 正式簽發必須在同一次工作階段依序通過公開預檢、本機管理員預檢、Let’s Encrypt Staging。任一設定或指紋變更、結果超過 30 分鐘，都必須使後續閘門失效。
3. UAC worker 只接受 typed payload 與 allow-list action，不接受外部指定 executable、任意 CLI、下載 URL 或 hash。request 用 SHA-256 驗證；protocol v2 result 用每次操作隨機 HMAC-SHA256 驗證。不可退回未驗證 JSON 結果。
4. Staging 必須同時具備 `--test`、PFX file store、`--installation none`、`--notaskscheduler`，不得寫入 WebHosting、修改 IIS 或建立排程。固定 win-acme 的 `--test` 會在外部驗證與測試憑證簽發完成後以 `Console.ReadKey()` 詢問是否儲存；worker 無主控台，因此只能對已核對 SHA-256 的固定版本辨識完整提示前綴，終止該 Staging 子程序並確認 Windows 已回報結束，Production 絕不可套用此完成條件。PFX 只能放在 `%ProgramData%\MSTECH-IisSslManager\Temporary\Staging\<32字元GUID>` 的 MachinePrivate 目錄，且執行後必須確認清除；清除不確定視為 Staging 失敗。
5. Production 必須使用固定 production base URI、固定 renewal ID、`WebHosting`、IIS+retention script、`--nocache`、`--keepexisting`、`--notaskscheduler`。先備份 IIS 與本次 renewal；失敗或驗證不符時復原兩者。
6. Production 成功不能只相信 win-acme exit code。必須重新驗證 renewal JSON、憑證有效性與私鑰、完整 SAN、WebHosting store、選取網站所有精確 SNI 443 Binding 共用同一指紋。
7. SYSTEM 續期排程只能在正式憑證與 IIS 驗證完成後建立。就緒條件至少包含 Enabled、Run As SYSTEM、受控 `wacs.exe` 完整路徑、`--renew`、且只有一個執行動作。排程失敗不可撤銷已驗證的有效憑證，但 UI 必須明確警告需人工處理。
8. 舊憑證清理必須 fail-closed。30 天後仍需確認沒有任何 IIS HTTPS Binding 或 HTTP.sys `sslcert` 使用舊指紋；查詢失敗時保留，不可猜測後刪除。
9. 所有受權限保護的 ProgramData 寫入必須走 `ProgramDataSecurity`，拒絕 reparse point、非 Administrators/SYSTEM owner 或意外 writer。不要用一般 `Directory.CreateDirectory` 取代它。
10. CLI 參數必須使用 `ProcessStartInfo.ArgumentList`，不可改成 shell 字串拼接。PFX 密碼等 secret 必須在顯示、stdout、stderr、error 與 Log 中遮罩。
11. v1.3 的續期預覽及維護狀態查詢只讀，不得呼叫會建立目錄／修改 ACL 的 helper。正式執行須重新比對續期預覽雜湊，網域縮減須明確同意；不得只核對 renewal Id 而略過固定版本 schema 的網域、store、IIS／retention 設定。
12. 既有申請網域的 HTTPS 443 Binding 必須在本機預檢確認 SNI 已啟用且未使用 CCS；未知 SslFlags 不可當作 0 或通過。排程就緒還須符合完整 CLI allow-list、每日有效觸發與未來執行時間。憑證有效期、排程配置正確、上次排程成功及真實續期成功是不同概念。

## 架構導覽

- `MainWindow.xaml(.cs)`、`ViewModels/MainViewModel.cs`：UI、三階段 gate、30 分鐘 freshness 與操作確認。
- `Core/PublicPreflightService.cs`：公開 DNS、CAA、HTTP-01 route、ACME API、時鐘與 OS 檢查。這是診斷，不可取代真正 Staging。
- `Core/ElevatedLocalPreflightService.cs`：IIS 網站/Binding、Windows 服務、WebHosting、wacs hash/RSA 檢查。
- `Services/SecurityElevationService.cs`、`App.xaml.cs`：pre-UAC exchange、worker protocol v2、request SHA-256、result HMAC-SHA256。
- `Services/ElevatedWorkerDispatcher.cs`：提升權限 allow-list、Staging／Production 實際交易與 rollback。
- `Services/WinAcmeCommandBuilder.cs`：唯一可建立 wacs 命令的地方；安全 invariant 另在 dispatcher 再檢查一次。
- `Services/WinAcmeDownloadService.cs`：固定官方套件下載、ZIP/EXE hash、zip bomb/slip/symlink 防護與受控 settings。
- `Services/IisCertificateBindingVerifier.cs`：正式簽發後獨立驗證。
- `Services/WinAcmeRenewalStateTransaction.cs`：本次 renewal 的 capture/validate/commit/restore。
- `Scripts/CertificateRetention.ps1`：續期後 30 天的舊憑證安全清理。
- `Services/WinAcmeScheduledTaskService.cs`：透過 Task Scheduler COM 讀取排程，避免解析本地化文字。
- `Services/MaintenanceStatusService.cs`：只讀 IIS 443 Binding、憑證公開資料與續期排程；不開啟／匯出私鑰、不觸發續期、不修 ACL。
- `Infrastructure/AppPaths.cs`、`ProgramDataSecurity.cs`：資料路徑、ACL 與 reparse point 邊界。
- `Mstech.IisSslManager.SmokeTests/Program.cs`：無外部 test framework 的低依賴 smoke tests。

## 資料位置

- 一般使用者設定／Log：`%LocalAppData%\MSTECH\IisSslManager`。
- 受控根：`%ProgramData%\MSTECH-IisSslManager`。
- wacs：`...\win-acme\wacs.exe`。
- 獨立 state：`...\win-acme-state`。
- 敏感 Staging 暫存：`...\Temporary\Staging\<GUID>`。
- UAC exchange：`%ProgramData%\MSTECH-IisSslManager-Elevation\<GUID>`；必須允許標準使用者在 UAC 前建立自己的 private child，但不可讓其他使用者讀寫該 child。

## 修改與發行規則

1. 先閱讀 `git diff`／工作樹，保留使用者的無關修改。
2. 任何行為改動都要補 smoke test；涉及 IIS／ACME／ACL／UAC 時，同時重新檢查失敗、取消、逾時、TOCTOU、rollback 與 secret leakage。
3. 每次修改都要在 `CHANGELOG.md` 最上方版本下記錄；如果變更版本，同步更新 `Infrastructure/AppVersion.cs`、`.csproj`、`app.manifest`、主畫面、About、README、build-release artifact 名稱與 smoke test。
4. 建置與測試：

   ```powershell
   dotnet build .\Mstech.IisSslManager.csproj -c Release
   dotnet run --project ..\Mstech.IisSslManager.SmokeTests\Mstech.IisSslManager.SmokeTests.csproj -c Release
   ```

5. 發行：在專案目錄執行 `powershell -ExecutionPolicy Bypass -File .\build-release.ps1`。確認 Release 為 0 warning／0 error、全部 smoke tests 通過、About 與主畫面版本／Logo 正確，再交付 ZIP 與 `.sha256.txt`。
6. 不得在開發機上為了測試而實際修改 IIS、LocalMachine 憑證、Task Scheduler、HKCU Run 或執行 Production ACME，除非使用者明確授權且環境是指定測試機。

## 目前驗證界線

- 自動測試覆蓋純邏輯與靜態安全 invariant；發行前仍須在乾淨的 Windows Server 2016+ IIS 測試機做 UAC、Staging、Production、renewal、rollback、30 天腳本模擬及重新開機後排程驗證。
- 本開發工作區的驗證不得被描述成已完成真實網域簽發或真實 IIS 變更。
- 發行包暫保留標示 v1.2 的舊 PDF 基本手冊，v1.3 差異以 README 為準，不可聲稱 PDF 已更新。
