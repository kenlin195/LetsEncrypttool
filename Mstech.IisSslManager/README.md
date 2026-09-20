# MSTECH IIS SSL 自動更新工具

版本：v1.3（Windows 檔案版本 1.3.0.0）  
開發者：名世科技有限公司 MSTECH LTD.

這是一套給 Windows Server 2016 以上、IIS 10、x64 Desktop Experience 使用的繁體中文管理工具。它透過 win-acme 與 Let’s Encrypt，完成環境檢查、Staging 外部驗證、正式憑證申請、IIS HTTPS Binding 更新及背景自動續期。

完整安裝、DNS／NAT、Staging 與日常維護流程請參閱 [v1.3 PDF 安裝操作說明書](output/pdf/MSTECH-IIS-SSL-v1.3-安裝操作說明書.pdf)。新版共 12 頁，已同步狀態首頁、排程檢查、SNI、網域增減確認及通知限制；[可維護來源與產生方式](docs/manual/README.md)亦已納入專案。v1.2 舊手冊保留於 `output/pdf/archive/`，新版發行包只收錄 v1.3 PDF。

## v1.3 使用重點

- 新增首頁「憑證與續期狀態」：按「重新整理狀態（唯讀）」並完成必要的 UAC，讀取 IIS HTTPS 443 憑證期限、剩餘天數及工具管理排程的上次／下次執行、結果與設定檢查。查詢不會續期、匯出私鑰或變更 IIS／排程；畫面是有時間標記的快照，不是持續監控。讀取失敗明確顯示未知，不採用過期成功結果。
- 仍從「1 申請設定」開始申請。既有申請網域的 HTTPS Binding 若未啟用 SNI、使用 CCS 或無法可靠讀取設定，會在本機預檢停止並提供處理方式；不會自動更動既有 Binding。
- 同一網站再次正式申請前，會讀取並比較現有續期網域。移除任何網域需另外明確同意；若預覽後續期設定被其他程序變更，正式執行會停止，要求重新預覽。
- 黃色警告經人工確認後顯示「已人工確認」，不會被改成綠色或取代 Staging。設定更動、重新檢查或驗證逾期後，人工確認狀態會失效。
- 正式成功後仍需檢查排程；v1.3 額外核對正式環境完整參數、每日有效觸發條件及未來執行時間。排程不符不會撤銷已驗證的有效憑證，但會明確提示人工處理。
- 「上次排程執行成功」不表示當次有換發憑證；請搭配目前憑證期限及 win-acme 紀錄確認。
- 正式操作應安排在維護時段，避免同時由第二個工具視窗、背景續期或其他管理員修改 IIS。現有失敗復原仍使用完整 IIS 設定備份，不是跨程序交易鎖。
- 聯絡信箱只供 ACME 帳號聯絡，**填寫信箱不會啟用告警**。Let’s Encrypt 已停止到期提醒郵件；本工具不提供 SMTP 或 Teams 通知介面。受控 `settings.json` 會在下載及 Staging／正式操作前重建，自行填入的 SMTP 可能被覆寫，請由管理員另行規劃並測試通知或外部監控。

通知官方說明：[Let’s Encrypt](https://letsencrypt.org/docs/expiration-emails/)；[win-acme](https://www.win-acme.com/manual/automatic-renewal)。

## 最快使用流程

1. 解壓縮整個資料夾，執行 `MSTECH.IisSslManager.exe`，切換至「1 申請設定」。v1.3 尚未做程式碼簽章，Windows UAC 可能顯示「未知的發行者」。
2. 按「下載建議版本」，由工具下載並核對固定的官方 win-acme；管理員帳號與密碼只交給 Windows UAC，本工具不會讀取或保存。
3. 選擇本機 IIS 網站。
4. 選擇「一般網域」或「SAN 多網域」，只輸入完整網域名稱，不要輸入 `https://`、Port 或路徑。
5. 填寫 Let’s Encrypt 聯絡信箱，閱讀並勾選服務條款及 Certificate Transparency 提示。
6. 執行前兩階段檢查。黃色項目必須由操作人員明確確認；紅色項目會阻擋下一步。
7. 執行 Let’s Encrypt Staging。工具會完成外部驗證與測試憑證簽發，並在固定 win-acme 進入「是否儲存測試憑證」互動提示時安全結束該次 Staging；測試輸出只允許寫入 `%ProgramData%` 下僅 Administrators／SYSTEM 可存取的隨機暫存目錄，完成後確認刪除，不匯入 WebHosting、不修改 IIS、不建立續期排程或 Staging renewal。
8. 檢查正式 Binding 預覽，再按「正式申請並安裝」。工具會先建立 IIS `appcmd` 備份，失敗或安裝後驗證不符時自動復原。
9. 成功後確認畫面顯示 SYSTEM 自動續期排程已就緒。

## 執行前必要條件

- 作業系統為 Windows Server 2016／2019／2022／2025 x64，且有 IIS 10 管理工具及 `appcmd.exe`。
- IIS 網站已啟動；所有 SAN 名稱都由同一個選取網站管理。
- 公開 A／AAAA／CNAME 最後能到達此伺服器，或能正確轉送 ACME Challenge 的前端設備。
- Internet 能以 TCP 80 存取每個網域；`/.well-known/acme-challenge/` 不可被登入、WAF、Rewrite、CDN 或 Load Balancer 阻擋。
- 若 DNS 有 CAA，必須允許 `letsencrypt.org`。
- 伺服器能向外連線到 Let’s Encrypt ACME API TCP 443，Windows 日期與時間正確。
- 若同一 Host Header 已存在於其他 IIS 網站的 Port 80 或 Port 443，必須先排除衝突。

一般網域與 SAN 多網域都使用 HTTP-01，不需要新增 `_acme-challenge` TXT。只有 Wildcard（例如 `*.example.com`）需要 DNS-01；Wildcard 不在 v1.3 支援範圍。

## 三階段安全閘門

正式簽發必須在同一次執行階段依序通過：

1. 公開環境：網域格式、A/AAAA/CNAME、有效 CAA、HTTP 路徑、Production/Staging ACME API、系統時間。
2. 本機管理員環境：IIS 與網站、Port 80/443 衝突與變更預覽、W3SVC、HTTP.sys、Task Scheduler、`LocalMachine\WebHosting` 讀寫權限、win-acme SHA-256 及 RSA 2048 設定。
3. Let’s Encrypt Staging：由外部 ACME 伺服器實際完成每個名稱的 HTTP-01 驗證。

三階段結果會綁定申請模式、網域清單、IIS Site ID、win-acme 路徑與 SHA-256、聯絡信箱及驗證模式；設定變更或結果超過 30 分鐘後必須重驗。

## win-acme 與自動續期

- 固定測試版本：win-acme `2.2.9.1701 x64 trimmed`。
- 官方 ZIP SHA-256：`F4DC3B144841FFDBA391CE168C273D7A686D45A359075E30EE4BF4EE186857D6`。
- `wacs.exe` SHA-256：`FDFF5C5612E0BCBC8ABA52720E5D37E5C3821267179E2FA7341084148AD4B1EA`。
- 工具管理版本安裝於 `%ProgramData%\MSTECH-IisSslManager\win-acme`，並使用 RSA 2048-bit 設定。
- ACME 帳號、renewal、cache 與 log 使用 `%ProgramData%\MSTECH-IisSslManager\win-acme-state` 專用受保護目錄及 `MSTECH-IisSslManager` 工作名稱，不共用或改寫其他 win-acme 安裝的狀態。
- 正式憑證存入 `LocalMachine\WebHosting`，IIS 安裝由 win-acme 的 IIS plugin 執行。
- 正式申請停用 win-acme 憑證 cache 重用；若中斷後重試仍回傳既有憑證，只有在所有申請名稱均由同一張有效、含私鑰且 SAN 完整的 WebHosting 憑證綁定，並且 SNI 全部正確時才接受。
- 工具先以不建立排程的方式完成正式簽發及 IIS 驗證；全部成功後才建立每日 SYSTEM 排程，並再次核對排程已啟用、只有一個允許的執行動作、執行檔路徑正確且 Run As 為 SYSTEM。
- 舊憑證使用 `--keepexisting` 保留；續期成功後由受保護的本機腳本排定 30 天清理。清理前若任何 IIS HTTPS Binding 或 HTTP.sys SSL 註冊仍引用該指紋，就不會刪除；無法完成使用狀態檢查時也不刪除。

「選擇檔案」可用來檢查既有 `wacs.exe` 的版本與雜湊；v1.3 的 Staging／正式操作只執行固定測試 SHA-256，避免以 UAC 執行未受信任程式。

一般權限介面與 UAC 管理員工作程序之間的請求會驗證 SHA-256，回傳結果則使用每次操作隨機產生的 HMAC-SHA256 金鑰驗證。結果遭置換或修改時會失敗關閉，不會解鎖下一階段。

## IIS Binding 與復原

- 工具不會自動刪除其他網站的 Binding。
- 缺少精確 Port 80 Binding 時，HTTP-01 使用 win-acme SelfHosting；只有 Staging 成功才代表外部路徑真的可用。
- 正式安裝會對每個名稱建立或更新選取網站的 SNI `*:443:<host>` Binding。
- 正式操作前以 `appcmd add backup` 建立完整 IIS 設定備份。
- 工具同時以固定 renewal ID 快照本次網站專用的 win-acme renewal 狀態；不會回復或改寫其他 renewal。
- 簽發後會確認每個預期 Binding 均共同使用本次可安全確認的憑證指紋、`WebHosting` 存放區與 SNI；任一項不符即視為失敗。
- win-acme 非零結束或簽發後驗證失敗時，工具會同時復原該網站的 renewal 狀態與 `appcmd` 備份；復原結果會寫入 Log。

## 「登入 Windows 後自動開啟」勾選

此勾選只寫入目前使用者的 `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`，登入後開啟管理介面。它不需要也不保存管理員密碼。

憑證續期與 GUI 自動開啟是兩件事：即使沒有人登入、GUI 沒有開啟，win-acme 的 SYSTEM 工作排程仍會每日檢查是否需要續期。真正修改 IIS、憑證或排程的操作會另外由 Windows UAC 驗證權限。

## Log 與故障排除

- 一般權限的介面設定與 Log：`%LocalAppData%\MSTECH\IisSslManager`；管理員 GUI 可能改用受控 `%ProgramData%\MSTECH-IisSslManager` 根目錄。請由「開啟 Log 資料夾」確認實際紀錄位置。
- 需要系統權限的 win-acme 狀態與 Log：`%ProgramData%\MSTECH-IisSslManager\win-acme-state`。
- 警告與錯誤在權限允許時也會寫入 Windows Application Event Log。
- 本工具管理的 win-acme Log 位於 `%ProgramData%\MSTECH-IisSslManager\win-acme-state\Logs`。

若正式畫面顯示「IIS 自動復原未成功」，請不要再次簽發，立即開啟 IIS Manager、`appcmd list backups` 及本工具 Log 人工確認。

## v1.3 支援範圍

支援：本機 IIS、一般單網域、同一 IIS 網站的 SAN 多網域、HTTP-01 SelfHosting、WebHosting Store、SYSTEM 自動續期、目前使用者登入開啟 GUI、檔案與 Windows Event Log。

不支援：Wildcard、DNS-01、Server Core、跨 IIS 網站 SAN、Central Certificate Store、遠端 IIS、自動修改 CDN/WAF/Load Balancer、電子郵件或 Teams 通知。

## 開發建置

需要 .NET 10 SDK：

```powershell
dotnet build .\Mstech.IisSslManager.csproj -c Release
dotnet publish .\Mstech.IisSslManager.csproj -c Release -r win-x64 --self-contained true
```

執行 `..\Mstech.IisSslManager.SmokeTests` 可驗證網域、IIS parser、Staging／Production 命令、秘密遮罩、UAC 回傳驗證、受保護暫存路徑、續期排程動作白名單、HTTP.sys 保留檢查與版本一致性。版本紀錄請見 `CHANGELOG.md`；維護前必須先閱讀 `AGENTS.md`。

發行使用 `powershell -ExecutionPolicy Bypass -File .\build-release.ps1`，會先跑測試，成功後才產生 v1.3 ZIP 與 SHA-256。腳本不刪除舊包；同名輸出已存在時會停止，可用 `-OutputRoot` 指定另一個位於主專案內的新目錄。

## 開發者資訊

名世科技有限公司　MSTECH LTD.  
TEL：04-23956110  
FAX：04-23956117  
E-mail：service@mstech.tw  
聯絡地址：台中市太平區立德街89號
