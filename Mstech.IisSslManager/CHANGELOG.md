# 版本紀錄

所有重要修改都必須記錄在此檔案。日期使用台北時區；目前使用者介面版本顯示為 `v1.3`，Windows／.NET 數字版本為 `1.3.0.0`。

## v1.3 — 2026-09-20

### 可靠性與防誤操作

- 提前讀取既有 HTTPS Binding 的 SslFlags；本機預檢阻擋非 SNI、CCS 或未知設定，附人工處理說明，不自動修改 IIS。
- 加強續期排程完整參數、正式 ACME 環境、有效每日觸發條件與未來執行時間檢查；排程問題仍保留已驗證的有效憑證。
- 正式申請前增加既有／新續期網域差異預覽；移除網域必須額外同意，並使用狀態雜湊避免預覽後設定變更仍繼續。簽發後對照固定 win-acme schema 驗證續期設定內容，保留既有回復機制。
- 修正重新讀取相同 IIS Site ID 時不必要地清除驗證 gate；不同 Site ID 仍須重驗。正式預覽完成後再次檢查 30 分鐘 gate，有效期亦會在閒置畫面更新。

### 介面與維護

- 依業主要求建立 `kenlin195/LetsEncrypttool` 私人 GitHub 儲存庫，以 v1.3 作為初始來源基準；新增儲存庫首頁、維護入口、敏感資料與建置產物排除規則。原始碼、測試、Logo、PDF 與維護文件納管，第三方 ZIP 僅保留本機並記錄來源與雜湊，不改變程式執行行為。
- 新增「憑證與續期狀態」唯讀首頁，顯示 IIS 443 憑證期限／剩餘天數及排程檢查、上次／下次執行、上次結果；未知或查詢失敗不顯示為成功，排程執行成功不冒稱實際續期成功。
- 黃色警告保留警告色，但人工確認後改顯示「已人工確認」；取消確認時提示黃色項目，不再一律要求修正不存在的紅色項目。
- 修正聯絡信箱說明：不會自動提供異常／到期通知；受控 settings.json 重建可能覆寫自訂 SMTP，通知或外部監控需另行規劃與驗證。
- 版本提升至 v1.3 / 1.3.0.0；首頁版本共用 AppVersion。
- PDF 安裝手冊同步更新為 v1.3，共 12 頁，補充初次安裝與同機升級、唯讀狀態首頁、排程完整檢查、SNI／CCS、SAN 網域縮減、黃色人工確認、30 分鐘 gate 與通知限制。新增可維護的 ReportLab 來源，v1.2 PDF 移至 archive 保留；此文件更新不改動程式功能或版本號。
- 補充 SNI／CCS、排程條件、憑證期限、續期設定與網域縮減、人工確認與 gate 的回歸測試。
- 發行腳本改由專案版本產生檔名，先通過 smoke tests 再於獨立目錄建置；不再刪除舊發行包。相同版本輸出已存在時明確停止，請另指定專案內 OutputRoot。

本輪不在開發機執行實際 IIS／憑證／工作排程修改或 ACME 簽發；Windows Server 端到端驗收仍須另於指定測試機完成。

### 開發機驗證

- Release 建置 0 warning／0 error；18/18 smoke tests 通過。
- 使用合成資料離線渲染 WPF 六個畫面，確認首頁、最小寬度、捲動、環境確認、申請設定與紀錄頁；未觸發視窗 Loaded／Closed 或實際系統操作。
- 真實 ComboBox 雙向選取綁定測試確認重新載入相同 Site ID 不會誤清 gate，不同 Site ID 仍會清除。

## v1.2 — 2026-08-31

### 安全修正

- 修正 Let’s Encrypt Staging 在外部驗證與測試憑證簽發成功後永久停住：固定 win-acme 的 `--test` 模式會用 `Console.ReadKey()` 詢問是否儲存測試憑證，但提升權限 worker 刻意使用無主控台的隱藏程序。工具現在只對已核對 SHA-256 的固定版本辨識該簽發完成提示，立即終止 Staging 子程序、確認程序已結束並清除受保護暫存目錄；Production 不允許使用此完成條件。
- 修正 ProgramData 既有 ACL 的寫入權限判斷：不再因 `FullControl`／`Modify` 複合旗標包含讀取位元，而把內建 Users 的合法「讀取與執行」誤判為可寫；Users 實際具有寫入、刪除或變更 ACL 權限時仍會 fail-closed 拒絕接管。

### 介面與維護

- 新增「關於本軟體與使用聲明」頁面，沿用名世科技提供的 Logo，清楚說明無償使用、技術支援範圍、使用前備份提醒及公司聯絡資訊；內容區可捲動且視窗可縮放。
- 新增 11 頁繁體中文 PDF 安裝操作說明書，涵蓋系統需求、DNS／NAT／Port 80、黃色警告、Staging、正式安裝、SYSTEM 自動續期、安裝後驗證與常見問題，並納入 v1.2 發行包。
- 顯示版本更新為 `v1.2`，Assembly／File／Manifest 版本更新為 `1.2.0.0`，下載 User-Agent 更新為 `1.2.0`。
- 發行檔名更新為 `MSTECH-IisSslManager-v1.2-win-x64.zip`。
- 將 `CertificateRetention.ps1` 原始資源固定為含 BOM 的 UTF-8，避免繁中 Windows PowerShell 5.1 依系統 ANSI code page 誤判語法；smoke test 同步鎖定資源編碼及 HTTP.sys fail-closed 檢查。
- 修正 `build-release.ps1` 在 Windows PowerShell 5.1 參數預設值階段無法取得 `$PSScriptRoot` 的問題，無參數執行現在可正確輸出至專案內 `artifacts`。

## 1.1v — 2026-08-24

### 安全修正

- 將提升權限 worker 協定升級為第 2 版。一般權限介面除了驗證 request 的 SHA-256，現在也會以每次操作隨機產生的 HMAC-SHA256 驗證管理員 worker 回傳結果；結果檔遭竄改、置換或使用錯誤金鑰時一律拒絕採信。
- 將 Let’s Encrypt Staging 產生的測試 PFX 從一般使用者 `%TEMP%` 移到工具受控的 `%ProgramData%\MSTECH-IisSslManager\Temporary\Staging\<GUID>`，目錄只允許 Administrators 與 SYSTEM 存取，建立與清理前均檢查 reparse point。
- 強化 win-acme 自動續期工作排程核對：排程必須只有一個允許的 `wacs.exe --renew` 執行動作；含額外動作的排程不再被視為就緒。
- 舊憑證 30 天清理除了檢查 IIS HTTPS Binding，也會以 `netsh http show sslcert` 檢查所有 HTTP.sys SSL 註冊；無法檢查或仍被引用時採 fail-closed，保留舊憑證。

### 品質與維護

- 顯示版本更新為 `1.1v`，Assembly／File／Manifest 版本更新為 `1.1.0.0`，下載 User-Agent 更新為 `1.1.0`。
- 發行檔名更新為 `MSTECH-IisSslManager-1.1v-win-x64.zip`。
- 新增提升權限回傳防竄改、受保護 Staging 路徑、排程動作白名單、HTTP.sys 清理防護及版本一致性 smoke tests。
- 新增本版本紀錄與 `AGENTS.md` 專案維護記憶文件，並將兩者納入發行包。
- 2026-08-30 新增獨立開發移交資料、乾淨來源封裝腳本、接手提示詞與 Windows Server 實機驗收清單；此項不改變 1.1v 執行行為。

## v1.0 — 2026-08-20

- 第一個可執行版本。
- 支援 Windows Server 2016 以上、IIS 10、一般網域與同一網站 SAN 多網域。
- 建立公開預檢、本機 UAC 預檢、Let’s Encrypt Staging 與 Production 三階段閘門。
- 固定並驗證 win-acme `2.2.9.1701 x64 trimmed`，正式簽發後核對 IIS Binding、WebHosting、SNI、renewal 狀態與 SYSTEM 自動續期排程。
- 正式操作前建立 IIS 備份，失敗時復原 renewal 與 IIS 設定；舊憑證保留 30 天。
- 新增目前使用者登入後開啟 GUI、Log、關於我們與名世科技 Logo／聯絡資訊。
