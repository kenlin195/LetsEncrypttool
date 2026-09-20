# 儲存庫維護入口

這是 `kenlin195/LetsEncrypttool` 的本機 Git 工作目錄，初始版本 v1.3。

修改前必須先讀取：

1. 本目錄 `README.md`。
2. `Mstech.IisSslManager/AGENTS.md` 全部安全不變條件。
3. `Mstech.IisSslManager/README.md` 與 `CHANGELOG.md`。
4. `git status` 和相關差異，保留既有使用者修改。

`移交文件` 是歷史資料；其中尚未使用 Git／1.1v 的敘述不再代表現況，不得據此重新初始化或覆寫現在的歷史。

不得提交憑證私鑰、PFX、實際 ACME 帳號與續期狀態、credential、客戶執行紀錄或建置產物。第三方 ZIP 只保留本機，來源及雜湊記錄於 `references/README.md`。

GitHub 初始為私人儲存庫。不要自行改公開、變更授權、force-push 或把其他本機專案資料加入本庫。

建置／測試／發行依主專案規則；不得把開發機 smoke 或離線 WPF 渲染測試描述成完成真實 IIS／ACME 簽發驗收。
