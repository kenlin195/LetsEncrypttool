# Windows Server 實機驗收清單

此清單尚未在本開發工作區執行完成。測試必須使用業主明確指定的測試伺服器、測試 IIS Site 與可控制的公開網域；不要直接在唯一正式站台上做第一次驗收。

## A. 測試前準備

- [ ] Windows Server 2016／2019／2022／2025 x64 Desktop Experience，記錄實際版本與 patch level。
- [ ] IIS 10、Management Tools、`appcmd.exe` 已安裝。
- [ ] 建立專用測試 IIS Site，不與正式客戶站台混用。
- [ ] 準備一般網域與至少兩個 SAN 名稱；A／AAAA／CNAME 皆可控制。
- [ ] Internet TCP 80 可到達測試機或正確的前端轉送設備。
- [ ] 檢查 CAA 允許 `letsencrypt.org`。
- [ ] 備份 IIS configuration、現有憑證與私鑰，記錄還原方式。
- [ ] 記錄測試前 IIS Binding、WebHosting cert store、Task Scheduler 與 `%ProgramData%\MSTECH-IisSslManager` 狀態。

## B. 安裝與一般權限

- [ ] 從發行 ZIP 完整解壓縮後執行，不要直接在 ZIP 內啟動 EXE。
- [ ] 未提升權限時 GUI 正常啟動，不要求輸入或保存 Windows 密碼。
- [ ] UAC 取消時操作安全停止，沒有殘留成功狀態。
- [ ] 「登入 Windows 後自動開啟」只改目前使用者 HKCU Run；取消勾選可正確移除。
- [ ] GUI 自動開啟與 SYSTEM 憑證續期的說明清楚且互不依賴。

## C. 公開與本機預檢

- [ ] 正確網域全部通過 DNS／CAA／HTTP／ACME／clock 檢查。
- [ ] 錯誤 A 或殘留錯誤 AAAA 會阻擋或明確警告。
- [ ] Port 80 被防火牆／WAF／登入阻擋時不會誤判為可正式簽發。
- [ ] 其他 IIS Site 有相同 Port 80/443 Host Header 時會阻擋。
- [ ] IIS Site 未啟動、W3SVC／HTTP／Schedule 未執行、WebHosting 不可寫時會阻擋。
- [ ] 被替換或 hash 不符的 `wacs.exe` 不會透過 UAC 執行。
- [ ] 變更網域、Site、信箱或 wacs 後，先前 gate 立即失效。
- [ ] gate 超過 30 分鐘後必須重驗。

## D. Let’s Encrypt Staging

- [ ] Staging 對單網域完成外部 HTTP-01。
- [ ] Staging 對 SAN 全部名稱完成外部 HTTP-01。
- [ ] Staging 前後 IIS Binding、WebHosting store 與 Task Scheduler 沒有改變。
- [ ] `%ProgramData%\MSTECH-IisSslManager\Temporary\Staging\<GUID>` 在完成後刪除。
- [ ] 故意造成 challenge 失敗時，Production 按鈕維持停用。
- [ ] 測試 PFX 清除失敗時採 fail-closed，不會解鎖 Production。

## E. Production 正式簽發

- [ ] 使用專用測試網域與維護時段執行第一次正式簽發。
- [ ] 操作前建立 IIS appcmd backup，記錄 backup name。
- [ ] 正式憑證位於 `LocalMachine\WebHosting` 且具有私鑰。
- [ ] SAN 完整，憑證鏈、有效期間與 Production issuer 正確。
- [ ] 所選 IIS Site 的每個名稱都有 `*:443:<host>` SNI Binding，且共同使用新 thumbprint。
- [ ] HTTPS 實際連線與瀏覽器／TLS 掃描正確。
- [ ] renewal JSON 使用固定網站專用 ID，沒有改寫其他 win-acme renewal。
- [ ] SYSTEM renewal task 已啟用、只有一個 `wacs.exe --renew` 動作、路徑是受控版本。

## F. 續期、重開機與復原

- [ ] 在不觸發 Production rate limit 的受控方式下完成一次實際 renewal 驗收。
- [ ] renewal 後 IIS Binding 切到新憑證，舊憑證仍保留。
- [ ] 無人登入時 SYSTEM task 可執行。
- [ ] 重新開機後 task、IIS Binding、憑證私鑰與 HTTPS 均正常。
- [ ] 在專用測試站台模擬 wacs 非零退出，確認 renewal 與 IIS backup 復原。
- [ ] 模擬簽發後 Binding 驗證不符，確認 fail-closed 並復原。
- [ ] 模擬復原失敗時 UI／Log 明確要求人工介入，不會宣稱成功。

## G. 舊憑證清理

- [ ] 只使用可拋棄的測試憑證驗證 retention script。
- [ ] 舊 thumbprint 仍在任一 IIS HTTPS Binding 時不刪除。
- [ ] 舊 thumbprint 仍在任一 HTTP.sys `sslcert` 時不刪除。
- [ ] `netsh http show sslcert` 查詢失敗時不刪除。
- [ ] 確認完全未使用後，才從 WebHosting 移除舊憑證。
- [ ] 一次性 cleanup task 的結果與殘留情況有紀錄。

## H. 驗收證據

每項至少保存：測試日期、Windows 版本、IIS Site ID、測試網域、工具版本、wacs hash、畫面截圖、應用程式 Log、win-acme Log、IIS backup name、簽發前後 thumbprint、Task Scheduler XML／截圖與結果。不得把私鑰、PFX 密碼或帳號 secret 放進一般移交文件。

全部必要項目通過後，才能在 `CHANGELOG.md` 記錄「已完成哪個 Windows Server 版本與哪種場景的實機驗收」；不要只寫籠統的「正式可用」。
