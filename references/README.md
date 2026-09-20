# 固定第三方參考資料

為保持來源庫精簡並避免將第三方二進位／範例憑證混入本專案，原始 ZIP 僅保留於本機，不提交 Git。一般建置與 smoke tests 不需要這些 ZIP；核對 win-acme CLI／schema 或升級固定版本時才需要。

## win-acme 執行套件

- 版本：`2.2.9.1701 x64 trimmed`。
- 官方專案：<https://github.com/win-acme/win-acme>。
- 官方下載網址以 `Mstech.IisSslManager/Services/WinAcmeModels.cs` 中 `WinAcmeRecommendedRelease.DownloadUri` 為準。
- 本機參考檔名：`win-acme.v2.2.9.1701.x64.trimmed.zip`。
- ZIP SHA-256：`F4DC3B144841FFDBA391CE168C273D7A686D45A359075E30EE4BF4EE186857D6`。
- `wacs.exe` SHA-256：`FDFF5C5612E0BCBC8ABA52720E5D37E5C3821267179E2FA7341084148AD4B1EA`。

## 固定來源快照

- 官方來源 commit：[3f6d83bbbfbecef94ee5049fa2859f6f2cf84a24](https://github.com/win-acme/win-acme/tree/3f6d83bbbfbecef94ee5049fa2859f6f2cf84a24)。
- 本機參考檔名：`win-acme-source-3f6d83b.zip`。
- 原始參考 ZIP SHA-256：`A9DD434DA0A490435D2B50FAE65E850C507A33C6C6428C29233C1BBF62268E3F`。

外部封裝格式改變時，即使 commit 相同也不可直接假定 ZIP 雜湊相同；應重新核對來源與內容。任何 win-acme 升級仍須遵守主專案 AGENTS 的完整核對與實機驗證要求。
