# v1.3 PDF 手冊來源

`build_manual.py` 是繁體中文安裝操作說明書的可維護來源，使用 ReportLab 與 Windows 微軟正黑體（一般／粗體 TTC），沿用專案內 `Assets/mstech-logo.jpg`，不讀取 IIS、憑證、ACME 帳號或任何使用者實際資料。

在主專案目錄執行（需 Python 3 與 `reportlab`）：

```powershell
python .\docs\manual\build_manual.py
```

輸出：`output/pdf/MSTECH-IIS-SSL-v1.3-安裝操作說明書.pdf`，12 頁，含內嵌中文字型、頁碼、書籤及官方參考連結。程式會檢查缺字與每頁內容越界；執行會重新產生此明確目標檔案。

每次修改後，必須另外用 Poppler 逐頁渲染並人工查看，不能只信任文字抽取或高度檢查。例如先建立 `tmp/pdfs/`，再執行：

```powershell
pdftoppm -r 120 -png .\output\pdf\MSTECH-IIS-SSL-v1.3-安裝操作說明書.pdf .\tmp\pdfs\manual
```

逐頁確認繁體中文、表格、超連結、頁碼與下緣均完整無裁切，再清理 `tmp/pdfs/`。建議用 `pypdf` 額外確認 12 頁、可擷取中文與無附件；不得放入私鑰或真實執行資料。

`output/pdf/` 根層只放目前版本手冊，因發行腳本要求該層恰有一份 PDF。v1.2 舊手冊保留於 `output/pdf/archive/`，不會加入新版發行包。重新封裝請指定新的專案內 `-OutputRoot`，不要覆寫既有同名 ZIP 與 SHA-256。
