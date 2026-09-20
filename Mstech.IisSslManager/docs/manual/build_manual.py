"""Build the v1.3 Traditional Chinese installation manual (Windows fonts).

Run from any directory: python docs/manual/build_manual.py
Requires reportlab. PDF generation never reads IIS, ACME state or credentials.
Each page is explicitly composed and checked for vertical overflow.
"""
from pathlib import Path
from xml.sax.saxutils import escape

from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle


ROOT = Path(__file__).resolve().parents[2]
OUTPUT = ROOT / "output/pdf/MSTECH-IIS-SSL-v1.3-安裝操作說明書.pdf"
VERSION = "v1.3"
DATE = "2026-09-20"
TOTAL = 12
W, H = A4
LEFT = 44
WIDTH = W - LEFT * 2
BLUE = colors.HexColor("#126CA8")
INK = colors.HexColor("#23394A")
MUTED = colors.HexColor("#5D7283")
LINE = colors.HexColor("#D9E4EB")
PALE = colors.HexColor("#EDF5FA")
AMBER = colors.HexColor("#FFF4DE")
GOLD = colors.HexColor("#F3AC3A")


def register_fonts():
    fonts = Path("C:/Windows/Fonts")
    pdfmetrics.registerFont(TTFont("JhengHei", str(fonts / "msjh.ttc"), subfontIndex=0))
    pdfmetrics.registerFont(TTFont("JhengHeiBold", str(fonts / "msjhbd.ttc"), subfontIndex=0))
    pdfmetrics.registerFontFamily("JhengHei", normal="JhengHei", bold="JhengHeiBold")


class Manual:
    def __init__(self):
        OUTPUT.parent.mkdir(parents=True, exist_ok=True)
        self.c = canvas.Canvas(str(OUTPUT), pagesize=A4, pageCompression=1)
        self.c.setTitle("MSTECH IIS SSL 自動更新工具 v1.3 安裝操作說明書")
        self.c.setAuthor("名世科技有限公司")
        self.c.setCreator("MSTECH manual builder / ReportLab")
        self.c.setSubject("安裝、DNS/NAT、Staging、IIS 憑證及 SYSTEM 自動續期操作")
        self.page = 0
        self.y = 0
        self.bottoms = []

    def para(self, text, size=11, leading=18, bold=False, color=INK):
        text = text.replace("\n", "<br/>")
        # Reject missing glyphs, including accidentally pasted emoji.
        plain = text.replace("<br/>", " ")
        import re
        plain = re.sub(r"<[^>]*>", "", plain)
        from html import unescape
        plain = unescape(plain)
        cmap = pdfmetrics.getFont("JhengHeiBold" if bold else "JhengHei").face.charToGlyph
        missing = {c for c in plain if not c.isspace() and ord(c) not in cmap}
        if missing:
            raise ValueError(f"Missing font glyphs: {missing}")
        return Paragraph(text, ParagraphStyle(
            "body", fontName="JhengHeiBold" if bold else "JhengHei", fontSize=size,
            leading=leading, textColor=color, wordWrap="CJK", alignment=TA_LEFT,
            splitLongWords=True, allowWidows=0, allowOrphans=0,
        ))

    def draw(self, flowable, gap=10):
        _, height = flowable.wrap(WIDTH, H)
        if self.y - height < 55:
            raise ValueError(f"Page {self.page} overflow: bottom={self.y - height:.1f}")
        flowable.drawOn(self.c, LEFT, self.y - height)
        self.y -= height + gap

    def text(self, text, **kwargs):
        self.draw(self.para(text, **kwargs))

    def heading(self, text):
        self.draw(self.para(text, 13.1, 20, True, BLUE), gap=7)

    def bullet(self, text):
        self.text("<font color='#126CA8'>•</font> " + text)

    def step(self, number, title, text):
        self.text(f"<b><font color='#126CA8'>{number:02d}　{title}</font></b><br/>{text}")

    def callout(self, title, text, warning=False):
        p = self.para(f"<b>{title}</b><br/>{text}", 10.4, 16.5)
        t = Table([[p]], colWidths=[WIDTH])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, -1), AMBER if warning else PALE),
            ("BOX", (0, 0), (-1, -1), 0.5, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 13),
            ("RIGHTPADDING", (0, 0), (-1, -1), 13),
            ("TOPPADDING", (0, 0), (-1, -1), 10),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 10),
        ]))
        self.draw(t, gap=14)

    def table(self, headers, rows, ratios=(0.26, 0.74), size=10.0):
        data = [[self.para(h, size, 15.5, True, colors.white) for h in headers]]
        data += [[self.para(cell, size, 15.5) for cell in row] for row in rows]
        t = Table(data, colWidths=[WIDTH * x for x in ratios])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), BLUE),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F8FA")]),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("LINEBELOW", (0, 1), (-1, -1), 0.4, LINE),
            ("LEFTPADDING", (0, 0), (-1, -1), 10),
            ("RIGHTPADDING", (0, 0), (-1, -1), 10),
            ("TOPPADDING", (0, 0), (-1, -1), 8),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 8),
        ]))
        self.draw(t, gap=14)

    def begin(self, title, label):
        if self.page:
            self.bottoms.append((self.page, round(self.y, 1)))
            self.c.showPage()
        self.page += 1
        self.c.setFillColor(BLUE)
        self.c.rect(0, H - 7, W, 7, fill=1, stroke=0)
        self.c.setFillColor(MUTED)
        self.c.setFont("JhengHei", 8.4)
        self.c.drawString(LEFT, H - 33, "MSTECH IIS SSL 自動更新工具")
        self.c.drawRightString(W - LEFT, H - 33, "安裝操作說明書  v1.3")
        self.c.setStrokeColor(LINE)
        self.c.line(LEFT, 42, W - LEFT, 42)
        self.c.setFont("JhengHei", 8)
        self.c.drawString(LEFT, 27, "名世科技有限公司  |  2026-09-20")
        self.c.drawRightString(W - LEFT, 27, f"{self.page:02d} / {TOTAL:02d}")
        self.c.bookmarkPage(f"page-{self.page}")
        self.c.addOutlineEntry(title, f"page-{self.page}", level=0)
        self.y = H - 63
        self.draw(self.para(label, 9, 14, True, BLUE), 6)
        self.draw(self.para(title, 24, 33, True), 18)

    def finish(self):
        self.bottoms.append((self.page, round(self.y, 1)))
        assert self.page == TOTAL, (self.page, TOTAL)
        self.c.save()
        print(f"Created {OUTPUT}")
        print(f"Pages: {self.page}; content bottoms: {self.bottoms}")


def build():
    register_fonts()
    m = Manual()

    m.begin("安裝操作說明書", "USER GUIDE / v1.3")
    m.c.drawImage(str(ROOT / "Assets/mstech-logo.jpg"), LEFT, m.y - 99,
                  width=325, height=99, preserveAspectRatio=True, mask="auto")
    m.y -= 133
    m.text("IIS SSL 自動更新工具", size=27, leading=36, bold=True)
    m.text("從第一次安裝，到日常憑證與續期維護。", size=15, leading=23, color=MUTED)
    m.y -= 12
    m.table(["本手冊適用", "版本與環境"], [
        ["軟體版本", "v1.3 / Windows 檔案版本 1.3.0.0"],
        ["適用平台", "Windows Server 2016 / 2019 / 2022 / 2025<br/>x64 Desktop Experience、IIS 10、本機網站"],
        ["文件更新", "2026 年 9 月 20 日"],
    ])
    m.heading("v1.3 閱讀重點")
    m.bullet("新增唯讀的憑證與續期狀態首頁，協助辨識到期提醒與排程問題。")
    m.bullet("正式申請前確認網域增減；既有 SNI 與續期排程檢查更完整。")
    m.bullet("黃色警告保留警告色，確認後清楚標示「已人工確認」。")
    m.callout("重要界線", "本手冊依 v1.3 程式行為編寫。文件、建置測試或離線介面檢查，不代表已完成您的正式主機、網域或續期驗收。請依第 12 頁逐項確認。")

    m.begin("先了解流程與支援範圍", "01 / 使用前必讀")
    m.table(["章節", "頁碼 / 內容"], [
        ["準備與安裝", "3　系統需求、DNS 與 NAT\n4　初次安裝、同機升級及資料位置"],
        ["申請憑證", "5　填寫申請設定\n6　環境檢查與黃色警告\n7　Staging 與三階段解鎖\n8　正式安裝與網域增減"],
        ["日常維護", "9　憑證與續期狀態首頁\n10　自動續期、通知與舊憑證\n11　常見問題排除\n12　驗收、支援與參考資料"],
    ])
    m.heading("適用與不適用的情境")
    m.text("支援一般單網域，以及同一個 IIS 網站的 SAN 多網域憑證。使用 HTTP-01 SelfHosting 驗證，正式憑證存入 LocalMachine\\WebHosting，並以 SNI 更新 HTTPS 443 Binding。")
    m.text("不支援 Wildcard（萬用字元）、DNS-01、Server Core、遠端 IIS、跨 IIS 網站 SAN 或 Central Certificate Store（CCS）。工具不會自動修改路由器、防火牆、CDN、WAF 或負載平衡器。")
    m.heading("整體操作順序")
    m.callout("初次申請", "完整解壓與下載 win-acme → 填寫申請設定 → 公開環境檢查 → 本機環境檢查 → Staging 外部驗證 → 確認網域差異 → 正式安裝 → 檢查排程與外部 HTTPS。")
    m.callout("先備份，並安排維護時段", "保留 IIS 設定、既有憑證及必要系統備份。工具的自動備份不能取代獨立備份；憑證或帳號資料應受保護，不要放入 Git、一般郵件或公開分享。操作時避免其他視窗、背景續期或管理員同時修改 IIS。", warning=True)
    m.text("管理員帳號與密碼只交由 Windows UAC 處理；本工具不接收或保存管理員密碼。", size=10, color=MUTED)

    m.begin("系統需求、DNS 與 NAT", "02 / 連線準備")
    m.table(["項目", "開始前確認"], [
        ["Windows / IIS", "支援的 Windows Server x64 Desktop Experience；已安裝 IIS 10、管理工具及 appcmd.exe，目標網站已啟動。"],
        ["權限 / 時間", "可完成管理員 UAC；日期、時區與時間同步正確。發行包為 self-contained，不需另裝 .NET Runtime。"],
        ["對外連線", "可查詢公開 DNS，並連到 Let's Encrypt ACME API TCP 443。"],
        ["驗證入口", "Internet TCP 80 必須能到達每個網域的 HTTP-01 驗證路徑；不能只開 443 或對外自訂高位連接埠。[1]"],
    ])
    m.heading("A 紀錄指向公網 IP，主機使用內網 IP，可以使用")
    m.callout("NAT 路徑示意", "Internet 的網域 / 公開 IP:80<br/>↓ 路由器或防火牆 Port Forward<br/>IIS 主機的內部 IP:80<br/><br/>A 紀錄不必等於 IIS 的內部 IP。工具無法只靠本機證明 NAT 轉送正確，因此可能要求人工確認；仍需由 Staging 驗證外部可達性。")
    m.bullet("所有申請名稱都要有正確 A／AAAA／CNAME 解析；若有 AAAA，IPv6 路徑也必須正確。不要保留指向別台主機的 AAAA。")
    m.bullet("若設定 CAA，必須允許 letsencrypt.org。每個 SAN 名稱都要符合 DNS 與驗證條件。")
    m.bullet("登入驗證、Rewrite、WAF 或 Proxy 不可攔截 /.well-known/acme-challenge/；多台前端需確保驗證內容可正確到達。")
    m.bullet("不支援 NAT loopback 時，內網自行連線可能失敗。不要僅憑內網測試判斷；搭配外部測試與 Staging 結果。")
    m.text("[1] Let's Encrypt HTTP-01 官方說明：參考第 12 頁。正式網站 HTTPS 另需確認外部 TCP 443 路徑。", size=9.2, leading=14, color=MUTED)

    m.begin("初次安裝與同機升級", "03 / 程式與資料")
    m.step(1, "取得完整 v1.3 發行包", "使用名世科技提供的 MSTECH-IisSslManager-v1.3-win-x64.zip，核對隨附 SHA-256。完整解壓至固定資料夾；不要在 ZIP 內執行，也不要只複製單一 EXE。")
    m.step(2, "開啟管理介面", "執行 MSTECH.IisSslManager.exe，確認畫面版本 v1.3，再切換「1 申請設定」。本版尚未做程式碼簽章，Windows 可能顯示「未知的發行者」；請先確認檔案來源。")
    m.step(3, "下載受控 win-acme", "按「下載建議版本」並完成 Windows UAC。工具固定使用 win-acme 2.2.9.1701 x64 trimmed，核對 ZIP 與執行檔雜湊，再安裝至受保護目錄。")
    m.callout("既有 wacs.exe 不等於可直接正式申請", "「選擇檔案」可診斷既有 wacs.exe；Staging 與正式流程要求工具管理、已核對的固定版本。不要自行覆蓋受控程式或放寬 ProgramData 寫入權限。")
    m.heading("從 v1.2 升級到 v1.3")
    m.text("關閉舊介面，保留舊發行資料夾，將 v1.3 完整解壓到新資料夾再啟動。升級管理介面不需要重新簽發已有效的憑證。不要刪除 win-acme-state；先從首頁重新整理狀態。若原本啟用登入自動開啟，請在新版重新設定並確認指向新 EXE。")
    m.table(["資料", "位置（Windows 環境變數）"], [
        ["受控 win-acme", "%ProgramData%\\MSTECH-IisSslManager\\win-acme"],
        ["帳號 / 續期 / Log", "%ProgramData%\\MSTECH-IisSslManager\\win-acme-state<br/>win-acme 紀錄位於此目錄下的 Logs。"],
        ["介面設定 / Log", "一般權限：%LocalAppData%\\MSTECH\\IisSslManager<br/>以管理員身分啟動 GUI 時，可能改用受控 ProgramData 根目錄。實際紀錄位置請按「開啟 Log 資料夾」確認。"],
    ], size=9.5)
    m.text("升級時保留 ProgramData 資料與原有續期排程。備份帳號、續期及憑證資料時，需依公司規範限制存取。", size=9.4, leading=15, color=MUTED)

    m.begin("填寫申請設定", "04 / 選站台與網域")
    m.step(1, "選擇正確的本機 IIS 網站", "讀取 IIS 網站清單，依名稱與 Site ID 確認要安裝的站台。所有 SAN 名稱必須屬於同一個選取網站；不可用一次申請包辦多個不同 IIS 網站。")
    m.step(2, "選擇一般網域或 SAN 多網域", "一般網域輸入一個完整主機名稱；SAN 多網域逐項新增 2 到 100 個名稱。只填名稱，例如 www.example.com；不要填 https://、Port、路徑或 *.example.com。")
    m.step(3, "填寫聯絡信箱", "使用可正常收信且由管理人員維護的地址，供 ACME 帳號聯絡。這不會啟用到期提醒或異常告警，詳見第 10 頁。")
    m.step(4, "閱讀並完成必要勾選", "閱讀 Let's Encrypt 服務條款，確認 Certificate Transparency（憑證透明度）公開紀錄提示後勾選。憑證中的網域名稱會公開，請先評估名稱是否適合公開。")
    m.step(5, "核對 win-acme 與預覽", "確認路徑為工具管理的 wacs.exe，版本與完整性檢查符合要求。檢視目標網站、全部名稱與預計 HTTPS 443 Binding，再開始環境檢查。")
    m.table(["示例", "如何填寫"], [
        ["一般網域", "www.example.com"],
        ["同網站 SAN", "example.com、www.example.com<br/>兩個名稱都由同一網站提供，且都能通過 HTTP-01。"],
        ["不適用", "https://example.com、example.com:8443、*.example.com"],
    ])
    m.callout("再次申請不是只新增一個名稱", "同一網站已有受管理憑證時，本次清單可能取代該筆續期清單。請保留仍需要續期的全部名稱；正式執行前再核對第 8 頁的網域差異。", warning=True)

    m.begin("環境檢查與黃色警告", "05 / 公開與本機預檢")
    m.text("到「2 環境檢查」執行前兩階段檢查。先確認公開 DNS、CAA、HTTP 路徑，再依 UAC 指示檢查本機 IIS、權限、win-acme 與安裝條件。失敗時看該列說明及「如何修正」。")
    m.table(["畫面狀態", "意義與下一步"], [
        ["綠色：已通過", "該項已由工具檢查通過；不代表所有階段完成。"],
        ["黃色：需確認", "需由操作者確認真實環境或變更影響。在確認提示中明確同意後，才能繼續對應階段。"],
        ["黃色：已人工確認", "保留黃色顯示，記錄使用者已確認；本身不會讓 Staging 失敗，也不取代真正外部驗證。"],
        ["紅色：必要條件失敗", "先修正，再重新檢查。不可用人工確認略過。"],
    ])
    m.heading("DNS 指向人工確認：NAT 使用者常見")
    m.text("若公開 A 紀錄指向路由器公網 IP、IIS 只有內網 IP，這是合理架構。先確認外部 TCP 80 已轉送到該 IIS，所有名稱與 IPv6 路徑也正確，再接受人工確認。單純保持黃色不會阻止後續；尚未確認、紅色失敗或其他階段未通過，仍會鎖住按鈕。")
    m.heading("v1.3 新增：既有 HTTPS Binding 的 SNI 檢查")
    m.text("本次申請網域若已有 HTTPS 443 Binding，但未啟用 SNI、使用 CCS，或無法可靠讀取 SslFlags，本機預檢會停止。請由管理員在 IIS Manager 確認網站、主機名稱與 Binding 用途，再評估修正；工具不會自動勾選既有 SNI 或停用 CCS。")
    m.callout("不要把讀不到當作沒問題", "無權限、設定未知或與別站台衝突都需要處理。若尚無相符的 443 Binding，正式安裝可依預覽建立新的 SNI Binding；不要為了預檢而先亂綁既有憑證。", warning=True)

    m.begin("Staging 與三階段解鎖", "06 / 真正的外部驗證")
    m.step(1, "確認前兩階段已通過", "公開環境與本機環境均通過，黃色必要確認已完成，沒有紅色必要條件失敗。")
    m.step(2, "按「執行 Staging 驗證」", "完成必要的 UAC。Let's Encrypt 測試環境會從外部驗證每個名稱的 HTTP-01 路徑。SAN 中有任何名稱驗證失敗，都必須先處理。")
    m.step(3, "等候工具回報完成", "測試 PFX 使用受保護的隨機暫存目錄，完成後確認刪除。不匯入 WebHosting、不修改 IIS、不建立正式續期排程，也不把測試憑證當作正式憑證。")
    m.callout("Staging 失敗，先看原因，不要直接正式申請", "優先檢查 A／AAAA、NAT、防火牆、Port 80、WAF、Rewrite 與所有 SAN 名稱。暫存清除或權限檢查失敗也可能使整體 Staging 判定失敗，請看「3 執行紀錄」。")
    m.heading("正式申請按鈕何時可用？")
    m.table(["狀況", "結果"], [
        ["只有公開環境通過", "還需本機環境與 Staging；不能正式申請。"],
        ["黃色已人工確認", "可依階段繼續；仍須讓 Staging 實際通過。"],
        ["三階段均有效通過", "可進入正式申請前的網域差異與安裝確認。"],
        ["設定變更 / 超過 30 分鐘", "相關檢查與確認會失效；重新檢查受影響階段。"],
        ["關閉並重新開啟程式", "不沿用前次通過結果；正式操作前重新驗證。"],
    ])
    m.text("三階段是同一次程式工作階段內的安全閘門。停留在正式預覽太久，也可能需要重新驗證；勿嘗試跳過鎖定或修改結果檔。", size=10, color=MUTED)

    m.begin("正式安裝與網域增減", "07 / 最後確認")
    m.step(1, "查看現有與本次網域差異", "按「正式申請並安裝」後，依提示完成只讀的續期設定預覽，核對選取網站及將保留、新增或移除的名稱。移除任何名稱都要額外明確同意。")
    m.callout("SAN 縮減示例", "原本：example.com、www.example.com<br/>本次：example.com<br/><br/>確認後，www.example.com 不再包含於這筆續期設定；其舊 Binding 不會因此自動刪除，也不代表已有別的續期安排。若仍需維護該名稱，請取消並補回清單。", warning=True)
    m.step(2, "再次確認正式安裝", "確認網站、全部名稱、SNI 443 Binding 與 WebHosting 存放區。工具會先備份完整 IIS 設定及本次 renewal，再向正式 ACME 環境申請並安裝。")
    m.step(3, "等候獨立驗證與排程結果", "工具會重新檢查憑證有效性、私鑰、完整 SAN、renewal 設定，以及所有預期 Binding 是否使用同一張正確憑證。通過後才建立並核對 SYSTEM 續期排程。")
    m.table(["回報結果", "應如何處理"], [
        ["憑證與排程均就緒", "進行外部 HTTPS 與日常狀態驗收，見第 12 頁。"],
        ["憑證已安裝，排程異常", "有效憑證會保留，但不可認定自動續期正常。請處理排程；不要只為修排程反覆簽發。"],
        ["簽發 / 安裝驗證失敗", "工具嘗試復原本次 renewal 與 IIS 備份。若復原不完整，先人工檢查 IIS 與 Log，不要立即重試。"],
    ])
    m.text("若預覽後 renewal 被其他程序修改，正式執行會停止，必須重新預覽。完整 IIS 備份的復原可能影響同時發生的其他設定變更，請避免並行維護。", size=9.8, leading=15.5, color=MUTED)

    m.begin("憑證與續期狀態首頁", "08 / v1.3 日常檢查")
    m.step(1, "開啟首頁並重新整理", "在「憑證與續期狀態」按「重新整理狀態（唯讀）」，依需要完成 UAC。這是查詢，不會申請、續期、匯出私鑰或修改 IIS／排程。")
    m.step(2, "先看查詢時間與查詢是否成功", "資料只代表該次查詢的快照，不是背景持續監控。權限不足或讀取失敗會顯示未知；請排除原因後重新整理，不要把舊畫面當成即時結果。")
    m.table(["畫面區塊", "可確認與不能推論的事"], [
        ["IIS HTTPS 443 憑證", "列出本機 443 Binding 的憑證期限、剩餘天數與狀態。到期前 30 天提醒；逾期、尚未生效或缺少私鑰需處理。讀不到不等於憑證一定遺失。"],
        ["SYSTEM 續期排程", "只列本工具管理的排程，顯示設定檢查、上次／下次執行及結果。不是電腦上所有排程的總表。"],
        ["有效的憑證", "不代表外部 HTTPS、信任鏈、DNS／Proxy 或未來續期已驗證。仍需外部連線與紀錄檢查。"],
        ["上次排程成功", "表示程序上次成功結束，不代表當次一定換發憑證；可能只檢查後判定尚未到續期時間。"],
    ])
    m.callout("憑證清單不是受管理續期清單", "首頁會讀取本機 IIS 443 Binding，但沒有逐網站比對每一筆 renewal 是否涵蓋該站台。看見有效憑證加上健康排程，仍不能保證所有網站都已加入本工具的自動續期。", warning=True)
    m.heading("建議管理方式")
    m.text("部署後、調整網域／Binding 後與例行維護時重新整理。接近到期卻未看到有效換發紀錄時，立即查 win-acme Log 及排程結果；不要等到到期日才處理。若需自動提醒，另行部署並驗證監控。")

    m.begin("自動續期、通知與舊憑證", "09 / 背景維護")
    m.text("正式憑證及 IIS 驗證完成、排程就緒後，SYSTEM 每日檢查受管理 renewal 是否需續期。無需登入或保持 GUI 開啟；每日檢查不等於每日簽發。[3]")
    m.table(["排程就緒重點", "v1.3 的核對內容"], [
        ["身分 / 動作", "已啟用、以 SYSTEM 執行、只有一個允許的執行動作。"],
        ["程式 / 參數", "受控 wacs.exe 完整路徑及工作目錄；允許的 --renew 與正式 ACME 環境參數，無額外任意動作。"],
        ["觸發 / 下次執行", "有效且已啟用的每日觸發條件；下次執行時間在未來 48 小時內。48 小時是健康檢查容差，不是換發週期。"],
        ["上次結果", "與排程設定分別看待。0x41303 代表尚未執行；成功結果仍需搭配憑證期限及換發 Log。"],
    ])
    m.heading("聯絡信箱不會自動開啟到期或異常告警")
    m.text("Let's Encrypt 已停止到期提醒郵件服務。[2] 本工具未提供 SMTP 或 Teams 通知介面。win-acme 本身雖有郵件功能，[3] 但本工具在下載及執行 Staging／正式操作前會重建受控 settings.json，自行填入的 SMTP 設定可能被覆寫。請由管理員另行規劃並測試通知或外部監控。")
    m.heading("舊憑證的安全保留")
    m.text("續期後保留舊憑證 30 天，再由清理工作確認是否仍被任何 IIS HTTPS Binding 或 HTTP.sys 使用；仍在使用或查詢失敗就保留，不會猜測後刪除。30 天後仍被引用不保證之後自動重試清理，不要以手動大量刪除代替確認。")
    m.callout("登入後開啟 GUI 與自動續期是兩件事", "「登入 Windows 後自動開啟」只控制目前使用者登入時開啟管理介面，不會因此啟用、停用或代替 SYSTEM 續期排程。")
    m.text("[2][3] 官方通知及 win-acme 自動續期說明：參考第 12 頁。", size=9.2, leading=14, color=MUTED)

    m.begin("常見問題排除", "10 / 先判斷，再處理")
    m.table(["現象", "建議處理"], [
        ["下載顯示 ProgramData 拒絕存取", "確認執行 v1.3 並完成 UAC。請管理員查目錄擁有者、ACL 及連結／接合點設定。不可直接授予 Everyone 寫入權限；保留錯誤內容以供判斷。"],
        ["DNS 已正確，仍顯示黃色", "NAT／Proxy 需要人工確認屬正常情境。確認外部 TCP 80 路徑後接受提示；變為「已人工確認」仍保持黃色，接著執行 Staging。"],
        ["Staging 或正式按鈕不能按", "檢查缺少哪些階段、黃色是否未確認、是否有紅色失敗，或設定已變更／結果已超過 30 分鐘。正式申請必須三階段都有效通過。"],
        ["HTTP-01 驗證失敗", "逐一檢查所有網域 A／AAAA、外部 TCP 80、NAT、防火牆、WAF、Rewrite 與登入驗證。不要只測內網，也不要用正式簽發反覆試錯。"],
        ["既有 HTTPS Binding 被擋", "確認正確站台與 Host、SNI 已啟用，未使用 CCS 且設定可讀。<br/>由管理員評估調整，並保留其他網站 Binding。"],
        ["預覽後設定改變", "停止並查是否有其他程序更動 renewal；重新整理／預覽，必要時重跑檢查，不要強行沿用舊確認。"],
        ["憑證成功，排程未就緒", "檢查 Enabled、SYSTEM、唯一動作、程式／工作目錄、正式參數與有效每日觸發。修復排程後重新查詢；不需只為此重複申請憑證。"],
        ["顯示 IIS 自動復原未成功", "停止重試，先由管理員查看 IIS、IIS 備份及執行 Log，確認服務與 Binding 狀態，再決定復原方案。"],
        ["瀏覽器仍看到舊憑證", "先確認實際連到哪一台 IIS／CDN／Proxy，檢查該 Host 的 SNI Binding。首頁正常不等於外部流量經過這台主機。"],
    ], ratios=(0.28, 0.72), size=9.6)
    m.text("回報時附：v1.3 版本、發生時間、Windows / IIS 版本、操作階段、已遮罩的錯誤與 Log。不要附管理員密碼、私鑰、PFX、ACME 帳號金鑰或完整敏感狀態檔。", size=9.7, leading=15, color=MUTED)

    m.begin("驗收、支援與參考資料", "11 / 完成後保留這一頁")
    m.heading("安裝完成驗收清單")
    m.bullet("從外部網路開啟每個 https://網域，確認名稱、期限及信任狀態正確。")
    m.bullet("確認目標 IIS 站台的各個 SNI 443 Binding 使用正確 WebHosting 憑證。")
    m.bullet("重新整理狀態首頁，確認憑證、SYSTEM 排程與下次執行時間；查詢未知、排程警告或復原錯誤不得視為驗收通過。")
    m.bullet("保留備份與已遮罩的操作紀錄。<br/>後續確認每日執行與實際換發；安裝完成不代表已驗證未來續期。")
    m.callout("停用或移除前先確認影響", "只刪除 GUI 資料夾不會移除 IIS 憑證、Binding、renewal 或 SYSTEM 排程。完整停用應先安排替代憑證與續期機制，再由管理員逐項處理，避免服務中斷。")
    m.heading("名世科技有限公司 - 您的資訊服務好夥伴")
    m.text("本軟體由名世科技有限公司開發，旨在簡化 Microsoft IIS 環境中 Let's Encrypt SSL/TLS 憑證的申請、安裝與更新流程。本工具無償提供，歡迎使用、轉載與分享。", size=10, leading=16)
    m.text("免費範圍不包含遠端連線、伺服器環境設定、故障排除、客製化修改或其他技術支援；如有需求，請另行洽詢。", size=10, leading=16)
    m.text("地址：台中市太平區立德街 89 號<br/>電話：04-2395-6110<br/>問題回報：<link href='mailto:service@mstech.tw' color='#126CA8'>service@mstech.tw</link>", size=10, leading=16)
    m.heading("官方參考資料")
    for title, url in [
        ("[1] Let's Encrypt：HTTP-01 與其他驗證方式", "https://letsencrypt.org/docs/challenge-types/"),
        ("[2] Let's Encrypt：到期提醒郵件服務已停止", "https://letsencrypt.org/docs/expiration-emails/"),
        ("[3] win-acme：自動續期與監控", "https://www.win-acme.com/manual/automatic-renewal"),
    ]:
        m.text(f"{escape(title)}<br/><link href='{url}' color='#126CA8'>{url}</link>", size=8.8, leading=13)
    m.text("查核日期：2026-09-20。官方通用說明與本工具受控流程不同時，以本工具版本限制為準。win-acme 與 Let's Encrypt 為獨立第三方專案；相關權利及聲明見發行包 THIRD-PARTY-NOTICES.txt。", size=8.6, leading=13, color=MUTED)
    m.finish()


if __name__ == "__main__":
    build()
