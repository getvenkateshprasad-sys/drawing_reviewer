import http.server, socketserver, json, os, base64, re, io, traceback
from collections import Counter, defaultdict

PORT       = 5000
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC_DIR, **kw)

    def do_OPTIONS(self):
        self.send_response(200)
        for k,v in [("Access-Control-Allow-Origin","*"),("Access-Control-Allow-Methods","GET,POST,OPTIONS"),("Access-Control-Allow-Headers","Content-Type")]:
            self.send_header(k,v)
        self.end_headers()

    def do_GET(self):
        # Silently ignore favicon requests
        if self.path == "/favicon.ico":
            self.send_response(204)
            self.end_headers()
            return
        try:
            super().do_GET()
        except Exception as e:
            print(f"[server] GET error: {e}")

    def do_POST(self):
        try:
            n    = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(n)
            data = json.loads(body)
            pdf  = base64.b64decode(data.get("pdf", ""))
            if self.path == "/analyse":
                self._ok({"findings": analyse(pdf)})
            elif self.path == "/export":
                out = export(pdf, data.get("approved", []))
                self._ok({"pdf": base64.b64encode(out).decode()})
            else:
                self.send_response(404)
                self.end_headers()
        except Exception as e:
            print(f"[server] POST error: {e}")
            traceback.print_exc()
            try:
                self._ok({"error": str(e)}, 500)
            except Exception:
                pass

    def _ok(self, obj, code=200):
        p = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(p))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(p)

    def log_message(self, f, *a):
        print(f"[server] {f % a}")

# ── Patterns ──────────────────────────────────────────────────────────────────
TIGHT = re.compile(r"[\xb1]\s*0\.00[0-4]\d*")
LOOSE = re.compile(r"[\xb1]\s*[5-9]\d*\.?\d*")
DIM   = re.compile(r"\b(\d+\.?\d*)\s*(mm|in|\")", re.I)
TOL   = re.compile(r"[\xb1+\-]\s*\d+\.?\d+")

def F(id, type, sev, page, region, cur, sug, reason):
    return dict(id=id, type=type, severity=sev, page=page, region=region,
                current=cur, suggested=sug, reason=reason, status="open")

# ── Analyser ──────────────────────────────────────────────────────────────────
def analyse(pdf_bytes):
    try:
        import pypdf
    except ImportError:
        return [F("E0","install_error","high",1,"Server","","","Run: pip install pypdf reportlab")]
    try:
        reader = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    except Exception as e:
        return [F("E1","parse_error","high",1,"Server","",str(e),"Could not read PDF")]

    c = [0]
    def nid():
        c[0] += 1
        return f"F{c[0]:03d}"

    all_text, findings = "", []
    for pn, page in enumerate(reader.pages, 1):
        try:
            text = page.extract_text() or ""
        except Exception:
            text = ""
        all_text += text + "\n"
        findings += check(text, pn, nid)
    findings += dupes(all_text, nid)
    if not findings:
        findings.append(F(nid(),"info","low",1,"Full drawing","","",
            "No automated anomalies detected. Manual review still recommended."))
    return findings

def check(text, pn, nid):
    f = []; t = text.upper()

    for m in TIGHT.finditer(text):
        f.append(F(nid(),"extreme_tolerance","high",pn,f"Near: {m.group()}",
            m.group(),"+-0.01 (verify necessity)",
            "Tolerance tighter than +-0.005 is very hard to manufacture and inspect."))

    for m in LOOSE.finditer(text):
        f.append(F(nid(),"loose_tolerance","medium",pn,f"Near: {m.group()}",
            m.group(),"Review against fit/function",
            "Tolerance of +-5 or greater is unusually loose."))

    MAT = ["MATERIAL","MAT:","ALLOY","STEEL","ALUMIN","PLASTIC","BRASS","TITANIUM","COPPER","NYLON"]
    if not any(w in t for w in MAT):
        f.append(F(nid(),"missing_material","high",pn,"Title block",
            "No material found","Add e.g. EN AW-6082-T6",
            "Every drawing must specify material."))

    if not any(w in t for w in ["FINISH","ROUGHNESS","RA ","RZ "]) and "Ra" not in text:
        f.append(F(nid(),"missing_surface_finish","medium",pn,"Title block",
            "No surface finish","Add e.g. Ra 1.6",
            "Surface finish missing."))

    if not any(w in t for w in ["UNLESS OTHERWISE","GENERAL TOL","ISO 2768","ASME Y14","BS 8888"]):
        f.append(F(nid(),"missing_general_tolerance","medium",pn,"General notes",
            "No general tolerance note",
            "UNLESS OTHERWISE SPECIFIED: Linear +-0.1mm Angular +-0.5deg",
            "Untoleranced dimensions cause disputes."))

    if not any(w in t for w in ["REV","REVISION"]):
        f.append(F(nid(),"missing_revision","low",pn,"Title block",
            "No revision","Add e.g. Rev A",
            "All drawings need a revision level."))

    if not any(w in t for w in ["SCALE","1:1","1:2","2:1","1:5","1:10"]):
        f.append(F(nid(),"missing_scale","low",pn,"Title block",
            "No scale","Add e.g. SCALE 1:1",
            "Scale not declared."))

    dims = DIM.findall(text)
    if not dims and len(text.strip()) > 80:
        f.append(F(nid(),"missing_dimensions","high",pn,"Full page",
            "No dimensions found","Verify all dims present",
            "No dimension values found. Drawing may be incomplete."))

    if dims and not TOL.findall(text):
        f.append(F(nid(),"dims_without_tolerances","medium",pn,"Full page",
            f"{len(dims)} dims, no tolerances","Add tolerances",
            "Dimensions found but no tolerances."))

    return f

def dupes(text, nid):
    f = []
    vals = [f"{v}{u}" for v, u in DIM.findall(text)]
    for val, n in Counter(vals).items():
        if n >= 4:
            f.append(F(nid(),"duplicate_dimension","medium",1,"Multiple",
                f"'{val}' x{n}","Verify no conflicts",
                f"'{val}' repeated {n} times."))
    return f

# ── Export ────────────────────────────────────────────────────────────────────
def export(pdf_bytes, approved):
    try:
        import pypdf
        from reportlab.pdfgen import canvas as C
        from reportlab.lib.colors import HexColor
    except ImportError:
        return pdf_bytes

    if not approved:
        return pdf_bytes

    reader  = pypdf.PdfReader(io.BytesIO(pdf_bytes))
    writer  = pypdf.PdfWriter()
    by_page = defaultdict(list)
    for item in approved:
        by_page[int(item.get("page", 1))].append(item)

    COLORS = {"high": "#B71C1C", "medium": "#E65100", "low": "#1565C0"}

    for pn, page in enumerate(reader.pages, 1):
        if pn in by_page:
            try:
                mb = page.mediabox
                pw, ph = float(mb.width), float(mb.height)
                pkt = io.BytesIO()
                c = C.Canvas(pkt, pagesize=(pw, ph))
                c.setFillColor(HexColor("#0D47A1"))
                c.rect(8, ph-24, pw-16, 20, fill=1, stroke=0)
                c.setFillColor(HexColor("#FFFFFF"))
                c.setFont("Helvetica-Bold", 7)
                c.drawString(12, ph-14, f"DRAWING REVIEW - APPROVED CHANGES | Page {pn}")
                y = ph - 34
                for item in by_page[pn]:
                    if y < 50: break
                    col = COLORS.get(item.get("severity", "low"), "#333333")
                    c.setFillColor(HexColor("#FAFAFA"))
                    c.roundRect(8, y-36, pw-16, 38, 3, fill=1, stroke=0)
                    c.setFillColor(HexColor(col))
                    c.rect(8, y-36, 5, 38, fill=1, stroke=0)
                    c.setFillColor(HexColor("#111111"))
                    c.setFont("Helvetica-Bold", 6.5)
                    c.drawString(18, y-4,  f"[{item.get('id','')}] {item.get('type','').replace('_',' ').upper()} ({item.get('severity','').upper()})")
                    c.setFont("Helvetica", 6)
                    c.drawString(18, y-14, f"Was:       {str(item.get('current',''))[:100]}")
                    c.drawString(18, y-23, f"Change to: {str(item.get('suggested',''))[:100]}")
                    c.setFillColor(HexColor("#555555"))
                    c.drawString(18, y-32, f"Reason:    {str(item.get('reason',''))[:110]}")
                    y -= 44
                c.save()
                pkt.seek(0)
                overlay = pypdf.PdfReader(pkt).pages[0]
                page.merge_page(overlay)
            except Exception as e:
                print(f"[server] overlay error page {pn}: {e}")
        writer.add_page(page)

    out = io.BytesIO()
    writer.write(out)
    return out.getvalue()

# ── Run ───────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    socketserver.TCPServer.allow_reuse_address = True
    with socketserver.TCPServer(("", PORT), Handler) as s:
        print(f"\n  Drawing Reviewer  ->  http://localhost:{PORT}")
        print(f"  Serving from: {STATIC_DIR}")
        print(f"  Press Ctrl+C to stop.\n")
        s.serve_forever()
