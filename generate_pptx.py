"""
Generate a professional 5-slide PowerPoint presentation (.pptx)
for the API Authorization Security Testing Framework.
"""

from pptx import Presentation
from pptx.util import Inches, Pt
from pptx.dml.color import RGBColor
from pptx.enum.text import PP_ALIGN
from pptx.enum.shapes import MSO_SHAPE
from pathlib import Path

prs = Presentation()
prs.slide_width = Inches(13.333)
prs.slide_height = Inches(7.5)

# Color Palette (Dark Cybersecurity Theme)
BG_COLOR = RGBColor(13, 17, 23)        # #0d1117
SURFACE_COLOR = RGBColor(22, 27, 34)   # #161b22
ACCENT_BLUE = RGBColor(88, 166, 255)   # #58a6ff
TEXT_WHITE = RGBColor(240, 246, 252)   # #f0f6fc
TEXT_MUTED = RGBColor(139, 148, 158)   # #8b949e
VULN_RED = RGBColor(229, 62, 62)       # #e53e3e
SAFE_GREEN = RGBColor(56, 161, 105)    # #38a169

def set_slide_background(slide):
    background = slide.background
    fill = background.fill
    fill.solid()
    fill.fore_color.rgb = BG_COLOR

def add_header(slide, title_text, category_text="WEB & API SECURITY R&D"):
    # Category tag
    cat_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.5), Inches(11.7), Inches(0.4))
    tf_cat = cat_box.text_frame
    tf_cat.word_wrap = True
    p_cat = tf_cat.paragraphs[0]
    p_cat.text = category_text.upper()
    p_cat.font.size = Pt(11)
    p_cat.font.bold = True
    p_cat.font.color.rgb = ACCENT_BLUE

    # Title
    t_box = slide.shapes.add_textbox(Inches(0.8), Inches(0.85), Inches(11.7), Inches(0.8))
    tf_t = t_box.text_frame
    tf_t.word_wrap = True
    p_t = tf_t.paragraphs[0]
    p_t.text = title_text
    p_t.font.size = Pt(26)
    p_t.font.bold = True
    p_t.font.color.rgb = TEXT_WHITE

# -------------------------------------------------------------
# SLIDE 1: Title & Executive Summary
# -------------------------------------------------------------
slide1 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_background(slide1)

# Title container
tbox = slide1.shapes.add_textbox(Inches(1.0), Inches(1.8), Inches(11.3), Inches(2.2))
tf = tbox.text_frame
tf.word_wrap = True

p0 = tf.paragraphs[0]
p0.text = "🔒 Automated API Authorization Security Testing Framework"
p0.font.size = Pt(32)
p0.font.bold = True
p0.font.color.rgb = ACCENT_BLUE

p1 = tf.add_paragraph()
p1.text = "Evidence-Based Detection of BOLA & BFLA Vulnerabilities in REST Services"
p1.font.size = Pt(20)
p1.font.color.rgb = TEXT_WHITE
p1.space_before = Pt(10)

p2 = tf.add_paragraph()
p2.text = "CyberFox Society Cybersecurity R&D Internship | October 2026 | Version 2.0.0"
p2.font.size = Pt(14)
p2.font.color.rgb = TEXT_MUTED
p2.space_before = Pt(15)

# 3 Highlights Cards
cards = [
    ("OWASP API Security Alignment", "Directly targets API1:2023 (BOLA) and API5:2023 (BFLA), the two most critical API security vulnerabilities."),
    ("Comparative Testing Engine", "Multi-identity analysis compares authorized owner/admin requests against unprivileged actors in real time."),
    ("Production Verification", "136 automated tests, pre-flight health checks, dark-theme web dashboard, and zero false-clean reports.")
]

for idx, (title, desc) in enumerate(cards):
    left = Inches(1.0 + idx * 3.9)
    card_shape = slide1.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(4.5), Inches(3.6), Inches(2.2))
    card_shape.fill.solid()
    card_shape.fill.fore_color.rgb = SURFACE_COLOR
    card_shape.line.color.rgb = ACCENT_BLUE

    ctf = card_shape.text_frame
    ctf.word_wrap = True
    cp0 = ctf.paragraphs[0]
    cp0.text = title
    cp0.font.size = Pt(15)
    cp0.font.bold = True
    cp0.font.color.rgb = ACCENT_BLUE

    cp1 = ctf.add_paragraph()
    cp1.text = desc
    cp1.font.size = Pt(12)
    cp1.font.color.rgb = TEXT_WHITE
    cp1.space_before = Pt(8)

# -------------------------------------------------------------
# SLIDE 2: The Problem: BOLA & BFLA in Modern APIs
# -------------------------------------------------------------
slide2 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_background(slide2)
add_header(slide2, "The Problem: Authorization Vulnerabilities in Modern APIs")

# Left Box: BOLA
b_left = slide2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(2.0), Inches(5.4), Inches(4.8))
b_left.fill.solid()
b_left.fill.fore_color.rgb = SURFACE_COLOR
b_left.line.color.rgb = VULN_RED

tf_l = b_left.text_frame
tf_l.word_wrap = True
lp0 = tf_l.paragraphs[0]
lp0.text = "🚨 BOLA — Broken Object Level Authorization"
lp0.font.size = Pt(18)
lp0.font.bold = True
lp0.font.color.rgb = VULN_RED

items_bola = [
    "OWASP API1:2023: Most common API vulnerability worldwide.",
    "Mechanics: Attacker substitutes object keys (e.g. /api/documents/101 -> 102).",
    "Root Cause: Server validates the user's token but fails to verify that the caller owns the specific object requested.",
    "Business Impact: Data exfiltration, massive privacy breaches, tenant leaks.",
    "Detection Challenge: Returns valid HTTP 200 with standard payload; blind fuzzers cannot recognize unauthorized access."
]
for item in items_bola:
    p = tf_l.add_paragraph()
    p.text = f"• {item}"
    p.font.size = Pt(12)
    p.font.color.rgb = TEXT_WHITE
    p.space_before = Pt(8)

# Right Box: BFLA
b_right = slide2.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.8))
b_right.fill.solid()
b_right.fill.fore_color.rgb = SURFACE_COLOR
b_right.line.color.rgb = VULN_RED

tf_r = b_right.text_frame
tf_r.word_wrap = True
rp0 = tf_r.paragraphs[0]
rp0.text = "🚨 BFLA — Broken Function Level Authorization"
rp0.font.size = Pt(18)
rp0.font.bold = True
rp0.font.color.rgb = VULN_RED

items_bfla = [
    "OWASP API5:2023: Function-level privilege escalation.",
    "Mechanics: Standard user calls administrative/privileged routes directly (e.g. /api/admin).",
    "Root Cause: Enforcing roles in UI by hiding buttons, while omitting server-side controller permission checks.",
    "Business Impact: Complete administrative takeover, configuration corruption.",
    "Detection Challenge: Requires dual-role state comparison between authenticated administrative and standard user personas."
]
for item in items_bfla:
    p = tf_r.add_paragraph()
    p.text = f"• {item}"
    p.font.size = Pt(12)
    p.font.color.rgb = TEXT_WHITE
    p.space_before = Pt(8)

# -------------------------------------------------------------
# SLIDE 3: Architecture & Security Controls
# -------------------------------------------------------------
slide3 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_background(slide3)
add_header(slide3, "System Architecture & Defensive Engineering")

arch_cards = [
    ("Local Test Lab Fixtures", "app/api.py (Port 5000)", [
        "127.0.0.1 bound only — strictly no public exposure.",
        "Contains vulnerable routes (/api/documents/<id>, /api/admin).",
        "Includes hardened secure routes (/api/documents/secure/<id>, /api/admin/secure) for false-positive validation.",
        "Synthetic identity matrix (alice, bob, carol, admin)."
    ]),
    ("Config-Driven Scanner", "app/scanner.py & config.py", [
        "Strict hostname allowlist (rejects external domains).",
        "URL scheme validation (http/https only).",
        "Configurable per-request timeouts and bounded retries.",
        "Dry-Run mode inspects execution plans with zero network traffic."
    ]),
    ("Defensive Reporting & Health", "app/report_generator.py", [
        "Pre-flight health check halts scans if target API is offline.",
        "Eliminates false-clean scans (connection-refused is marked FAILED).",
        "Automatic PII & credential scrubbing (tokens, passwords redacted).",
        "Atomic JSON & HTML exports with timestamped audit logging."
    ])
]

for idx, (title, sub, bullets) in enumerate(arch_cards):
    left = Inches(1.0 + idx * 3.9)
    shape = slide3.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, left, Inches(2.0), Inches(3.6), Inches(4.8))
    shape.fill.solid()
    shape.fill.fore_color.rgb = SURFACE_COLOR
    shape.line.color.rgb = ACCENT_BLUE

    tf = shape.text_frame
    tf.word_wrap = True
    p_t = tf.paragraphs[0]
    p_t.text = title
    p_t.font.size = Pt(16)
    p_t.font.bold = True
    p_t.font.color.rgb = ACCENT_BLUE

    p_s = tf.add_paragraph()
    p_s.text = sub
    p_s.font.size = Pt(11)
    p_s.font.color.rgb = TEXT_MUTED
    p_s.space_before = Pt(4)

    for b in bullets:
        p = tf.add_paragraph()
        p.text = f"• {b}"
        p.font.size = Pt(11)
        p.font.color.rgb = TEXT_WHITE
        p.space_before = Pt(8)

# -------------------------------------------------------------
# SLIDE 4: Testing & Empirical Validation
# -------------------------------------------------------------
slide4 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_background(slide4)
add_header(slide4, "Testing, Verification & Empirical Scan Results")

# Left: Test Metrics
left_box = slide4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(2.0), Inches(5.4), Inches(4.8))
left_box.fill.solid()
left_box.fill.fore_color.rgb = SURFACE_COLOR
left_box.line.color.rgb = SAFE_GREEN

tf_lm = left_box.text_frame
tf_lm.word_wrap = True
lmp0 = tf_lm.paragraphs[0]
lmp0.text = "🧪 Comprehensive QA Pipeline (Pytest)"
lmp0.font.size = Pt(18)
lmp0.font.bold = True
lmp0.font.color.rgb = SAFE_GREEN

qa_points = [
    "136 Automated Tests passing with 100% success rate.",
    "Scanner Unit Tests: Network failures, timeouts, secret redaction, dry runs.",
    "BOLA Unit Tests: Cross-tenant 200 checks, 403 enforcement, missing IDs.",
    "BFLA Unit Tests: Privilege escalations, role matrices, server error handling.",
    "Integration Tests: Live multi-process scans with background API servers.",
    "Route Tests: Dashboard REST endpoints & directory traversal guard testing."
]
for q in qa_points:
    p = tf_lm.add_paragraph()
    p.text = f"✔ {q}"
    p.font.size = Pt(12)
    p.font.color.rgb = TEXT_WHITE
    p.space_before = Pt(8)

# Right: Live Scan Results
right_box = slide4.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.8))
right_box.fill.solid()
right_box.fill.fore_color.rgb = SURFACE_COLOR
right_box.line.color.rgb = ACCENT_BLUE

tf_rm = right_box.text_frame
tf_rm.word_wrap = True
rmp0 = tf_rm.paragraphs[0]
rmp0.text = "📊 Live Local Lab Scan Results (13 Tests)"
rmp0.font.size = Pt(18)
rmp0.font.bold = True
rmp0.font.color.rgb = ACCENT_BLUE

scan_points = [
    "5 Potential Vulnerabilities Detected (High Confidence):",
    "  - BOLA on Document 101 (Bob accessed Alice's document)",
    "  - BOLA on Document 102 (Alice accessed Bob's document)",
    "  - BFLA on /api/admin (Bob, Alice, Carol accessed admin function)",
    "4 Verified Clean Controls (HTTP 403 Forbidden):",
    "  - BOLA on secure Document 101 & 102 properly blocked",
    "  - BFLA on secure /api/admin properly enforced",
    "0 Errors & 0 False Negatives on Live Targets."
]
for s in scan_points:
    p = tf_rm.add_paragraph()
    p.text = s
    p.font.size = Pt(11)
    p.font.color.rgb = TEXT_WHITE
    p.space_before = Pt(6)

# -------------------------------------------------------------
# SLIDE 5: Strategic Remediation & Future Roadmap
# -------------------------------------------------------------
slide5 = prs.slides.add_slide(prs.slide_layouts[6])
set_slide_background(slide5)
add_header(slide5, "Developer Remediation & Future Enhancements")

# Remediation Box
box_rem = slide5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(1.0), Inches(2.0), Inches(5.4), Inches(4.8))
box_rem.fill.solid()
box_rem.fill.fore_color.rgb = SURFACE_COLOR
box_rem.line.color.rgb = ACCENT_BLUE

tf_rem = box_rem.text_frame
tf_rem.word_wrap = True
rp0 = tf_rem.paragraphs[0]
rp0.text = "🛡️ Production Remediation Guidelines"
rp0.font.size = Pt(18)
rp0.font.bold = True
rp0.font.color.rgb = ACCENT_BLUE

rems = [
    "Object Ownership Enforcement:",
    "  Validate ownership on every DB query using authenticated session IDs:",
    "  `if doc.owner_id != session.user_id: abort(403)`",
    "Server-Side Role Decorators:",
    "  Enforce declarative decorators at the controller boundary:",
    "  `@require_role('admin') def admin_view(): ...`",
    "Standardized Error Semantics:",
    "  Return explicit HTTP 403 Forbidden rather than leaking stack traces.",
    "Continuous Authorization Testing:",
    "  Embed multi-tenant authorization scans in pre-deployment CI/CD."
]
for r in rems:
    p = tf_rem.add_paragraph()
    p.text = r
    p.font.size = Pt(11)
    p.font.color.rgb = TEXT_WHITE
    p.space_before = Pt(6)

# Roadmap Box
box_road = slide5.shapes.add_shape(MSO_SHAPE.ROUNDED_RECTANGLE, Inches(6.9), Inches(2.0), Inches(5.4), Inches(4.8))
box_road.fill.solid()
box_road.fill.fore_color.rgb = SURFACE_COLOR
box_road.line.color.rgb = ACCENT_BLUE

tf_road = box_road.text_frame
tf_road.word_wrap = True
rdp0 = tf_road.paragraphs[0]
rdp0.text = "🚀 Future Roadmap (v3.0)"
rdp0.font.size = Pt(18)
rdp0.font.bold = True
rdp0.font.color.rgb = ACCENT_BLUE

roadmap = [
    "OpenAPI / Swagger Ingestion:",
    "  Auto-parse OpenAPI specifications with interactive endpoint selection.",
    "OAuth2 & JWT Token Lifecycle:",
    "  Automate token acquisition, rotation, and custom claim injection.",
    "CI/CD Integration:",
    "  GitHub Actions and GitLab CI runners for automated regression gating.",
    "CVSS 3.1 Scoring Engine:",
    "  Calculate deterministic vulnerability metrics for compliance reporting.",
    "Concurrent Scanning Engine:",
    "  Asynchronous worker queues for large enterprise microservice fleets."
]
for rd in roadmap:
    p = tf_road.add_paragraph()
    p.text = f"• {rd}"
    p.font.size = Pt(11)
    p.font.color.rgb = TEXT_WHITE
    p.space_before = Pt(8)

# Output path
output_path = Path("docs") / "presentation.pptx"
prs.save(str(output_path))
print(f"PowerPoint presentation generated at: {output_path.resolve()}")
