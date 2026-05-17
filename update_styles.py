import re

with open('web_dashboard/index.html', 'r') as f:
    content = f.read()

# Add Outfit font
content = content.replace('<style>', "<style>\n    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700;800&display=swap');")

# Replace dark theme variables
dark_vars = """    :root,
    html[data-theme="dark"] {
      color-scheme: dark;
      font-family: 'Outfit', Inter, system-ui, sans-serif;
      background: #020205;
      color: #ffffff;
      --bg: #020205;
      --bg-aura-a: rgba(138, 43, 226, 0.25);
      --bg-aura-b: rgba(0, 212, 255, 0.2);
      --grid-line: rgba(255, 255, 255, 0.03);
      --trace-line: rgba(0, 212, 255, 0.5);
      --trace-soft: rgba(255, 255, 255, 0.02);
      --panel: rgba(15, 15, 22, 0.6);
      --panel-strong: rgba(25, 25, 35, 0.8);
      --panel-glass: rgba(10, 10, 15, 0.7);
      --panel-fill: rgba(15, 15, 22, 0.6);
      --panel-head: rgba(25, 25, 35, 0.8);
      --stat-from: rgba(40, 40, 55, 0.4);
      --stat-to: rgba(15, 15, 22, 0.8);
      --line: rgba(255, 255, 255, 0.1);
      --line-soft: rgba(255, 255, 255, 0.05);
      --muted: #a0a0b8;
      --muted-soft: #606078;
      --text: #ffffff;
      --message: #e0e0e0;
      --event: rgba(20, 20, 30, 0.5);
      --event-line: rgba(255, 255, 255, 0.08);
      --empty-bg: rgba(10, 10, 15, 0.5);
      --empty-line: rgba(255, 255, 255, 0.15);
      --button: rgba(255, 255, 255, 0.08);
      --button-hover: rgba(255, 255, 255, 0.15);
      --shadow: rgba(0, 0, 0, 0.6);
      --shadow-soft: rgba(0, 0, 0, 0.4);
      --mark-bg: linear-gradient(135deg, #00d4ff, #8a2be2);
      --control: rgba(255, 255, 255, 0.05);
      --control-hover: rgba(255, 255, 255, 0.1);
      --danger: #ff2a5f;
      --danger-bg: rgba(255, 42, 95, 0.15);
      --danger-soft: rgba(255, 42, 95, 0.08);
      --danger-status: rgba(255, 42, 95, 0.2);
      --warning: #ffb800;
      --warning-bg: rgba(255, 184, 0, 0.15);
      --warning-soft: rgba(255, 184, 0, 0.08);
      --warning-status: rgba(255, 184, 0, 0.2);
      --success: #00ff88;
      --success-bg: rgba(0, 255, 136, 0.15);
      --success-soft: rgba(0, 255, 136, 0.08);
      --success-status: rgba(0, 255, 136, 0.2);
      --info: #00d4ff;
      --info-bg: rgba(0, 212, 255, 0.15);
    }"""
content = re.sub(r':root,\s*html\[data-theme="dark"\]\s*\{[^}]+\}', dark_vars, content, count=1)

# Enhance panels with glassmorphism and blurs
content = content.replace("backdrop-filter: blur(18px);", "backdrop-filter: blur(24px);\n      -webkit-backdrop-filter: blur(24px);")
content = content.replace("box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.04);", "box-shadow: inset 0 1px 0 rgba(255, 255, 255, 0.1), 0 8px 32px rgba(0,0,0,0.5);\n      backdrop-filter: blur(12px);\n      -webkit-backdrop-filter: blur(12px);")

# Update mark (logo) text color to white since background is gradient now
content = content.replace("color: var(--info);\n      font-size: 20px;\n      font-weight: 800;", "color: #fff;\n      font-size: 22px;\n      font-weight: 800;\n      text-shadow: 0 2px 10px rgba(0,0,0,0.3);")

# Update section panels
content = content.replace("background: var(--panel-fill);", "background: var(--panel-fill);\n      backdrop-filter: blur(16px);\n      -webkit-backdrop-filter: blur(16px);\n      border: 1px solid rgba(255,255,255,0.08);")

# Make events pop more
content = content.replace("background: var(--event);", "background: var(--event);\n      backdrop-filter: blur(8px);\n      -webkit-backdrop-filter: blur(8px);")

with open('web_dashboard/index.html', 'w') as f:
    f.write(content)
