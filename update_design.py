import re

with open('web_dashboard/index.html', 'r') as f:
    content = f.read()

new_styles = """
    @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@400;500;600;700&display=swap');
    
    :root,
    html[data-theme="dark"] {
      color-scheme: dark;
      font-family: 'Outfit', system-ui, sans-serif;
      background: #111827;
      color: #f9fafb;
      --bg: #111827;
      --panel: #1f2937;
      --panel-strong: #374151;
      --panel-head: #1f2937;
      --stat-from: #1f2937;
      --stat-to: #1f2937;
      --line: #374151;
      --line-soft: #1f2937;
      --muted: #9ca3af;
      --muted-soft: #6b7280;
      --text: #f9fafb;
      --text-inv: #ffffff;
      --message: #e5e7eb;
      --event: #374151;
      --event-line: #4b5563;
      --empty-bg: #1f2937;
      --empty-line: #4b5563;
      --button: #374151;
      --button-hover: #4b5563;
      --shadow: rgba(0, 0, 0, 0.2);
      --shadow-soft: rgba(0, 0, 0, 0.1);
      --control: #374151;
      --control-hover: #4b5563;
      --primary: #15803d;
      --primary-gradient: linear-gradient(135deg, #14532d, #166534);
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #22c55e;
      --info: #3b82f6;
    }

    html[data-theme="light"] {
      color-scheme: light;
      background: #f3f4f6;
      color: #111827;
      --bg: #f3f4f6;
      --panel: #ffffff;
      --panel-strong: #f9fafb;
      --panel-head: #ffffff;
      --stat-from: #ffffff;
      --stat-to: #ffffff;
      --line: #e5e7eb;
      --line-soft: #f3f4f6;
      --muted: #6b7280;
      --muted-soft: #9ca3af;
      --text: #111827;
      --text-inv: #ffffff;
      --message: #374151;
      --event: #ffffff;
      --event-line: #e5e7eb;
      --empty-bg: #f9fafb;
      --empty-line: #d1d5db;
      --button: #f3f4f6;
      --button-hover: #e5e7eb;
      --shadow: rgba(0, 0, 0, 0.05);
      --shadow-soft: rgba(0, 0, 0, 0.02);
      --control: #f3f4f6;
      --control-hover: #e5e7eb;
      --primary: #15803d;
      --primary-gradient: linear-gradient(135deg, #1b5b37, #24824d);
      --danger: #ef4444;
      --warning: #f59e0b;
      --success: #22c55e;
      --info: #3b82f6;
    }

    * { box-sizing: border-box; }

    body {
      margin: 0;
      min-height: 100vh;
      background: var(--bg);
      color: var(--text);
    }

    .shell {
      position: relative;
      z-index: 1;
      width: min(1320px, 100%);
      margin: 0 auto;
      padding: 24px;
    }

    .topbar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 20px;
      padding: 16px 24px;
      border-radius: 100px;
      background: var(--panel);
      box-shadow: 0 4px 12px var(--shadow);
      margin-bottom: 24px;
      border: 1px solid var(--line);
    }

    .brand {
      display: flex;
      align-items: center;
      gap: 12px;
      min-width: 0;
    }

    h1, h2, p { margin: 0; }
    h1 { color: var(--text); font-size: 22px; font-weight: 700; line-height: 1.2; letter-spacing: -0.5px;}
    .subhead { margin-top: 2px; color: var(--muted); font-size: 13px; font-weight: 500;}

    .status {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      padding: 6px 14px;
      border-radius: 999px;
      background: var(--button);
      color: var(--muted);
      font-size: 13px;
      font-weight: 600;
    }
    .status::before {
      width: 8px; height: 8px; border-radius: 50%; content: ""; background: currentColor;
    }
    .status.warn { color: var(--warning); }
    .status.error { color: var(--danger); }
    .status.success { color: var(--success); }

    .header-actions { display: flex; align-items: center; gap: 12px; }

    button {
      cursor: pointer;
      border: 1px solid var(--line);
      border-radius: 100px;
      background: var(--button);
      color: var(--text);
      font: inherit;
    }
    button:hover { background: var(--button-hover); }

    .theme-toggle {
      display: inline-flex; align-items: center; justify-content: center;
      width: 40px; height: 40px; border-radius: 50%; border: 1px solid var(--line); background: var(--panel); color: var(--muted);
    }
    .theme-toggle:hover { background: var(--button-hover); color: var(--text); }
    .theme-icon { width: 20px; height: 20px; display: none; }
    html[data-theme="light"] .theme-icon.sun, html[data-theme="dark"] .theme-icon.moon { display: block; }

    main { display: grid; gap: 24px; }
    
    .stats {
      display: grid;
      grid-template-columns: repeat(4, minmax(0, 1fr));
      gap: 20px;
    }

    .stat {
      padding: 24px;
      border-radius: 20px;
      background: var(--panel);
      box-shadow: 0 4px 12px var(--shadow-soft);
      display: flex;
      flex-direction: column;
      justify-content: space-between;
      min-height: 150px;
      border: 1px solid var(--line);
      transition: transform 0.2s ease, box-shadow 0.2s ease;
    }
    .stat:hover {
      transform: translateY(-2px);
      box-shadow: 0 8px 24px var(--shadow-soft);
    }

    .stat:first-child {
      background: var(--primary-gradient);
      color: var(--text-inv);
      border: none;
    }
    
    .stat:first-child .stat-top, .stat:first-child .hint, .stat:first-child .value {
      color: var(--text-inv);
    }
    
    .stat:first-child .signal {
      background: transparent;
      border-color: rgba(255,255,255,0.4);
      color: var(--text-inv);
    }

    .stat-top {
      display: flex; align-items: center; justify-content: space-between; gap: 10px;
      color: var(--muted); font-size: 15px; font-weight: 600;
    }

    .signal {
      width: 28px; height: 28px; border-radius: 50%; border: 1px solid var(--line);
      display: flex; align-items: center; justify-content: center; font-size: 12px; font-weight: 700;
      color: var(--muted);
    }
    .signal::after { content: "↗"; }

    .value {
      display: block; margin-top: 16px; color: var(--text); font-size: 46px; font-weight: 700; line-height: 1; letter-spacing: -1px;
    }

    .hint { margin-top: 8px; color: var(--muted-soft); font-size: 13px; font-weight: 500;}
    .stat:first-child .hint { opacity: 0.8; }

    .grid {
      display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 24px; align-items: start;
    }

    section {
      min-height: 400px;
      border-radius: 20px;
      background: var(--panel);
      box-shadow: 0 4px 12px var(--shadow-soft);
      border: 1px solid var(--line);
      overflow: hidden;
    }

    .panel-head {
      display: flex; align-items: center; justify-content: space-between; padding: 20px 24px;
      border-bottom: 1px solid var(--line);
      background: var(--panel-head);
    }

    h2 { color: var(--text); font-size: 18px; font-weight: 700; letter-spacing: -0.5px;}

    .count {
      padding: 6px 14px; border-radius: 100px; background: var(--button); border: 1px solid var(--line); color: var(--muted); font-size: 12px; font-weight: 600;
    }

    .events {
      display: grid; gap: 12px; max-height: 500px; padding: 20px 24px; overflow: auto;
    }

    .event {
      padding: 16px; border-radius: 16px; background: var(--panel-strong); border: 1px solid var(--line);
      display: flex; flex-direction: column; gap: 8px;
    }
    
    .meta { display: flex; align-items: center; gap: 10px; color: var(--muted); font-size: 13px; font-weight: 600; }

    .badge {
      padding: 4px 12px; border-radius: 100px; font-size: 11px; text-transform: uppercase; font-weight: 700;
    }
    .badge.denied { background: rgba(239, 68, 68, 0.1); color: var(--danger); border: 1px solid rgba(239,68,68,0.2); }
    .badge.approved { background: rgba(34, 197, 94, 0.1); color: var(--success); border: 1px solid rgba(34,197,94,0.2); }
    .badge.warn { background: rgba(245, 158, 11, 0.1); color: var(--warning); border: 1px solid rgba(245,158,11,0.2); }
    .badge.neutral { background: rgba(59, 130, 246, 0.1); color: var(--info); border: 1px solid rgba(59,130,246,0.2); }

    .message { color: var(--text); font-size: 15px; font-weight: 500; }

    .empty {
      display: grid; place-items: center; min-height: 120px; padding: 24px;
      border: 1px dashed var(--line); border-radius: 16px; color: var(--muted); font-size: 14px; font-weight: 500;
    }

    @media (max-width: 980px) { .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); } .grid { grid-template-columns: 1fr; } }
    @media (max-width: 620px) { .stats { grid-template-columns: 1fr; } .topbar { flex-direction: column; align-items: flex-start; border-radius: 20px;} }
"""

# Replace the style block
content = re.sub(r'<style>.*?</style>', f'<style>\n{new_styles}\n  </style>', content, flags=re.DOTALL)

with open('web_dashboard/index.html', 'w') as f:
    f.write(content)
