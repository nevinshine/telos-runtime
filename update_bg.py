import re

with open('web_dashboard/index.html', 'r') as f:
    content = f.read()

new_body = """    body {
      position: relative;
      margin: 0;
      min-height: 100vh;
      background-color: var(--bg);
      color: var(--text);
    }

    body::before {
      position: absolute;
      content: "";
      inset: 0;
      z-index: 0;
      pointer-events: none;
      background-image: radial-gradient(var(--line) 1px, transparent 1px);
      background-size: 24px 24px;
      mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 80%);
      -webkit-mask-image: linear-gradient(to bottom, rgba(0,0,0,1) 0%, rgba(0,0,0,0) 80%);
    }
    
    body::after {
      position: absolute;
      content: "";
      inset: 0;
      z-index: 0;
      pointer-events: none;
      background: radial-gradient(circle at 15% 50%, rgba(21, 128, 61, 0.08), transparent 40%),
                  radial-gradient(circle at 85% 30%, rgba(59, 130, 246, 0.05), transparent 40%);
    }"""

content = re.sub(r'    body \{\s*margin: 0;\s*min-height: 100vh;\s*background: var\(--bg\);\s*color: var\(--text\);\s*\}', new_body, content)

with open('web_dashboard/index.html', 'w') as f:
    f.write(content)
