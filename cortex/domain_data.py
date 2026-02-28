"""
Telos Domain Intelligence — Seed Database

Curated domain → category → trust mappings for the deterministic
classification engine. This is the "threat intelligence" layer.

Categories:
    docs        — Documentation sites
    code        — Developer tools, repositories
    search      — Search engines
    news        — News outlets
    package     — Package registries
    academic    — Research / academic
    social      — Social media
    filehost    — File hosting / sharing
    exfil       — Known data exfiltration targets
    gaming      — Gaming platforms
    streaming   — Streaming / media
    cloud       — Cloud infrastructure
    mail        — Email providers
    finance     — Financial services
    cdn         — Content delivery networks
    ads         — Advertising / tracking
    vpn_proxy   — VPN / proxy / anonymizer
    paste       — Paste / snippet services (exfil risk)
    unknown     — Uncategorized

Trust levels:
    100  — Core infrastructure (loopback, DNS)
     80  — Highly trusted (major platforms)
     60  — Trusted (well-known services)
     40  — Neutral (known but not inherently safe)
     20  — Suspicious (common abuse vector)
      0  — Blocked (known malicious pattern)
"""

# --- CATEGORY CONSTANTS ---
CAT_DOCS     = "docs"
CAT_CODE     = "code"
CAT_SEARCH   = "search"
CAT_NEWS     = "news"
CAT_PACKAGE  = "package"
CAT_ACADEMIC = "academic"
CAT_SOCIAL   = "social"
CAT_FILEHOST = "filehost"
CAT_EXFIL    = "exfil"
CAT_GAMING   = "gaming"
CAT_STREAM   = "streaming"
CAT_CLOUD    = "cloud"
CAT_MAIL     = "mail"
CAT_FINANCE  = "finance"
CAT_CDN      = "cdn"
CAT_ADS      = "ads"
CAT_VPN      = "vpn_proxy"
CAT_PASTE    = "paste"
CAT_UNKNOWN  = "unknown"

# --- INTENT → ALLOWED CATEGORIES ---
# Maps intent keywords to the set of categories that are
# semantically valid for that intent.
INTENT_CATEGORIES = {
    "documentation": {CAT_DOCS, CAT_CODE, CAT_PACKAGE, CAT_ACADEMIC, CAT_SEARCH},
    "docs":          {CAT_DOCS, CAT_CODE, CAT_PACKAGE, CAT_ACADEMIC, CAT_SEARCH},
    "search":        {CAT_SEARCH, CAT_ACADEMIC, CAT_DOCS, CAT_NEWS},
    "research":      {CAT_ACADEMIC, CAT_SEARCH, CAT_DOCS, CAT_NEWS, CAT_CODE},
    "news":          {CAT_NEWS, CAT_SEARCH},
    "weather":       {CAT_NEWS, CAT_SEARCH, CAT_CLOUD},
    "download":      {CAT_PACKAGE, CAT_CODE, CAT_CDN, CAT_CLOUD},
    "package":       {CAT_PACKAGE, CAT_CODE},
    "install":       {CAT_PACKAGE, CAT_CODE, CAT_CDN},
    "deploy":        {CAT_CLOUD, CAT_CODE, CAT_CDN},
    "email":         {CAT_MAIL},
    "finance":       {CAT_FINANCE},
    "payment":       {CAT_FINANCE},
    "code":          {CAT_CODE, CAT_PACKAGE, CAT_DOCS, CAT_ACADEMIC},
    "programming":   {CAT_CODE, CAT_PACKAGE, CAT_DOCS, CAT_ACADEMIC, CAT_SEARCH},
    "python":        {CAT_DOCS, CAT_CODE, CAT_PACKAGE, CAT_ACADEMIC, CAT_SEARCH},
    "machine learning": {CAT_ACADEMIC, CAT_CODE, CAT_SEARCH, CAT_DOCS},
    "ai":            {CAT_ACADEMIC, CAT_CODE, CAT_SEARCH, CAT_DOCS},
    "server":        {CAT_CLOUD, CAT_CODE, CAT_CDN},
    "monitor":       {CAT_CLOUD, CAT_CODE},
    "database":      {CAT_CLOUD, CAT_CODE, CAT_DOCS},
}

# --- DOMAIN SEED DATA ---
# (domain, category, trust_level)
SEED_DOMAINS = [
    # === Documentation ===
    ("docs.python.org",       CAT_DOCS,     80),
    ("docs.rs",               CAT_DOCS,     80),
    ("devdocs.io",            CAT_DOCS,     70),
    ("developer.mozilla.org", CAT_DOCS,     80),
    ("learn.microsoft.com",   CAT_DOCS,     80),
    ("docs.oracle.com",       CAT_DOCS,     70),
    ("golang.org",            CAT_DOCS,     80),
    ("rustup.rs",             CAT_DOCS,     75),
    ("man7.org",              CAT_DOCS,     70),
    ("cppreference.com",      CAT_DOCS,     75),
    ("ruby-doc.org",          CAT_DOCS,     70),
    ("php.net",               CAT_DOCS,     70),
    ("kotlinlang.org",        CAT_DOCS,     70),
    ("swift.org",             CAT_DOCS,     70),
    ("reactjs.org",           CAT_DOCS,     70),
    ("vuejs.org",             CAT_DOCS,     70),
    ("angular.io",            CAT_DOCS,     70),
    ("nextjs.org",            CAT_DOCS,     70),
    ("docs.docker.com",       CAT_DOCS,     75),
    ("kubernetes.io",         CAT_DOCS,     75),

    # === Code / Developer Tools ===
    ("github.com",            CAT_CODE,     80),
    ("gitlab.com",            CAT_CODE,     75),
    ("bitbucket.org",         CAT_CODE,     70),
    ("stackoverflow.com",     CAT_CODE,     80),
    ("codeberg.org",          CAT_CODE,     65),
    ("sourcehut.org",         CAT_CODE,     60),
    ("raw.githubusercontent.com", CAT_CODE, 75),
    ("gist.github.com",      CAT_CODE,     75),
    ("hub.docker.com",        CAT_CODE,     70),
    ("registry.npmjs.org",    CAT_CODE,     75),

    # === Search Engines ===
    ("google.com",            CAT_SEARCH,   80),
    ("www.google.com",        CAT_SEARCH,   80),
    ("bing.com",              CAT_SEARCH,   75),
    ("duckduckgo.com",        CAT_SEARCH,   80),
    ("search.brave.com",      CAT_SEARCH,   70),
    ("startpage.com",         CAT_SEARCH,   65),
    ("yandex.com",            CAT_SEARCH,   50),
    ("baidu.com",             CAT_SEARCH,   40),

    # === News ===
    ("reuters.com",           CAT_NEWS,     80),
    ("bbc.com",               CAT_NEWS,     80),
    ("cnn.com",               CAT_NEWS,     75),
    ("nytimes.com",           CAT_NEWS,     75),
    ("theguardian.com",       CAT_NEWS,     75),
    ("apnews.com",            CAT_NEWS,     80),
    ("npr.org",               CAT_NEWS,     75),
    ("aljazeera.com",         CAT_NEWS,     65),
    ("washingtonpost.com",    CAT_NEWS,     70),
    ("arstechnica.com",       CAT_NEWS,     70),
    ("techcrunch.com",        CAT_NEWS,     65),
    ("wired.com",             CAT_NEWS,     70),
    ("theverge.com",          CAT_NEWS,     65),
    ("hackernews.com",        CAT_NEWS,     65),

    # === Package Registries ===
    ("pypi.org",              CAT_PACKAGE,  80),
    ("npmjs.com",             CAT_PACKAGE,  80),
    ("crates.io",             CAT_PACKAGE,  80),
    ("rubygems.org",          CAT_PACKAGE,  75),
    ("packagist.org",         CAT_PACKAGE,  70),
    ("pkg.go.dev",            CAT_PACKAGE,  80),
    ("nuget.org",             CAT_PACKAGE,  70),
    ("hex.pm",                CAT_PACKAGE,  65),
    ("mvnrepository.com",     CAT_PACKAGE,  70),
    ("anaconda.org",          CAT_PACKAGE,  70),

    # === Academic / Research ===
    ("arxiv.org",             CAT_ACADEMIC, 80),
    ("scholar.google.com",    CAT_ACADEMIC, 80),
    ("wikipedia.org",         CAT_ACADEMIC, 80),
    ("en.wikipedia.org",      CAT_ACADEMIC, 80),
    ("semanticscholar.org",   CAT_ACADEMIC, 75),
    ("researchgate.net",      CAT_ACADEMIC, 65),
    ("ieee.org",              CAT_ACADEMIC, 75),
    ("acm.org",               CAT_ACADEMIC, 75),
    ("sciencedirect.com",     CAT_ACADEMIC, 70),
    ("pubmed.ncbi.nlm.nih.gov", CAT_ACADEMIC, 75),
    ("nature.com",            CAT_ACADEMIC, 75),
    ("science.org",           CAT_ACADEMIC, 75),

    # === Social Media ===
    ("facebook.com",          CAT_SOCIAL,   40),
    ("instagram.com",         CAT_SOCIAL,   40),
    ("twitter.com",           CAT_SOCIAL,   40),
    ("x.com",                 CAT_SOCIAL,   40),
    ("tiktok.com",            CAT_SOCIAL,   30),
    ("reddit.com",            CAT_SOCIAL,   50),
    ("linkedin.com",          CAT_SOCIAL,   50),
    ("pinterest.com",         CAT_SOCIAL,   35),
    ("snapchat.com",          CAT_SOCIAL,   30),
    ("threads.net",           CAT_SOCIAL,   35),
    ("mastodon.social",       CAT_SOCIAL,   40),
    ("tumblr.com",            CAT_SOCIAL,   35),

    # === File Hosting / Sharing ===
    ("dropbox.com",           CAT_FILEHOST, 40),
    ("drive.google.com",      CAT_FILEHOST, 50),
    ("onedrive.live.com",     CAT_FILEHOST, 45),
    ("mega.nz",               CAT_FILEHOST, 20),
    ("mediafire.com",         CAT_FILEHOST, 20),
    ("wetransfer.com",        CAT_FILEHOST, 35),
    ("box.com",               CAT_FILEHOST, 45),
    ("sendspace.com",         CAT_FILEHOST, 15),
    ("rapidshare.com",        CAT_FILEHOST, 10),
    ("anonfiles.com",         CAT_FILEHOST, 5),
    ("gofile.io",             CAT_FILEHOST, 10),
    ("file.io",               CAT_FILEHOST, 10),
    ("transfer.sh",           CAT_FILEHOST, 15),

    # === Known Exfiltration / Abuse Vectors ===
    ("pastebin.com",          CAT_PASTE,    20),
    ("hastebin.com",          CAT_PASTE,    15),
    ("ghostbin.com",          CAT_PASTE,    10),
    ("paste.ee",              CAT_PASTE,    10),
    ("dpaste.org",            CAT_PASTE,    15),
    ("justpaste.it",          CAT_PASTE,    10),
    ("rentry.co",             CAT_PASTE,    15),
    ("privatebin.net",        CAT_PASTE,    10),
    ("webhook.site",          CAT_EXFIL,    5),
    ("requestbin.com",        CAT_EXFIL,    5),
    ("pipedream.com",         CAT_EXFIL,    10),
    ("hookbin.com",           CAT_EXFIL,    5),
    ("ngrok.io",              CAT_EXFIL,    15),
    ("serveo.net",            CAT_EXFIL,    10),
    ("localhost.run",         CAT_EXFIL,    10),
    ("burpcollaborator.net",  CAT_EXFIL,    5),

    # === Cloud Infrastructure ===
    ("aws.amazon.com",        CAT_CLOUD,    75),
    ("cloud.google.com",      CAT_CLOUD,    75),
    ("azure.microsoft.com",   CAT_CLOUD,    75),
    ("digitalocean.com",      CAT_CLOUD,    65),
    ("heroku.com",            CAT_CLOUD,    60),
    ("vercel.com",            CAT_CLOUD,    65),
    ("netlify.com",           CAT_CLOUD,    65),
    ("render.com",            CAT_CLOUD,    60),
    ("fly.io",                CAT_CLOUD,    60),
    ("railway.app",           CAT_CLOUD,    55),

    # === Mail ===
    ("gmail.com",             CAT_MAIL,     70),
    ("outlook.com",           CAT_MAIL,     70),
    ("protonmail.com",        CAT_MAIL,     65),
    ("mail.google.com",       CAT_MAIL,     70),
    ("yahoo.com",             CAT_MAIL,     50),

    # === CDN ===
    ("cdn.jsdelivr.net",      CAT_CDN,      75),
    ("cdnjs.cloudflare.com",  CAT_CDN,      75),
    ("unpkg.com",             CAT_CDN,      70),
    ("fastly.net",            CAT_CDN,      70),
    ("cloudflare.com",        CAT_CDN,      75),
    ("akamai.com",            CAT_CDN,      70),

    # === Gaming ===
    ("store.steampowered.com", CAT_GAMING,  50),
    ("epicgames.com",         CAT_GAMING,   50),
    ("roblox.com",            CAT_GAMING,   40),
    ("twitch.tv",             CAT_GAMING,   45),
    ("discord.com",           CAT_GAMING,   45),
    ("discord.gg",            CAT_GAMING,   40),

    # === Streaming / Media ===
    ("youtube.com",           CAT_STREAM,   60),
    ("netflix.com",           CAT_STREAM,   55),
    ("spotify.com",           CAT_STREAM,   55),
    ("soundcloud.com",        CAT_STREAM,   45),

    # === Image / Media Hosting ===
    ("imgur.com",             CAT_SOCIAL,   35),
    ("flickr.com",            CAT_SOCIAL,   40),
    ("giphy.com",             CAT_SOCIAL,   30),
    ("imgbb.com",             CAT_FILEHOST, 20),
    ("postimg.cc",            CAT_FILEHOST, 15),
    ("ibb.co",                CAT_FILEHOST, 15),
    ("prnt.sc",               CAT_FILEHOST, 20),

    # === VPN / Proxy / Anonymizers ===
    ("nordvpn.com",           CAT_VPN,      30),
    ("expressvpn.com",        CAT_VPN,      30),
    ("torproject.org",        CAT_VPN,      20),
    ("hide.me",               CAT_VPN,      20),
    ("proxysite.com",         CAT_VPN,      10),

    # === Advertising / Tracking ===
    ("doubleclick.net",       CAT_ADS,      20),
    ("googlesyndication.com", CAT_ADS,      25),
    ("googleadservices.com",  CAT_ADS,      25),
    ("facebook.net",          CAT_ADS,      25),
    ("analytics.google.com",  CAT_ADS,      30),

    # === Finance ===
    ("stripe.com",            CAT_FINANCE,  75),
    ("paypal.com",            CAT_FINANCE,  70),
    ("wise.com",              CAT_FINANCE,  60),
    ("revolut.com",           CAT_FINANCE,  55),

    # === Security / CVE ===
    ("cve.mitre.org",         CAT_DOCS,     80),
    ("nvd.nist.gov",          CAT_DOCS,     80),
    ("exploit-db.com",        CAT_DOCS,     60),
    ("virustotal.com",        CAT_DOCS,     65),

    # === Weather ===
    ("weather.gov",           CAT_NEWS,     80),
    ("weather.com",           CAT_NEWS,     70),
    ("wttr.in",               CAT_NEWS,     60),
]

# --- HIGH-VALUE WATCHLIST ---
# Domains to check for typosquat similarity.
# Only the most commonly targeted domains.
WATCHLIST = [
    "google.com",
    "github.com",
    "python.org",
    "docs.python.org",
    "pypi.org",
    "npmjs.com",
    "stackoverflow.com",
    "wikipedia.org",
    "amazon.com",
    "microsoft.com",
    "apple.com",
    "paypal.com",
    "stripe.com",
    "gmail.com",
    "outlook.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "arxiv.org",
    "youtube.com",
    "cloudflare.com",
    "aws.amazon.com",
    "azure.microsoft.com",
    "docs.docker.com",
    "kubernetes.io",
    "crates.io",
    "rubygems.org",
    "bbc.com",
    "reuters.com",
    "nytimes.com",
]

# --- HOMOGLYPH MAP ---
# Characters commonly substituted in typosquat attacks.
HOMOGLYPHS = {
    '0': 'o',
    '1': 'l',
    'I': 'l',
    '|': 'l',
    '!': 'l',
    'rn': 'm',
    'vv': 'w',
}
