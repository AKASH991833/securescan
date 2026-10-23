"""Same-origin crawler for profile 2. Non-destructive: GET only, within the
scope guard and the shared request budget. No form submission, no params."""
from __future__ import annotations
import re
from urllib.parse import urljoin, urlparse, urldefrag

LINK_RE = re.compile(r'(?i)<a\s[^>]*href=["\']([^"\'#]+)')

def crawl(ctx, max_pages: int = 10):
    """Returns list of FetchResult for crawled pages (baseline included)."""
    seen, queue, pages = set(), ["/"], []
    base_host = ctx.guard.base_host
    while queue and len(pages) < max_pages:
        path = queue.pop(0)
        r = ctx.client.get(path)
        if r.error or r.status != 200:
            continue
        pages.append(r)
        seen.add(urldefrag(r.url)[0])
        if "text/html" not in r.headers.get("Content-Type", ""):
            continue
        for href in LINK_RE.findall(r.body):
            nxt = urldefrag(urljoin(r.url, href))[0]
            p = urlparse(nxt)
            if p.scheme not in ("http", "https"):
                continue
            if (p.hostname or "").lower() != base_host:
                continue  # same-origin only; cross-origin links never followed
            if nxt not in seen and nxt not in queue:
                queue.append(nxt)
    return pages
