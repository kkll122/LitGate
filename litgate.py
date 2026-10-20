# -*- coding: utf-8 -*-
"""
LitGate —— 文献查询与转发网关（最小安装版）

用法:
    pip install -r requirements.txt
    python litgate.py                 # 默认 127.0.0.1:8791
    python litgate.py --host 0.0.0.0 --port 9000   # 对外开放（注意风险）
    python litgate.py --db /path/litgate.db

安全设计:
    - 密码仅在首次设置时创建, 以 PBKDF2-HMAC-SHA256(240k 迭代)+随机盐 哈希存储。
      没有任何恢复机制: 忘记密码 = 删除 litgate.db 后重新初始化（所有 key 一并失效）。
    - 客户端 API key 只存哈希, 创建时明文仅显示一次。
    - 总闸(断电开关)状态持久化; 断电时 /v1/* 一律 503。
    - 转发 API 按 key 做滑动窗口限频（次数/时间窗）。
    - 会话令牌仅在内存中, 重启即失效（需重新登录）。
"""
import argparse
import asyncio
import hashlib
import webbrowser
import hmac
import ipaddress
import json
import re
import secrets
import socket
import sqlite3
import threading
import time
import xml.etree.ElementTree as ET
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import httpx
import uvicorn
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse
from search_core import (SOURCE_INFO, VERIFIED_ON, SECRET_FIELDS, public_config,
                         update_config, options, combine)

# ----------------------------------------------------------------------------
# 常量 / 全局
# ----------------------------------------------------------------------------
DB_PATH = str(Path(__file__).with_name("litgate.db"))
SESSION_TTL = 12 * 3600          # 会话 12 小时
PBKDF2_ITERS = 240_000
LOGIN_FAIL_LIMIT = 10            # 连续失败 10 次
LOGIN_LOCK_SECONDS = 300         # 锁 5 分钟
S2_MIN_INTERVAL = 1.1            # 申请初始 key 同样通常为1req/s，不因有key取消节流

DB_LOCK = threading.Lock()
SESSIONS: dict = {}              # token -> expiry
LOGIN_FAILS = {"n": 0, "until": 0}
RATE_BUCKETS: dict = {}          # key_id -> deque[timestamps]
S2_LOCK = asyncio.Lock()
S2_LAST = {"t": 0.0}
ARXIV_LOCK = asyncio.Lock()      # arXiv 官方要求约 3 秒间隔；406 是其限流信号
ARXIV_LAST = {"t": 0.0}

app = FastAPI(title="LitGate", docs_url=None, redoc_url=None, openapi_url=None)
HTTP = httpx.AsyncClient(timeout=25.0, follow_redirects=False,
                          headers={"User-Agent": "LitGate/2.0 (personal gateway)"})

# ----------------------------------------------------------------------------
# 韧性取数层：429/406/503 自动退避重试；错误仅返回状态码和处置建议
# ----------------------------------------------------------------------------
UPSTREAM_HINTS = [
    ("api.openalex.org",
     "OpenAlex：在官方 Settings → API 查看密钥、额度和轮换状态；申请入口见端点配置"),
    ("semanticscholar.org",
     "Semantic Scholar 建议：无 key 共享池限流严重，semanticscholar.org/product/api 可免费申请 key"),
    ("api.crossref.org",
     "Crossref 建议：在端点「配置」里填 mailto 邮箱进入 polite 池，限流更宽松"),
    ("api.elsevier.com",
     "Scopus 建议：检查 api_key；通常需机构网络 / VPN 环境"),
    ("export.arxiv.org",
     "arXiv 建议：官方要求请求间隔约 3 秒；若持续 406，通常是该 IP 进入临时惩罚期，几分钟后自动恢复"),
    ("dblp.org",
     "DBLP 建议：稍后重试或更换网络环境"),
]

def _snippet(t, n=140):
    return " ".join((t or "").split())[:n]

def _hint_for(url):
    for host, h in UPSTREAM_HINTS:
        if host in url:
            return h
    return ""

class UpstreamError(Exception):
    """上游错误：状态码和公共建议，不转发上游正文或凭据。"""

async def upstream_get(url, params=None, headers=None, *, label="上游", retries=2,
                       backoff=(1.5, 6.0)):
    r = None
    for attempt in range(retries + 1):
        try:
            r = await HTTP.get(url, params=params, headers=headers)
        except httpx.HTTPError as ex:
            raise UpstreamError(
                f"{label} 网络错误：{type(ex).__name__}（检查本机网络 / 代理）")
        if r.status_code == 200:
            return r
        raw = r.text or ""
        # OpenAlex 当日额度耗尽：重试无意义，快速失败并给出重置时间
        if r.status_code == 429 and ("Insufficient budget" in raw or "$0 remaining" in raw):
            raise UpstreamError(
                f"{label} 限流（429）：当日额度已耗尽。{_hint_for(url)}")
        if r.status_code in (429, 406, 503) and attempt < retries:
            wait = backoff[1]
            try:
                wait = float(r.headers.get("Retry-After") or backoff[1])
            except (TypeError, ValueError):
                pass
            await asyncio.sleep(min(max(wait, backoff[0]), backoff[1]))
            continue
        break
    sc = r.status_code
    head = (f"{label} 限流（429，已自动重试 {retries} 次仍被拒）" if sc == 429
            else f"{label} 返回 HTTP {sc}")
    raise UpstreamError(f"{head}。{_hint_for(url)}")


# ----------------------------------------------------------------------------
# 存储
# ----------------------------------------------------------------------------
class ClosingConnection(sqlite3.Connection):
    def __exit__(self, *args):
        try:
            return super().__exit__(*args)
        finally:
            self.close()

def db() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False, factory=ClosingConnection)
    conn.row_factory = sqlite3.Row
    return conn

def init_db() -> None:
    with DB_LOCK, db() as conn:
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS config(key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS endpoints(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            adapter TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            config TEXT NOT NULL DEFAULT '{}',
            note TEXT DEFAULT ''
        );
        CREATE TABLE IF NOT EXISTS apikeys(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            prefix TEXT NOT NULL,
            key_hash TEXT NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            rate_limit INTEGER NOT NULL DEFAULT 30,
            window_seconds INTEGER NOT NULL DEFAULT 60,
            allowed TEXT NOT NULL DEFAULT '["*"]',
            created TEXT NOT NULL,
            last_used TEXT DEFAULT ''
        );
        """)
        if not conn.execute("SELECT 1 FROM endpoints LIMIT 1").fetchone():
            seeds = [
                ("Crossref",      "crossref", 1, "{}", "无需密钥；可在配置中加 mailto 进入 polite 池"),
                ("OpenAlex",      "openalex", 1, "{}", "可选api_key；额度与使用情况到官方账户页查询"),
                ("Semantic Scholar", "semanticscholar", 1, "{}", "可选api_key；初始密钥额度以官方批准信息为准"),
                ("arXiv",         "arxiv",    1, "{}", "无需密钥"),
                ("DBLP",          "dblp",     1, "{}", "无需密钥，计算机科学书目"),
                ("Scopus",        "scopus",   0, "{}", "需在配置中填 dev.elsevier.com 的 API key"),
            ]
            conn.executemany(
                "INSERT INTO endpoints(name,adapter,enabled,config,note) VALUES(?,?,?,?,?)", seeds)
        if conn.execute("SELECT value FROM config WHERE key='powered'").fetchone() is None:
            conn.execute("INSERT INTO config(key,value) VALUES('powered','1')")

def cfg_get(key: str, default=None):
    with DB_LOCK, db() as conn:
        row = conn.execute("SELECT value FROM config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def cfg_set(key: str, value: str) -> None:
    with DB_LOCK, db() as conn:
        conn.execute("INSERT INTO config(key,value) VALUES(?,?) "
                     "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, value))

def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

# ----------------------------------------------------------------------------
# 密码 / 会话
# ----------------------------------------------------------------------------
def hash_password(password: str, salt: bytes) -> str:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERS).hex()

def has_password() -> bool:
    return cfg_get("pw_hash") is not None

def new_session() -> str:
    token = secrets.token_urlsafe(32)
    SESSIONS[token] = time.time() + SESSION_TTL
    return token

def session_ok(request: Request) -> bool:
    token = request.headers.get("X-Session-Token", "")
    exp = SESSIONS.get(token)
    if exp is None:
        return False
    if time.time() > exp:
        SESSIONS.pop(token, None)
        return False
    SESSIONS[token] = time.time() + SESSION_TTL      # 滑动续期
    return True

def require_session(request: Request) -> None:
    if not session_ok(request):
        raise HTTPException(401, "未登录或会话已过期")

# ----------------------------------------------------------------------------
# API key 工具
# ----------------------------------------------------------------------------
def generate_api_key() -> tuple[str, str, str]:
    """返回 (full_key, prefix, key_hash)"""
    prefix = secrets.token_hex(4)
    secret = secrets.token_hex(20)
    full = f"lg_{prefix}_{secret}"
    return full, prefix, hashlib.sha256(full.encode()).hexdigest()

def key_hash_ok(full_key: str) -> Optional[sqlite3.Row]:
    with DB_LOCK, db() as conn:
        rows = conn.execute("SELECT * FROM apikeys WHERE enabled=1").fetchall()
    want = hashlib.sha256(full_key.encode()).hexdigest()
    for r in rows:
        if hmac.compare_digest(r["key_hash"], want):
            return r
    return None

def rate_allow(krow) -> tuple[bool, int, float]:
    """滑动窗口; 返回 (允许否, 剩余额度, 窗口重置秒)"""
    now = time.time()
    q = RATE_BUCKETS.setdefault(krow["id"], deque())
    while q and q[0] <= now - krow["window_seconds"]:
        q.popleft()
    remaining = krow["rate_limit"] - len(q)
    reset = (q[0] + krow["window_seconds"] - now) if q else 0.0
    if len(q) >= krow["rate_limit"]:
        return False, max(remaining, 0), max(reset, 0.0)
    q.append(now)
    return True, max(remaining - 1, 0), max(reset, 0.0)

def touch_key(key_id: int) -> None:
    with DB_LOCK, db() as conn:
        conn.execute("UPDATE apikeys SET last_used=? WHERE id=?", (now_iso(), key_id))

# ----------------------------------------------------------------------------
# 上游适配器（统一返回 [{source,title,year,venue,authors,doi,url}]）
# ----------------------------------------------------------------------------
def _n(v):
    return v.strip() if isinstance(v, str) else v

def _yr(r):
    try:
        return int(r.get("year") or 0)
    except (TypeError, ValueError):
        return 0

def _client_sort(out, sort):
    """无服务端排序的源（Semantic Scholar 等）在本地按被引/年份重排；relevance 原样返回"""
    if sort == "cited":
        out.sort(key=lambda r: (r["cited"] if isinstance(r.get("cited"), int) else -1), reverse=True)
    elif sort == "newest":
        out.sort(key=_yr, reverse=True)
    elif sort == "oldest":
        out.sort(key=_yr)
    return out

async def fetch_source(adapter: str, cfg: dict, q: str, limit: int,
                       field: str = "all", sort: str = "relevance",
                       year_from=None, year_to=None, cited_min=None, cited_max=None, oa="any") -> list:
    lim = max(1, min(limit or 10, 50))
    try:
        year_from = int(year_from) if year_from else None
    except (TypeError, ValueError):
        year_from = None
    try:
        year_to = int(year_to) if year_to else None
    except (TypeError, ValueError):
        year_to = None

    if adapter == "crossref":
        params = {"rows": lim,
                  "select": "DOI,title,container-title,issued,author,URL,is-referenced-by-count"}
        if field == "title":
            params["query.title"] = q
        elif field == "author":
            params["query.author"] = q
        else:                                    # all / abstract（Crossref 无摘要检索，回退全字段）
            params["query"] = q
        if sort == "newest":
            params["sort"], params["order"] = "published", "desc"
        elif sort == "oldest":
            params["sort"], params["order"] = "published", "asc"
        elif sort in ("cited", "cited_asc"):
            params["sort"], params["order"] = "is-referenced-by-count", "desc" if sort == "cited" else "asc"
        flt = []
        if year_from:
            flt.append(f"from-pub-date:{year_from}-01-01")
        if year_to:
            flt.append(f"until-pub-date:{year_to}-12-31")
        if flt:
            params["filter"] = ",".join(flt)
        if cfg.get("email"):
            params["mailto"] = cfg["email"]
        r = await upstream_get("https://api.crossref.org/works",
                               params=params, label="Crossref")
        out = []
        for it in r.json().get("message", {}).get("items", []):
            out.append({
                "source": "Crossref",
                "title": " ".join(it.get("title") or ["(无题名)"]),
                "year": (it.get("issued", {}).get("date-parts") or [[None]])[0][0],
                "venue": (it.get("container-title") or [""])[0],
                "authors": ", ".join(f"{a.get('family','')}" for a in (it.get("author") or [])[:6]),
                "doi": it.get("DOI", ""),
                "url": "https://doi.org/" + it.get("DOI", "") if it.get("DOI") else (it.get("URL") or ""),
                "cited": it.get("is-referenced-by-count"),
            })
        return out

    if adapter == "openalex":
        params = {"per_page": lim}
        if field == "title":
            params["filter"] = f"title.search:{q}"
        elif field == "abstract":
            params["filter"] = f"abstract.search:{q}"
        elif field == "author":
            author_headers = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg.get("api_key") else {}
            authors_response = await upstream_get("https://api.openalex.org/authors",
                params={"search": q, "per_page": 10}, headers=author_headers, label="OpenAlex作者")
            author_ids = [a["id"].rsplit("/", 1)[-1] for a in authors_response.json().get("results", []) if a.get("id")]
            if not author_ids:
                return []
            params["filter"] = "authorships.author.id:" + "|".join(author_ids)
        else:
            params["search"] = q
        ycond = []
        if year_from:
            ycond.append(f"from_publication_date:{year_from}-01-01")
        if year_to:
            ycond.append(f"to_publication_date:{year_to}-12-31")
        if cited_min is not None and cited_min > 0:
            ycond.append(f"cited_by_count:>{cited_min - 1}")
        if cited_max is not None:
            ycond.append(f"cited_by_count:<{cited_max + 1}")
        if oa == "yes":
            ycond.append("open_access.is_oa:true")
        if ycond:
            params["filter"] = (params["filter"] + "," + ",".join(ycond)
                                if "filter" in params else ",".join(ycond))
        if sort in ("cited", "cited_asc"):
            params["sort"] = "cited_by_count:" + ("desc" if sort == "cited" else "asc")
        elif sort == "newest":
            params["sort"] = "publication_date:desc"
        elif sort == "oldest":
            params["sort"] = "publication_date:asc"
        elif "filter" not in params:             # relevance_score 仅在 search 模式可用
            params["sort"] = "relevance_score:desc"
        oa_headers = {"Authorization": f"Bearer {cfg['api_key']}"} if cfg.get("api_key") else {}
        if cfg.get("mailto"):
            params["mailto"] = cfg["mailto"]          # polite 池，可与 api_key 叠加
        r = await upstream_get("https://api.openalex.org/works",
                               params=params, headers=oa_headers, label="OpenAlex")
        out = []
        for it in r.json().get("results", []):
            src = ((it.get("primary_location") or {}).get("source") or {})
            out.append({
                "source": "OpenAlex",
                "title": it.get("title") or it.get("display_name") or "(无题名)",
                "year": it.get("publication_year"),
                "venue": src.get("display_name", ""),
                "authors": ", ".join(a.get("author", {}).get("display_name", "")
                                     for a in (it.get("authorships") or [])[:6]),
                "doi": (it.get("doi") or "").replace("https://doi.org/", ""),
                "url": it.get("doi") or (it.get("id") or ""),
                "cited": it.get("cited_by_count"),
                "is_oa": (it.get("open_access") or {}).get("is_oa"),
                "pdf_url": (it.get("best_oa_location") or {}).get("pdf_url"),
            })
        return out

    if adapter == "semanticscholar":
        global S2_LAST
        s2_key = cfg.get("api_key") or ""
        s2_headers = {"x-api-key": s2_key} if s2_key else {}
        interval = S2_MIN_INTERVAL
        s2_params = {"query": q, "limit": min(lim, 100),
                     "fields": "title,abstract,year,venue,authors,externalIds,citationCount,publicationDate,isOpenAccess,openAccessPdf"}
        if year_from or year_to:                 # S2 接受 year=起-止
            s2_params["year"] = f"{year_from or 1800}-{year_to or 2100}"
        async with S2_LOCK:                      # 串行 + 最小间隔, 规避 429
            wait = S2_LAST["t"] + interval - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                r = await upstream_get("https://api.semanticscholar.org/graph/v1/paper/search",
                                       params=s2_params, headers=s2_headers,
                                       label="Semantic Scholar")
            finally:
                S2_LAST["t"] = time.time()       # 失败也计入间隔，防止失败后立刻重发
        out = []
        for it in r.json().get("data", []):
            doi = (it.get("externalIds") or {}).get("DOI", "")
            out.append({
                "source": "Semantic Scholar",
                "title": it.get("title") or "(无题名)",
                "year": it.get("year"),
                "venue": it.get("venue") or "",
                "authors": ", ".join(a.get("name", "") for a in (it.get("authors") or [])[:6]),
                "doi": doi,
                "url": "https://doi.org/" + doi if doi else "",
                "cited": it.get("citationCount"),
                "abstract": it.get("abstract") or "",
                "is_oa": it.get("isOpenAccess"),
                "pdf_url": (it.get("openAccessPdf") or {}).get("url"),
            })
        return _client_sort(out, sort)           # S2 无服务端排序，本地按被引/年份重排

    if adapter == "arxiv":
        safe_q = " ".join(re.sub(r'["\':()\[\]{}&?#]', " ", q).split())  # 去掉会破坏 arXiv 语法的字符
        if not safe_q:
            return []
        prefix = {"title": "ti:", "abstract": "abs:", "author": "au:"}.get(field, "all:")
        sq = f"{prefix}{safe_q}"
        if year_from or year_to:                 # submittedDate 区间过滤
            sq += (f" AND submittedDate:[{year_from or 1000}01010000"
                   f" TO {year_to or 2999}12312359]")
        async with ARXIV_LOCK:                   # 串行 + 3 秒最小间隔（406 是 arXiv 的限流信号）
            wait = ARXIV_LAST["t"] + 3.0 - time.time()
            if wait > 0:
                await asyncio.sleep(wait)
            try:
                r = await upstream_get("https://export.arxiv.org/api/query", params={
                    "search_query": sq, "max_results": lim,
                    "sortBy": "submittedDate" if sort in ("newest", "oldest") else "relevance",
                    "sortOrder": "ascending" if sort == "oldest" else "descending"},
                    label="arXiv", retries=2, backoff=(4.0, 10.0))
            finally:
                ARXIV_LAST["t"] = time.time()    # 失败也计入间隔，防止失败后立刻重发
        ns = {"a": "http://www.w3.org/2005/Atom"}
        root = ET.fromstring(r.text)
        out = []
        for e in root.findall("a:entry", ns):
            doi = ""
            for d in e.findall("{http://arxiv.org/schemas/atom}doi"):
                doi = d.text or ""
            link = next((l.get("href") for l in e.findall("a:link", ns)
                         if l.get("type") == "application/pdf"), "")
            alink = e.find("a:id", ns)
            out.append({
                "source": "arXiv",
                "title": _n(e.findtext("a:title", "", ns)).replace("\n", " "),
                "year": (e.findtext("a:published", "", ns) or "")[:4] or None,
                "venue": "arXiv 预印本",
                "authors": ", ".join(a.findtext("a:name", "", ns) for a in e.findall("a:author", ns)[:6]),
                "doi": doi,
                "url": (alink.text if alink is not None else "") or link,
                "abstract": _n(e.findtext("a:summary", "", ns)),
                "is_oa": True,
                "pdf_url": link,
            })
        return out

    if adapter == "dblp":
        cookie = (cfg.get("cookie") or "").strip()
        db_headers = {"Accept": "application/json"}
        if cookie:
            db_headers["Cookie"] = cookie        # 用户浏览器通过 Anubis 验证后的会话
        payload, errs = None, []
        for host in ("https://dblp.org", "https://dblp.uni-trier.de", "https://dblp.dagstuhl.de"):
            try:
                r = await upstream_get(host + "/search/publ/api",
                                       params={"q": q, "format": "json", "h": lim},
                                       headers=db_headers, label="DBLP", retries=0)
            except UpstreamError as ex:
                errs.append(f"{host.split('//')[1]} 不可达（{_snippet(str(ex), 60)}）")
                continue
            try:
                payload = r.json()
                break
            except Exception:
                low = r.text[:3000].lower()
                if "within.website" in low or "not a bot" in low:
                    errs.append(f"{host.split('//')[1]} 弹人机验证页")
                else:
                    errs.append(f"{host.split('//')[1]} 返回非 JSON（HTTP {r.status_code}）")
        if payload is None:
            tip = ("已带上你配置的 Cookie 仍被拦——Cookie 可能已过期，请在浏览器重新完成验证后更新"
                   if cookie else
                   "解决方法（恢复 API 直连）：用浏览器打开 dblp.org 完成人机验证，然后 F12 → 网络(Network) → 刷新 → 任选一条 dblp 请求 → 复制请求头中完整的 Cookie 值，粘贴到该端点「配置」的 Cookie 字段")
            raise UpstreamError(f"DBLP 三个官方 API 入口均被拦截：{'；'.join(errs)}。{tip}")
        hits = (((payload.get("result") or {}).get("hits")) or {}).get("hit") or []
        out = []
        for h in hits:
            i = h.get("info", {})
            au = i.get("authors", {}).get("author", [])
            if isinstance(au, dict):
                au = [au]
            out.append({
                "source": "DBLP",
                "title": i.get("title", ""),
                "year": i.get("year"),
                "venue": i.get("venue", ""),
                "authors": ", ".join(a.get("text", "") if isinstance(a, dict) else str(a) for a in au[:6]),
                "doi": (i.get("doi") or "").replace("https://doi.org/", ""),
                "url": i.get("ee") or i.get("doi") or "",
            })
        if year_from:                            # DBLP 无服务端过滤，本地做
            out = [x for x in out if _yr(x) >= year_from]
        if year_to:
            out = [x for x in out if _yr(x) <= year_to]
        return _client_sort(out, sort)

    if adapter == "scopus":
        if field == "title":
            sq = f"TITLE({q})"
        elif field == "abstract":
            sq = f"ABS({q})"
        elif field == "author":
            sq = f"AUTHOR-NAME({q})"
        else:
            sq = f"ALL({q})"
        ycon = []
        if year_from:
            ycon.append(f"PUBYEAR > {year_from - 1}")
        if year_to:
            ycon.append(f"PUBYEAR < {year_to + 1}")
        if ycon:
            sq = "(" + sq + ") AND " + " AND ".join(ycon)
        params = {"query": sq, "count": lim}
        if sort in ("cited", "cited_asc"):
            params["sort"] = "-citedby-count" if sort == "cited" else "+citedby-count"
        elif sort == "newest":
            params["sort"] = "-coverDate"
        elif sort == "oldest":
            params["sort"] = "+coverDate"
        else:
            params["sort"] = "relevancy"
        sc_headers = {"Accept": "application/json"}
        if cfg.get("api_key"):
            sc_headers["X-ELS-APIKey"] = cfg["api_key"]
        if cfg.get("inst_token"):
            sc_headers["X-ELS-Insttoken"] = cfg["inst_token"]
        r = await upstream_get("https://api.elsevier.com/content/search/scopus",
                               params=params, headers=sc_headers, label="Scopus")
        entries = ((((r.json().get("search-results") or {}).get("entry")) or []))
        out = []
        for e in entries:
            doi = (e.get("prism:doi") or "").replace("https://doi.org/", "") \
                  if e.get("prism:doi") else (e.get("dc:identifier") or "").replace("DOI:", "")
            out.append({
                "source": "Scopus",
                "title": e.get("dc:title", ""),
                "year": (e.get("prism:coverDate") or "")[:4] or None,
                "venue": e.get("prism:publicationName", ""),
                "authors": e.get("dc:creator", "") or
                           ", ".join(c.get("authname", "") if isinstance(c, dict) else str(c)
                                     for c in (e.get("dc:creators") or [])[:6]),
                "doi": doi,
                "url": "https://doi.org/" + doi if doi else "",
                "cited": int(e["citedby-count"]) if str(e.get("citedby-count", "")).isdigit() else None,
                "is_oa": str(e.get("openaccess")) == "1" if e.get("openaccess") is not None else None,
            })
        return out

    raise ValueError(f"未知适配器: {adapter}")

def get_endpoint(adapter_or_id):
    with DB_LOCK, db() as conn:
        if isinstance(adapter_or_id, int):
            r = conn.execute("SELECT * FROM endpoints WHERE id=?", (adapter_or_id,)).fetchone()
        else:
            r = conn.execute("SELECT * FROM endpoints WHERE adapter=? AND enabled=1",
                             (adapter_or_id,)).fetchone()
    return r

# ----------------------------------------------------------------------------
# 认证 / 初始化
# ----------------------------------------------------------------------------
@app.post("/api/setup")
async def setup(request: Request):
    body = await request.json()
    pw = (body or {}).get("password", "")
    if len(pw) < 8:
        raise HTTPException(400, "密码至少 8 位")
    if has_password():
        raise HTTPException(409, "密码已存在，不能重复初始化")
    salt = secrets.token_bytes(16)
    cfg_set("pw_salt", salt.hex())
    cfg_set("pw_hash", hash_password(pw, salt))
    return {"ok": True, "token": new_session()}

@app.post("/api/login")
async def login(request: Request):
    if time.time() < LOGIN_FAILS["until"]:
        raise HTTPException(429, f"失败次数过多，锁定至 {int(LOGIN_FAILS['until']-time.time())} 秒后")
    body = await request.json()
    pw = (body or {}).get("password", "")
    salt = bytes.fromhex(cfg_get("pw_salt") or "")
    want = cfg_get("pw_hash") or ""
    if not (salt and want and hmac.compare_digest(hash_password(pw, salt), want)):
        LOGIN_FAILS["n"] += 1
        if LOGIN_FAILS["n"] >= LOGIN_FAIL_LIMIT:
            LOGIN_FAILS["until"] = time.time() + LOGIN_LOCK_SECONDS
            LOGIN_FAILS["n"] = 0
        await asyncio.sleep(0.5)
        raise HTTPException(401, "密码错误")
    LOGIN_FAILS["n"] = 0
    return {"ok": True, "token": new_session()}

@app.post("/api/logout")
async def logout(request: Request):
    token = request.headers.get("X-Session-Token", "")
    SESSIONS.pop(token, None)
    return {"ok": True}

@app.post("/api/password")
async def change_password(request: Request):
    require_session(request)
    body = await request.json()
    old, new = body.get("old", ""), body.get("new", "")
    if len(new) < 8:
        raise HTTPException(400, "新密码至少 8 位")
    salt = bytes.fromhex(cfg_get("pw_salt") or "")
    if not hmac.compare_digest(hash_password(old, salt), cfg_get("pw_hash") or ""):
        raise HTTPException(401, "原密码错误")
    salt2 = secrets.token_bytes(16)
    cfg_set("pw_salt", salt2.hex())
    cfg_set("pw_hash", hash_password(new, salt2))
    return {"ok": True}

# ----------------------------------------------------------------------------
# 状态 / 总闸
# ----------------------------------------------------------------------------
@app.get("/api/state")
async def state(request: Request):
    powered = cfg_get("powered", "1") == "1"
    authed = session_ok(request)
    data = {"initialized": has_password(), "authed": authed, "powered": powered}
    if authed:
        with DB_LOCK, db() as conn:
            eps = conn.execute("SELECT id,name,adapter,enabled,config,note FROM endpoints ORDER BY id").fetchall()
            keys = conn.execute("SELECT id,name,prefix,enabled,rate_limit,window_seconds,allowed,created,last_used "
                                "FROM apikeys ORDER BY id").fetchall()
        data["endpoints"] = []
        for e in eps:
            cfg = json.loads(e["config"] or "{}")
            data["endpoints"].append(dict(e) | {
                "config": public_config(cfg),
                "configured_secrets": [k for k, v in cfg.items() if k.lower() in SECRET_FIELDS and v],
                "credential_info": SOURCE_INFO.get(e["adapter"], {}),
            })
        data["source_info"] = SOURCE_INFO
        data["links_verified_on"] = VERIFIED_ON
        data["keys"] = [dict(k) | {"allowed": json.loads(k["allowed"] or '["*"]')} for k in keys]
    return data

@app.post("/api/power")
async def power(request: Request):
    require_session(request)
    body = await request.json()
    on = bool(body.get("on"))
    cfg_set("powered", "1" if on else "0")
    return {"ok": True, "powered": on}

# ----------------------------------------------------------------------------
# 端点管理（登录态）
# ----------------------------------------------------------------------------
@app.post("/api/endpoints")
async def create_endpoint(request: Request):
    require_session(request)
    b = await request.json()
    if not b.get("name") or not b.get("adapter"):
        raise HTTPException(400, "name 与 adapter 必填")
    with DB_LOCK, db() as conn:
        conn.execute("INSERT INTO endpoints(name,adapter,enabled,config,note) VALUES(?,?,?,?,?)",
                     (b["name"], b["adapter"], int(bool(b.get("enabled", True))),
                      json.dumps(b.get("config", {})), b.get("note", "")))
    return {"ok": True}

@app.patch("/api/endpoints/{eid}")
async def update_endpoint(eid: int, request: Request):
    require_session(request)
    b = await request.json()
    with DB_LOCK, db() as conn:
        row = conn.execute("SELECT * FROM endpoints WHERE id=?", (eid,)).fetchone()
        if not row:
            raise HTTPException(404, "端点不存在")
        if "name" in b: conn.execute("UPDATE endpoints SET name=? WHERE id=?", (b["name"], eid))
        if "enabled" in b: conn.execute("UPDATE endpoints SET enabled=? WHERE id=?", (int(b["enabled"]), eid))
        if "note" in b: conn.execute("UPDATE endpoints SET note=? WHERE id=?", (b["note"], eid))
        if "config" in b:
            if not isinstance(b["config"], dict):
                raise HTTPException(400, "config须为对象")
            cfg = update_config(json.loads(row["config"] or "{}"), b["config"], bool(b.get("clear_secrets")))
            conn.execute("UPDATE endpoints SET config=? WHERE id=?", (json.dumps(cfg), eid))
    return {"ok": True}

@app.delete("/api/endpoints/{eid}")
async def delete_endpoint(eid: int, request: Request):
    require_session(request)
    with DB_LOCK, db() as conn:
        conn.execute("DELETE FROM endpoints WHERE id=?", (eid,))
    return {"ok": True}

# ----------------------------------------------------------------------------
# API key 管理（登录态）
# ----------------------------------------------------------------------------
@app.post("/api/keys")
async def create_key(request: Request):
    require_session(request)
    b = await request.json()
    if not b.get("name"):
        raise HTTPException(400, "名称必填")
    full, prefix, khash = generate_api_key()
    with DB_LOCK, db() as conn:
        cur = conn.execute(
            "INSERT INTO apikeys(name,prefix,key_hash,enabled,rate_limit,window_seconds,allowed,created) "
            "VALUES(?,?,?,?,?,?,?,?)",
            (b["name"], prefix, khash, 1,
             int(b.get("rate_limit", 30)), int(b.get("window_seconds", 60)),
             json.dumps(b.get("allowed", ["*"])), now_iso()))
        kid = cur.lastrowid
    return {"ok": True, "id": kid, "api_key": full,
            "note": "此密钥只显示这一次，请立即保存"}

@app.patch("/api/keys/{kid}")
async def update_key(kid: int, request: Request):
    require_session(request)
    b = await request.json()
    with DB_LOCK, db() as conn:
        row = conn.execute("SELECT id FROM apikeys WHERE id=?", (kid,)).fetchone()
        if not row:
            raise HTTPException(404, "key 不存在")
        if "name" in b: conn.execute("UPDATE apikeys SET name=? WHERE id=?", (b["name"], kid))
        if "enabled" in b: conn.execute("UPDATE apikeys SET enabled=? WHERE id=?", (int(b["enabled"]), kid))
        if "rate_limit" in b: conn.execute("UPDATE apikeys SET rate_limit=? WHERE id=?", (int(b["rate_limit"]), kid))
        if "window_seconds" in b: conn.execute("UPDATE apikeys SET window_seconds=? WHERE id=?", (int(b["window_seconds"]), kid))
        if "allowed" in b: conn.execute("UPDATE apikeys SET allowed=? WHERE id=?", (json.dumps(b["allowed"]), kid))
        RATE_BUCKETS.pop(kid, None)
    return {"ok": True}

@app.delete("/api/keys/{kid}")
async def delete_key(kid: int, request: Request):
    require_session(request)
    with DB_LOCK, db() as conn:
        conn.execute("DELETE FROM apikeys WHERE id=?", (kid,))
    RATE_BUCKETS.pop(kid, None)
    return {"ok": True}

# ----------------------------------------------------------------------------
# 会话内查询（多源扇出）
# ----------------------------------------------------------------------------
async def execute_search(eps, opt):
    async def one(e):
        adapter = e["adapter"]
        info = SOURCE_INFO.get(adapter)
        if not info or opt["field"] not in info["fields"]:
            return {"source": e["name"], "adapter": adapter, "ok": False,
                    "error": "该数据源不支持所选检索范围，已跳过"}
        try:
            records = await fetch_source(adapter, json.loads(e["config"] or "{}"),
                opt["q"], opt["limit"], field=opt["field"], sort=opt["sort"],
                year_from=opt["year_from"], year_to=opt["year_to"],
                cited_min=opt["cited_min"], cited_max=opt["cited_max"], oa=opt["oa"])
            warning = info["note"]
            if adapter in ("dblp", "semanticscholar") and opt["field"] != "all":
                fields = {"title": ("title",), "abstract": ("title", "abstract"), "author": ("authors",)}[opt["field"]]
                terms = [term.casefold() for pair in re.findall(r'"([^"]+)"|([^\s"]+)', opt["q"]) for term in pair if term]
                records = [r for r in records if all(term in " ".join(str(r.get(f) or "") for f in fields).casefold() for term in terms)]
                warning += " 检索范围由本次返回元数据本地筛选。"
            return {"source": info["name"], "endpoint": e["name"], "adapter": adapter,
                    "ok": True, "results": records, "note": warning}
        except UpstreamError as ex:
            return {"source": info["name"], "adapter": adapter, "ok": False, "error": str(ex)}
        except Exception as ex:
            return {"source": info["name"], "adapter": adapter, "ok": False,
                    "error": f"上游数据处理失败（{type(ex).__name__}）"}
    packets = await asyncio.gather(*(one(e) for e in eps))
    return {"q": opt["q"], "sources": packets, "options": opt, **combine(packets, opt)}

def enabled_endpoints():
    with DB_LOCK, db() as conn:
        rows = conn.execute("SELECT * FROM endpoints WHERE enabled=1 ORDER BY id").fetchall()
    # Multiple configured endpoints for an adapter are alternatives, not duplicate sources.
    seen = set()
    return [r for r in rows if not (r["adapter"] in seen or seen.add(r["adapter"]))]

@app.post("/api/query")
async def query(request: Request):
    require_session(request)
    b = await request.json()
    try:
        opt = options(b)
    except ValueError as ex:
        raise HTTPException(400, str(ex))
    sources = b.get("sources")
    if not isinstance(sources, list) or not sources:
        raise HTTPException(400, "请至少选择一个数据源")
    if any(src not in SOURCE_INFO for src in sources):
        raise HTTPException(400, "未知数据源")
    chosen = [e for e in enabled_endpoints() if e["adapter"] in sources]
    if not chosen:
        raise HTTPException(400, "所选数据源均未启用")
    return {**await execute_search(chosen, opt), "powered": cfg_get("powered", "1") == "1"}

# ----------------------------------------------------------------------------
# 连通性检测（登录态）
# ----------------------------------------------------------------------------
async def _tcp_probe(ip: str, port: int, timeout: float = 1.5) -> Optional[float]:
    loop = asyncio.get_event_loop()
    def _do():
        t0 = time.time()
        try:
            with socket.create_connection((ip, port), timeout=timeout):
                return (time.time() - t0) * 1000
        except OSError:
            return None
    return await loop.run_in_executor(None, _do)

@app.get("/api/netcheck")
async def netcheck(request: Request, endpoint: str = "", target: str = "", port: int = 0):
    """endpoint=适配器名 → 实测上游 API；target=主机或 CIDR → TCP 连通探测。"""
    require_session(request)

    if endpoint:
        ep = get_endpoint(endpoint)
        if ep is None:
            raise HTTPException(404, "端点不存在或未启用")
        t0 = time.time()
        try:
            res = await fetch_source(ep["adapter"], json.loads(ep["config"] or "{}"), "test", 1)
            return {"mode": "endpoint", "endpoint": ep["name"], "ok": True,
                    "latency_ms": round((time.time() - t0) * 1000),
                    "sample": (res[0]["title"][:80] if res else "(空结果,但接口可达)")}
        except Exception as ex:
            detail = getattr(ex, "response", None)
            code = getattr(detail, "status_code", None) if detail is not None else None
            return {"mode": "endpoint", "endpoint": ep["name"], "ok": False,
                    "latency_ms": round((time.time() - t0) * 1000),
                    "error": f"HTTP {code}" if code else (str(ex) if isinstance(ex, UpstreamError) else f"上游处理失败（{type(ex).__name__}）")}

    if target:
        target = target.strip()
        if "/" in target:                                   # CIDR 网段
            try:
                net = ipaddress.ip_network(target, strict=False)
            except ValueError:
                raise HTTPException(400, "网段格式错误")
            if net.num_addresses > 256:
                raise HTTPException(400, f"网段过大（{net.num_addresses} 个地址），上限 256")
            p = port or 80
            sem = asyncio.Semaphore(48)
            async def one(ip):
                async with sem:
                    ms = await _tcp_probe(str(ip), p)
                    return {"ip": str(ip), "ms": round(ms)} if ms is not None else None
            hits = [h for h in await asyncio.gather(*(one(ip) for ip in net.hosts()
                                                      if str(ip) != "0.0.0.0")) if h]
            return {"mode": "cidr", "cidr": str(net), "port": p,
                    "scanned": net.num_addresses - 2 if net.num_addresses > 2 else net.num_addresses,
                    "reachable": hits}
        else:                                               # 单主机 / 域名
            p = port or 443
            try:
                infos = await asyncio.get_event_loop().getaddrinfo(target, p, proto=socket.IPPROTO_TCP)
                ip = infos[0][4][0]
            except OSError:
                return {"mode": "host", "target": target, "port": p, "ok": False,
                        "error": "域名解析失败"}
            ms = await _tcp_probe(ip, p)
            return {"mode": "host", "target": target, "ip": ip, "port": p,
                    "ok": ms is not None,
                    "latency_ms": round(ms) if ms is not None else None}

    raise HTTPException(400, "缺少参数：endpoint 或 target")

# ----------------------------------------------------------------------------
# 转发 API（对外, X-Api-Key）
# ----------------------------------------------------------------------------
FORWARD_EXC = {"powered_off": (503, "网关已断电（总闸关闭）"),
               "bad_key": (401, "API key 无效或已停用"),
               "rate": (429, "超出该 key 的频率限制"),
               "no_source": (400, "数据源不可用或未授权")}

@app.get("/v1/search")
async def v1_search(request: Request, q: str, source: str = "crossref", limit: int = 20,
                    field: str = "all", sort: str = "relevance",
                    year_from: int = None, year_to: int = None,
                    cited_min: int = None, cited_max: int = None, venue: str = "",
                    author: str = "", exclude: str = "", oa: str = "any", dedupe: bool = True):
    if cfg_get("powered", "1") != "1":
        return JSONResponse(status_code=503, content={"error": FORWARD_EXC["powered_off"][1]})
    key = request.headers.get("X-Api-Key", "")
    krow = key_hash_ok(key) if key else None
    if krow is None:
        return JSONResponse(status_code=401, content={"error": FORWARD_EXC["bad_key"][1]})
    try:
        opt = options(dict(q=q,limit=limit,field=field,sort=sort,year_from=year_from,year_to=year_to,
            cited_min=cited_min,cited_max=cited_max,venue=venue,author=author,exclude=exclude,oa=oa,dedupe=dedupe))
    except ValueError as ex:
        return JSONResponse(status_code=400, content={"error": str(ex)})
    allowed = json.loads(krow["allowed"] or '["*"]')
    eps = enabled_endpoints()
    requested = [x.strip().lower() for x in source.split(",") if x.strip()]
    if source.strip().lower() == "all":
        requested = [e["adapter"] for e in eps if allowed == ["*"] or e["adapter"] in allowed]
    if not requested or any(x not in SOURCE_INFO or (allowed != ["*"] and x not in allowed) for x in requested):
        return JSONResponse(status_code=400, content={"error": FORWARD_EXC["no_source"][1]})
    chosen = [e for e in eps if e["adapter"] in requested]
    if not chosen or set(requested) != {e["adapter"] for e in chosen}:
        return JSONResponse(status_code=400, content={"error": FORWARD_EXC["no_source"][1]})
    ok, remaining, reset = rate_allow(krow)
    headers = {"X-RateLimit-Limit": str(krow["rate_limit"]), "X-RateLimit-Remaining": str(remaining),
               "X-RateLimit-Reset": f"{reset:.1f}"}
    if not ok:
        return JSONResponse(status_code=429, content={"error": FORWARD_EXC["rate"][1]}, headers=headers)
    result = await execute_search(chosen,opt)
    if not any(p.get("ok") for p in result["sources"]):
        return JSONResponse(status_code=502, content={"error":"所选数据源均未成功；查看sources中的说明",**result},headers=headers)
    touch_key(krow["id"])
    result.update(source=chosen[0]["name"] if len(chosen)==1 else "multi",count=len(result["results"]))
    return JSONResponse(result,headers=headers)


@app.get("/v1/quota")
async def v1_quota(request: Request):
    if cfg_get("powered", "1") != "1":
        return JSONResponse(status_code=503, content={"error": FORWARD_EXC["powered_off"][1]})
    key = request.headers.get("X-Api-Key", "")
    krow = key_hash_ok(key) if key else None
    if krow is None:
        return JSONResponse(status_code=401, content={"error": FORWARD_EXC["bad_key"][1]})
    q = RATE_BUCKETS.get(krow["id"], deque())
    now = time.time()
    fresh = [t for t in q if t > now - krow["window_seconds"]]
    return {"limit": krow["rate_limit"], "window_seconds": krow["window_seconds"],
            "remaining": max(krow["rate_limit"] - len(fresh), 0)}

# ----------------------------------------------------------------------------
# UI
# ----------------------------------------------------------------------------
INDEX_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LitGate · 文献闸门</title>
<style>
:root{
  --porcelain:#F4F6F3; --surface:#FFFFFF; --ink:#1D2622; --sub:#5B6A63;
  --line:#D7DDD5; --live:#0F6E5C; --live-deep:#0A4A3E; --off:#B23A2C;
  --serif:Georgia,"Times New Roman","Songti SC","SimSun",serif;
  --sans:system-ui,-apple-system,"PingFang SC","Microsoft YaHei",sans-serif;
}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--porcelain);color:var(--ink);font-family:var(--sans);
     font-size:15px;line-height:1.65;-webkit-font-smoothing:antialiased}
body.power-off main,body.power-off .bar-tab{opacity:.45;pointer-events:none}
a{color:var(--live)}
.wrap{max-width:1080px;margin:0 auto;padding:0 20px 80px}
/* ---- 顶栏 ---- */
header{border-bottom:1px solid var(--line);background:var(--porcelain);
       position:sticky;top:0;z-index:5}
.bar{max-width:1080px;margin:0 auto;padding:14px 20px;display:flex;
     align-items:center;justify-content:space-between;gap:16px}
.wordmark{font-family:var(--serif);font-size:22px;letter-spacing:.5px}
.wordmark small{font-family:var(--sans);font-size:12.5px;color:var(--sub);
                margin-left:10px;letter-spacing:0}
/* ---- 总闸 ---- */
.breaker{display:flex;align-items:center;gap:12px;user-select:none}
.breaker .lamp{width:10px;height:10px;border-radius:50%;
  background:var(--live);box-shadow:0 0 0 3px rgba(15,110,92,.18);transition:.25s}
.breaker.off .lamp{background:var(--off);box-shadow:0 0 0 3px rgba(178,58,44,.18)}
.switch{width:58px;height:30px;border:1.5px solid var(--ink);border-radius:4px;
  background:var(--surface);cursor:pointer;position:relative;padding:0;flex:none}
.switch .knob{position:absolute;top:2px;left:2px;width:24px;height:22px;
  border-radius:2px;background:var(--live);transition:left .18s ease,background .18s ease}
.switch.off .knob{left:28px;background:var(--off)}
.breaker .lab{font-size:13px;color:var(--sub);min-width:64px}
.breaker .lab b{display:block;color:var(--ink);font-weight:600;font-size:14px}
/* ---- 断电横幅 ---- */
.blackout{display:none;background:var(--off);color:#fff;text-align:center;
  padding:9px 16px;font-size:14px}
body.power-off .blackout{display:block}
/* ---- 登录 / 初始化 ---- */
.gate{max-width:420px;margin:12vh auto 0;background:var(--surface);
  border:1px solid var(--line);border-radius:6px;padding:34px 36px}
.gate h1{font-family:var(--serif);font-size:26px;margin:0 0 4px;font-weight:600}
.gate p.sub{margin:0 0 22px;color:var(--sub);font-size:14px}
.warn{border-left:3px solid var(--off);background:#FBEFEC;padding:10px 14px;
  font-size:13.5px;margin:0 0 18px;border-radius:0 4px 4px 0}
label.f{display:block;margin:14px 0 4px;font-size:13.5px;color:var(--sub)}
input[type=password],input[type=text],input[type=number],select,textarea{
  width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:4px;
  font:inherit;background:var(--surface);color:var(--ink)}
textarea{font-family:ui-monospace,Consolas,monospace;font-size:13px;resize:vertical}
input:focus-visible,select:focus-visible,button:focus-visible,
.tab:focus-visible,.switch:focus-visible{outline:2px solid var(--live);outline-offset:2px}
button.primary{background:var(--ink);color:#fff;border:none;border-radius:4px;
  padding:10px 22px;font:inherit;cursor:pointer;margin-top:20px}
button.primary:hover{background:#000}
button.ghost{background:none;border:1px solid var(--line);border-radius:4px;
  padding:6px 13px;font:inherit;cursor:pointer;color:var(--sub)}
button.ghost:hover{border-color:var(--ink);color:var(--ink)}
button.danger{color:var(--off);border-color:#E3C4BC}
.err{color:var(--off);font-size:13.5px;margin-top:12px;min-height:18px}
/* ---- 标签页 ---- */
.tabs{display:flex;gap:4px;margin:26px 0 20px;border-bottom:1px solid var(--line)}
.tab{background:none;border:none;border-bottom:2px solid transparent;
  padding:8px 16px 10px;font:inherit;font-size:15px;color:var(--sub);cursor:pointer}
.tab.on{color:var(--ink);border-bottom-color:var(--ink);font-weight:600}
/* ---- 查询 ---- */
.searchrow{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.searchrow input[type=text]{flex:1;min-width:220px}
.searchrow select{width:110px;flex:none}
.srcs{display:flex;gap:8px 18px;flex-wrap:wrap;margin:0 0 20px;font-size:14px}
.srcs label{display:flex;align-items:center;gap:6px;color:var(--sub);cursor:pointer}
h2.sec{font-family:var(--serif);font-size:19px;font-weight:600;margin:30px 0 10px}
h2.sec:first-child{margin-top:0}
.card{background:var(--surface);border:1px solid var(--line);border-radius:6px;
  padding:18px 20px;margin-bottom:16px}
.card h3{margin:0 0 4px;font-size:15.5px;font-weight:600;display:flex;
  justify-content:space-between;align-items:baseline;gap:10px}
.card h3 .st{font-size:13px;font-weight:400;color:var(--sub)}
.card h3 .st.bad{color:var(--off)}
/* ---- 表格 ---- */
.tblwrap{overflow-x:auto}
table{border-collapse:collapse;width:100%;font-size:14px}
th{text-align:left;font-weight:600;color:var(--sub);font-size:13px;
   border-bottom:1px solid var(--ink);padding:7px 10px;white-space:nowrap}
td{border-bottom:1px solid var(--line);padding:8px 10px;vertical-align:top}
tr:hover td{background:#FAFBF9}
td.t{font-family:var(--serif);font-size:15px;min-width:260px}
td a{text-decoration:none;border-bottom:1px dotted var(--live)}
.mono{font-family:ui-monospace,Consolas,monospace;font-size:13px}
.pill{display:inline-block;font-size:12px;padding:1px 8px;border-radius:10px;
  border:1px solid var(--line);color:var(--sub)}
.pill.on{border-color:var(--live);color:var(--live)}
/* ---- 管理表单 ---- */
.formrow{display:flex;gap:10px;flex-wrap:wrap;align-items:flex-end}
.formrow .f{flex:1;min-width:150px}
.formrow label{display:block;font-size:12.5px;color:var(--sub);margin-bottom:4px}
.formrow button{margin-top:0}
/* ---- 一次性密钥 ---- */
.once{position:fixed;inset:0;background:rgba(29,38,34,.55);display:flex;
  align-items:center;justify-content:center;z-index:20;padding:20px}
.once .box{background:var(--surface);border-radius:6px;max-width:520px;width:100%;
  padding:28px 30px;border-top:4px solid var(--live)}
.once .key{font-family:ui-monospace,Consolas,monospace;font-size:15px;
  word-break:break-all;background:var(--porcelain);padding:12px 14px;
  border-radius:4px;margin:14px 0}
.toast{position:fixed;bottom:22px;left:50%;transform:translateX(-50%);
  background:var(--ink);color:#fff;padding:9px 20px;border-radius:4px;
  font-size:14px;opacity:0;transition:opacity .2s;pointer-events:none;z-index:30}
.toast.show{opacity:1}
.hint{font-size:13px;color:var(--sub)}
@media (prefers-reduced-motion:reduce){*{transition:none!important}}
@media (max-width:640px){.gate{margin:6vh 12px 0;padding:26px 22px}
  .bar{flex-wrap:wrap}}
</style>
</head>
<body>
<header><div class="bar">
  <div class="wordmark">LitGate<small>文献查询与转发闸门</small></div>
  <div class="breaker" id="breaker" style="display:none">
    <span class="lamp"></span>
    <button class="switch" id="swBtn" aria-label="总闸" title="总闸：切换转发供电">
      <span class="knob"></span></button>
    <span class="lab"><b id="swState">已上电</b><span id="swSub">转发 API 正常供电</span></span>
  </div>
</div></header>
<div class="blackout" id="blackout">转发已切断——总闸处于断电状态，所有 <span class="mono">/v1</span> 请求将被拒绝。</div>

<!-- 初始化 / 登录 -->
<div class="gate" id="gateInit" style="display:none">
  <h1>设置主密码</h1>
  <p class="sub">首次使用，为这个网关设置一个主密码。</p>
  <div class="warn">密码只以哈希形式保存，<b>没有任何找回途径</b>。忘记密码只能删除数据库文件重新初始化，届时所有 API key 一并作废。</div>
  <label class="f">密码（至少 8 位）</label>
  <input type="password" id="pw1" autocomplete="new-password">
  <label class="f">再输入一次</label>
  <input type="password" id="pw2" autocomplete="new-password">
  <button class="primary" onclick="doSetup()">创建并进入</button>
  <div class="err" id="initErr"></div>
</div>

<div class="gate" id="gateLogin" style="display:none">
  <h1>LitGate</h1>
  <p class="sub">输入主密码登录。会话 12 小时有效，重启服务后需重新登录。</p>
  <label class="f">主密码</label>
  <input type="password" id="pw" autocomplete="current-password"
         onkeydown="if(event.key==='Enter')doLogin()">
  <button class="primary" onclick="doLogin()">登录</button>
  <div class="err" id="loginErr"></div>
</div>

<!-- 主界面 -->
<div class="wrap" id="main" style="display:none">
  <div class="tabs">
    <button class="tab on" id="tabQ" onclick="showTab('q')">查询</button>
    <button class="tab" id="tabM" onclick="showTab('m')">管理</button>
    <button class="tab" id="tabA" onclick="showTab('a')">账户</button>
    <span style="flex:1"></span>
    <button class="tab" onclick="doLogout()">退出登录</button>
  </div>

  <section id="paneQ">
    <div class="searchrow">
      <input type="text" id="q" placeholder="输入题名、关键词、作者…" onkeydown="if(event.key==='Enter')doQuery()">
      <select id="lim"><option>5</option><option>10</option><option selected>20</option><option>50</option></select>
      <button class="primary" style="margin-top:0" onclick="doQuery()">查询</button>
    </div>
    <div class="searchrow" style="margin-top:8px">
      <div class="f" style="min-width:150px;max-width:190px"><label>检索范围</label>
        <select id="qField">
          <option value="all">全部字段</option><option value="title">仅标题</option>
          <option value="abstract">标题+摘要</option><option value="author">作者</option>
        </select></div>
      <div class="f" style="min-width:150px;max-width:190px"><label>排序</label>
        <select id="qSort">
          <option value="relevance">相关度</option><option value="newest">时间 新→旧</option>
          <option value="oldest">时间 旧→新</option><option value="cited">被引 高→低</option><option value="cited_asc">被引 低→高</option>
        </select></div>
      <div class="f" style="min-width:170px;max-width:210px"><label>年份范围（可选）</label>
        <input type="text" id="qYear" placeholder="如 2020-2026 或 2024"></div>
    </div>
    <div class="searchrow" style="margin-top:8px;flex-wrap:wrap">
      <div class="f"><label>引用量下限 / 上限</label><div style="display:flex;gap:6px"><input type="number" min="0" id="qCmin" placeholder="不限"><input type="number" min="0" id="qCmax" placeholder="不限"></div></div>
      <div class="f"><label>期刊 / 会议名称包含</label><input id="qVenue" type="text" placeholder="如 Automation in Construction"></div>
      <div class="f"><label>作者包含</label><input id="qAuthor" type="text" placeholder="如 Wang"></div>
      <div class="f"><label>排除词（逗号分隔）</label><input id="qExclude" type="text" placeholder="如 medical, survey"></div>
      <div class="f"><label>全文</label><select id="qOA"><option value="any">不限</option><option value="yes">确认公开全文</option></select></div>
    </div>
    <div class="srcs" id="srcChecks"></div>
    <label class="hint"><input type="checkbox" id="qDedupe" checked> 合并重复文献</label>
    <label class="hint" style="margin-left:14px"><input type="checkbox" id="qGrouped"> 按来源展示</label>
    <p class="hint" style="margin:6px 0 0">每源取回量由搜索框右侧选择（最多50条）。筛选与全局排序仅针对本次取回批次，不是全库命中数。无引用量的文献在引用量筛选时排除；各源引用量保留来源，不相加。</p>
    <div id="results"></div>
  </section>

  <section id="paneM" style="display:none">
    <h2 class="sec">数据源端点</h2>
    <div class="card"><div class="tblwrap"><table id="epTable"></table></div>
      <div class="formrow" style="margin-top:14px">
        <div class="f"><label>名称</label><input type="text" id="neName" placeholder="如 Crossref 备用"></div>
        <div class="f"><label>适配器</label><select id="neAdapter">
          <option>crossref</option><option>openalex</option><option>semanticscholar</option>
          <option>arxiv</option><option>dblp</option><option>scopus</option></select></div>
        <button class="ghost" onclick="addEndpoint()">新增端点</button>
      </div>
    </div>

    <h2 class="sec">连通性检测</h2>
    <div class="card">
      <div class="formrow">
        <div class="f"><label>按端点测上游 API</label><select id="ncEp"></select></div>
        <button class="ghost" onclick="ncEndpoint()">测试上游</button>
      </div>
      <div class="formrow" style="margin-top:12px">
        <div class="f"><label>按主机 / 网段测 TCP</label>
          <input type="text" id="ncTarget" placeholder="如 127.0.0.1、dblp.org 或 192.168.1.0/24"></div>
        <div class="f" style="max-width:110px"><label>端口（默认 443）</label>
          <input type="number" id="ncPort" placeholder="443"></div>
        <button class="ghost" onclick="ncTarget()">测试连通</button>
      </div>
      <div id="ncOut" class="hint" style="margin-top:10px;white-space:pre-wrap"></div>
    </div>

    <h2 class="sec">转发 API 密钥</h2>
    <div class="card"><div class="tblwrap"><table id="keyTable"></table></div>
      <div class="formrow" style="margin-top:14px">
        <div class="f"><label>名称</label><input type="text" id="nkName" placeholder="如 实验室脚本"></div>
        <div class="f" style="max-width:110px"><label>次数 / 窗口</label><input type="number" id="nkRate" value="30" min="1"></div>
        <div class="f" style="max-width:110px"><label>窗口（秒）</label><input type="number" id="nkWin" value="60" min="1"></div>
        <div class="f"><label>允许的数据源</label><input type="text" id="nkAllowed" placeholder="* 或逗号分隔，如 crossref,arxiv"></div>
        <button class="ghost" onclick="addKey()">生成密钥</button>
      </div>
      <p class="hint" style="margin-bottom:0">调用方式：<span class="mono">GET /v1/search?q=…&amp;source=crossref</span>，可选参数 <span class="mono">field=all|title|abstract|author</span>、<span class="mono">sort=relevance|newest|oldest|cited</span>、<span class="mono">year_from / year_to</span>。请求头带 <span class="mono">X-Api-Key</span>。配额查询：<span class="mono">GET /v1/quota</span>。</p>
    </div>
  </section>

  <section id="paneA" style="display:none">
    <h2 class="sec">修改主密码</h2>
    <div class="card" style="max-width:420px">
      <label class="f">原密码</label><input type="password" id="opw" autocomplete="current-password">
      <label class="f">新密码（至少 8 位）</label><input type="password" id="npw1" autocomplete="new-password">
      <label class="f">再输入一次</label><input type="password" id="npw2" autocomplete="new-password">
      <button class="primary" onclick="doChpw()">保存新密码</button>
      <div class="err" id="chpwErr"></div>
    </div>
  </section>
</div>

<div class="once" id="onceBox" style="display:none"><div class="box">
  <h3 style="font-size:17px;margin:0">密钥已生成</h3>
  <p class="hint">下面这串密钥<b>只显示这一次</b>，关闭后无法再查看，请立即复制保存。</p>
  <div class="key" id="onceKey"></div>
  <button class="primary" style="margin-top:0" onclick="copyOnce()">复制</button>
  <button class="ghost" style="margin-left:8px" onclick="document.getElementById('onceBox').style.display='none'">我已保存，关闭</button>
</div></div>

<div class="once" id="cfgBox" style="display:none"><div class="box" style="max-width:640px">
  <h3 style="font-size:17px;margin:0 0 2px" id="cfgTitle">端点配置</h3>
  <p class="hint" id="cfgAdp" style="margin:0 0 6px"></p>
  <div id="cfgFields"></div>
  <label class="f" style="margin-top:16px">实发请求预览 <span class="hint">（按对方接口的接收方式构造，随输入实时更新）</span></label>
  <pre id="cfgPreview" class="mono" style="margin:4px 0 0;padding:10px 12px;background:var(--ink);color:#d9e6de;border-radius:6px;white-space:pre-wrap;word-break:break-all;font-size:12px;line-height:1.6"></pre>
  <div id="cfgHist"></div>
  <details style="margin-top:14px">
    <summary class="hint" style="cursor:pointer;user-select:none">高级：直接编辑配置 JSON</summary>
    <textarea id="cfgJson" rows="5" style="margin-top:8px" oninput="jsonToFields()"></textarea>
  </details>
  <div style="margin-top:16px;display:flex;align-items:center;gap:8px">
    <button class="primary" style="margin-top:0" onclick="saveCfg()">保存</button>
    <button class="ghost" onclick="document.getElementById('cfgBox').style.display='none'">取消</button>
    <span style="flex:1"></span>
    <button class="ghost danger" onclick="clearCfgKeys()">清空密钥字段</button>
  </div>
</div></div>
<div class="toast" id="toast"></div>

<script>
let TOKEN="";
// Remove legacy persistent credential history when an upgraded page is opened.
Object.keys(localStorage).filter(k=>k==="litgate_token"||k.startsWith("litgate_hist_")).forEach(k=>localStorage.removeItem(k));
const $=id=>document.getElementById(id);
async function api(path,opt={}){
  const o=Object.assign({headers:{}},opt);
  o.headers["Content-Type"]="application/json";
  if(TOKEN)o.headers["X-Session-Token"]=TOKEN;
  const r=await fetch(path,o);
  const j=await r.json().catch(()=>({}));
  if(!r.ok)throw new Error(j.detail||j.error||("HTTP "+r.status));
  return j;
}
function toast(m){const t=$("toast");t.textContent=m;t.classList.add("show");
  setTimeout(()=>t.classList.remove("show"),2200)}
function esc(s){return String(s??"").replace(/[&<>"]/g,c=>({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;"}[c]))}

async function boot(){
  TOKEN=sessionStorage.getItem("litgate_token")||"";
  let st;try{st=await api("/api/state")}catch(e){return}
  if(!st.initialized){$("gateInit").style.display="block";return}
  if(!st.authed){TOKEN="";sessionStorage.removeItem("litgate_token");
    $("gateLogin").style.display="block";return}
  enter(st);
}
function enter(st){
  $("gateLogin").style.display="none";$("gateInit").style.display="none";
  $("main").style.display="block";$("breaker").style.display="flex";
  renderPower(st.powered);renderSrcs(st.endpoints||[]);renderEP(st);renderKeys(st);
}
async function doSetup(){
  const a=$("pw1").value,b=$("pw2").value;
  if(a.length<8){$("initErr").textContent="密码至少 8 位。";return}
  if(a!==b){$("initErr").textContent="两次输入不一致。";return}
  try{const r=await api("/api/setup",{method:"POST",body:JSON.stringify({password:a})});
    TOKEN=r.token;sessionStorage.setItem("litgate_token",TOKEN);
    boot();}catch(e){$("initErr").textContent=e.message}
}
async function doLogin(){
  try{const r=await api("/api/login",{method:"POST",body:JSON.stringify({password:$("pw").value})});
    TOKEN=r.token;sessionStorage.setItem("litgate_token",TOKEN);$("loginErr").textContent="";
    boot();}catch(e){$("loginErr").textContent=e.message}
}
async function doLogout(){
  try{await api("/api/logout",{method:"POST"})}catch(e){}
  TOKEN="";sessionStorage.removeItem("litgate_token");location.reload();
}
async function doChpw(){
  const a=$("npw1").value,b=$("npw2").value;
  if(a.length<8){$("chpwErr").textContent="新密码至少 8 位。";return}
  if(a!==b){$("chpwErr").textContent="两次输入不一致。";return}
  try{await api("/api/password",{method:"POST",body:JSON.stringify({old:$("opw").value,new:a})});
    $("chpwErr").textContent="";toast("密码已更新");$("opw").value=$("npw1").value=$("npw2").value="";}
  catch(e){$("chpwErr").textContent=e.message}
}
function showTab(t){
  ["Q","M","A"].forEach(x=>{$("pane"+x).style.display=(x.toLowerCase()===t)?"block":"none";
    $("tab"+x).classList.toggle("on",x.toLowerCase()===t)});
}
/* ---- 总闸 ---- */
function renderPower(on){
  document.body.classList.toggle("power-off",!on);
  $("breaker").classList.toggle("off",!on);
  $("swBtn").classList.toggle("off",!on);
  $("swState").textContent=on?"已上电":"已断电";
  $("swSub").textContent=on?"转发 API 正常供电":"转发已切断";
}
$("swBtn").onclick=async()=>{
  const on=document.body.classList.contains("power-off");  // 当前断电→上电；当前上电→断电
  try{const r=await api("/api/power",{method:"POST",body:JSON.stringify({on})});
    renderPower(r.powered);toast(r.powered?"总闸已上电，转发恢复":"总闸已断电，/v1 拒绝服务");}
  catch(e){toast(e.message)}
};
/* ---- 查询 ---- */
function renderSrcs(eps){
  $("srcChecks").innerHTML=eps.filter(e=>e.enabled).map(e=>
    `<label><input type="checkbox" value="${esc(e.adapter)}" checked> ${esc(e.name)}</label>`).join("")
    ||'<span class="hint">没有已启用的数据源，请到「管理」开启。</span>';
}
function yearRange(){
  const v=$("qYear").value.trim();if(!v)return [null,null];
  const m=v.match(/^(\d{4})(?:\s*[-–]\s*(\d{4}))?$/);
  if(!m)throw new Error("年份格式须为2024或2020-2026");
  return [+m[1],+(m[2]||m[1])];
}
let LAST_SEARCH=null;
function renderSearch(r){
  const escUrl=u=>/^https?:\/\//i.test(u||"")?esc(u):"";
  const card=list=>`<div class="card"><div class="tblwrap"><table><tr><th>文献</th><th>年份</th><th>期刊 / 会议</th><th>作者</th><th>引用量</th><th>来源 / 全文</th></tr>${list.map(x=>{
    const url=x.doi?"https://doi.org/"+x.doi:x.url;
    const title=escUrl(url)?`<a href="${escUrl(url)}" target="_blank" rel="noopener noreferrer">${esc(x.title)}</a>`:esc(x.title);
    const cs=x.citations_by_source||{[x.source]:x.cited};
    const counts=Object.entries(cs).map(([s,n])=>`${s}: ${n==null?"未知":n}`).join("；");
    return `<tr><td class="t">${title}${x.abstract?`<details><summary class="hint">摘要</summary>${esc(x.abstract)}</details>`:""}</td><td>${esc(x.year||"未知")}</td><td>${esc(x.venue||"")}</td><td>${esc(x.authors||"")}</td><td title="${esc(counts)}">${x.cited==null?"未知":esc(x.cited)}${x.citation_source?`<small class="hint"> ${esc(x.citation_source)}</small>`:""}</td><td>${esc((x.sources||[x.source]).join(" · "))}${escUrl(x.pdf_url)?`<br><a href="${escUrl(x.pdf_url)}" target="_blank" rel="noopener noreferrer">公开全文</a>`:x.is_oa===true?"<br>公开全文":""}</td></tr>`}).join("")}</table></div></div>`;
  const c=r.counts;let html=`<p class="hint">取回 ${c.fetched} · 去重后 ${c.unique} · 筛选后 ${c.returned}；${esc(r.scope)}</p>`;
  html+=`<p class="hint">${esc(r.ranking)} ${esc(r.citation_policy)}</p>`;
  html+=(r.sources||[]).map(s=>`<p class="hint">${esc(s.source)}：${s.ok?esc(s.note||""):"失败 / 跳过："+esc(s.error||"")}</p>`).join("");
  if($("qGrouped").checked){
    html+=(r.sources||[]).filter(s=>s.ok).map(s=>`<h3>${esc(s.source)}</h3>`+card(r.results.filter(x=>(x.sources||[x.source]).includes(s.source)))).join("");
  }else html+=card(r.results);
  $("results").innerHTML=html+(r.results.length?"":"<p class='hint'>没有满足条件的结果；可扩大每源取回量或放宽筛选。</p>");
}
$("qGrouped").onchange=()=>{if(LAST_SEARCH)renderSearch(LAST_SEARCH)};
async function doQuery(){
  const sources=[...document.querySelectorAll("#srcChecks input:checked")].map(i=>i.value);
  if(!$("q").value.trim())return;
  try{
    const [yf,yt]=yearRange();
    if(!sources.length)throw new Error("请至少选择一个数据源");
    $("results").textContent="多源查询中…";
    const r=await api("/api/query",{method:"POST",body:JSON.stringify({q:$("q").value,sources,limit:+$("lim").value,
      field:$("qField").value,sort:$("qSort").value,year_from:yf,year_to:yt,
      cited_min:$("qCmin").value===""?null:+$("qCmin").value,cited_max:$("qCmax").value===""?null:+$("qCmax").value,
      venue:$("qVenue").value,author:$("qAuthor").value,exclude:$("qExclude").value,oa:$("qOA").value,dedupe:$("qDedupe").checked})});
    LAST_SEARCH=r;renderPower(r.powered);renderSearch(r);
  }catch(e){$("results").textContent=e.message}
}
/* ---- 连通性检测 ---- */
async function ncEndpoint(){
  const ep=$("ncEp").value;$("ncOut").textContent=`正在实测 ${ep} 上游接口…`;
  try{const r=await api(`/api/netcheck?endpoint=${encodeURIComponent(ep)}`);
    $("ncOut").textContent=r.ok
      ?`✓ ${r.endpoint} 上游可达，往返 ${r.latency_ms} ms\n  样例返回：${r.sample}`
      :`✗ ${r.endpoint} 上游异常（${r.latency_ms} ms）：${r.error}`;}
  catch(e){$("ncOut").textContent="✗ "+e.message}
}
async function ncTarget(){
  const t=$("ncTarget").value.trim(),p=$("ncPort").value.trim();
  if(!t){$("ncOut").textContent="请输入主机名或网段。";return}
  $("ncOut").textContent=`正在探测 ${t}…`;
  try{const r=await api(`/api/netcheck?target=${encodeURIComponent(t)}${p?"&port="+p:""}`);
    if(r.mode==="host")
      $("ncOut").textContent=r.ok
        ?`✓ ${r.target}（${r.ip}）:${r.port} 可连通，延迟 ${r.latency_ms} ms`
        :`✗ ${r.target}:${r.port} 无法建立 TCP 连接${r.error?"（"+r.error+"）":""}`;
    else if(r.mode==="cidr"){
      const list=r.reachable.map(h=>`  ${h.ip}  ${h.ms} ms`).join("\n");
      $("ncOut").textContent=`网段 ${r.cidr} 端口 ${r.port}：扫描 ${r.scanned} 个地址，可达 ${r.reachable.length} 个\n`+(list||"  （无存活主机）");}}
  catch(e){$("ncOut").textContent="✗ "+e.message}
}
/* ---- 管理 ---- */
let EPS={};
function renderEP(st){
  $("ncEp").innerHTML=st.endpoints.map(e=>
    `<option value="${esc(e.adapter)}">${esc(e.name)}（${esc(e.adapter)}）</option>`).join("");
  (st.endpoints||[]).forEach(e=>EPS[e.id]={name:e.name,adapter:e.adapter,cfg:e.config||{},secrets:e.configured_secrets||[],info:e.credential_info||{}});
  const rows=(st.endpoints||[]).map(e=>`<tr>
      <td><b>${esc(e.name)}</b><br><span class="mono hint">${esc(e.adapter)}</span></td>
      <td><label class="pill ${e.enabled?"on":""}" style="cursor:pointer">
        <input type="checkbox" ${e.enabled?"checked":""} onchange="toggleEP(${e.id},this.checked)" style="vertical-align:-2px"> ${e.enabled?"启用":"停用"}</label></td>
      <td class="hint">${esc(e.note||"")}</td>
      <td style="white-space:nowrap">
        <button class="ghost" onclick="openCfg(${e.id})">配置</button>
        <button class="ghost danger" onclick="delEP(${e.id})">删除</button></td></tr>`).join("");
  $("epTable").innerHTML=`<tr><th>端点</th><th>状态</th><th>备注</th><th></th></tr>`+rows;
}
/* ---- 端点配置弹窗 ---- */
/* 字段声明：how=发送方式，ex=公开填写示例，secret=不回传已存值 */
const EP_FIELDS={
  crossref:[
    {k:"email",label:"邮箱（mailto，可选）",ph:"you@university.edu",secret:false,
     how:"作为 ?mailto= 查询参数发送",
     hint:"进入 Crossref polite 池：限流更宽松、结果更稳，官方推荐高频用户填写",
     ex:"zhang.san@university.edu"}],
  openalex:[
    {k:"api_key",label:"API key（可选）",ph:"粘贴 OpenAlex key",secret:true,
     how:"以 Authorization: Bearer 请求头发送",
     hint:"账户额度和使用情况以官方账户页为准；未配置key也可进行受限查询",
     ex:"从 OpenAlex 的 Settings → API 复制，不按长度判断有效性"},
    {k:"mailto",label:"邮箱（mailto，可选）",ph:"you@university.edu",secret:false,
     how:"作为 ?mailto= 查询参数发送",
     hint:"可选联系邮箱；账户额度以官方认证说明和账户页为准",
     ex:"zhang.san@university.edu"}],
  semanticscholar:[
    {k:"api_key",label:"API key（可选）",ph:"粘贴 Semantic Scholar key",secret:true,
     how:"以 x-api-key 请求头发送",
     hint:"程序按至少1.1秒间隔发送；申请到key后的初始额度仍以官方批准信息为准",
     ex:"使用官方邮件发放的密钥；申请入口见上方链接"}],
  scopus:[
    {k:"api_key",label:"API key（必填）",ph:"粘贴 dev.elsevier.com 的 key",secret:true,
     how:"以 X-ELS-APIKey 请求头发送",
     hint:"dev.elsevier.com 免费申请；通常需在机构网络 / VPN 环境下调用",
     ex:"在上方 Elsevier 管理入口登录后复制自己的 API key"},
    {k:"inst_token",label:"InstToken（机构令牌，可选）",ph:"机构订阅令牌",secret:true,
     how:"以 X-ELS-Insttoken 请求头发送",
     hint:"个人 key 权限不足（如需完整摘要视图）时由机构签发，与 api_key 配合使用",
     ex:"向图书馆 / 机构管理员索取"}],
  arxiv:[],
  dblp:[
    {k:"cookie",label:"浏览器 Cookie（可选，Anubis 验证会话）",ph:"浏览器 F12 → 网络 → 任一 dblp 请求 → 复制 Cookie 请求头整段值",secret:true,
     how:"以 Cookie 请求头随 API 请求发送",
     hint:"DBLP可能返回人机验证页面；Cookie可能与浏览器绑定，不保证API可用。优先在官方网页完成检索",
     ex:"clear_site_data=…; deban_user=…（整段复制，不要只取其中一个字段）"}]
};
const EP_URL={
  crossref:"https://api.crossref.org/works",
  openalex:"https://api.openalex.org/works",
  semanticscholar:"https://api.semanticscholar.org/graph/v1/paper/search",
  scopus:"https://api.elsevier.com/content/search/scopus",
  arxiv:"https://export.arxiv.org/api/query",
  dblp:"https://dblp.org/search/publ/api"
};
let CFG_ID=null;let CFG_CLEAR_SECRETS=false;
function openCfg(id){
  const e=EPS[id];if(!e)return;CFG_ID=id;CFG_CLEAR_SECRETS=false;
  $("cfgTitle").textContent="配置："+e.name;
  $("cfgAdp").textContent="适配器 "+e.adapter;
  $("cfgHist").innerHTML=(e.info.links||[]).map(l=>`<a href="${esc(l.url)}" target="_blank" rel="noopener noreferrer">${esc(l.label)}</a>`).join(" · ")+`<p class="hint">核验：2026-10-08。${esc(e.info.verification||"")} ${esc(e.info.note||"")}</p>`;
  const fs=EP_FIELDS[e.adapter]||[];
  $("cfgFields").innerHTML=fs.length?fs.map(f=>
    `<label class="f" style="margin-top:12px">${f.label}</label>
     <input type="${f.secret?"password":"text"}" id="cf_${f.k}" placeholder="${esc(f.secret&&e.secrets.includes(f.k)?"已设置；留空保留原值":f.ph)}" value="${esc(e.cfg[f.k]||"")}" oninput="syncCfgJson();cfgPreview()" autocomplete="off" spellcheck="false">
     <p class="hint" style="margin:2px 0 0">发送方式：${esc(f.how)}${f.ex?"；例："+esc(f.ex):""}</p>
     ${f.hint?`<p class="hint" style="margin:2px 0 0;opacity:.75">${esc(f.hint)}</p>`:""}`).join("")
    :'<p class="hint" style="margin-top:8px">此端点无需任何密钥，开箱即用；请求示例如下。</p>';
  $("cfgJson").value=JSON.stringify(e.cfg||{},null,2);
  cfgPreview();
  $("cfgBox").style.display="flex";
  const first=$("cfgFields input");if(first)first.focus();
}
function cfgVal(k){
  const el=$("cf_"+k);if(el)return el.value.trim();
  const e=EPS[CFG_ID];return (e&&e.cfg[k])||"";
}
function maskVal(v){
  v=(v||"").trim();if(!v)return "";
  return v.length>10?v.slice(0,4)+"…"+v.slice(-4):"••••";
}
function cfgPreview(){
  const e=EPS[CFG_ID];if(!e)return;
  const a=e.adapter,q="crack segmentation mamba";
  let url="",hdr="";
  if(a==="crossref"){
    const p=new URLSearchParams({query:q,rows:"10",select:"DOI,title,container-title,issued"});
    if(cfgVal("email"))p.set("mailto",cfgVal("email"));
    url=EP_URL[a]+"?"+p;
  }else if(a==="openalex"){
    const p=new URLSearchParams({search:q,"per_page":"10"});
    if(cfgVal("api_key")||e.secrets.includes("api_key"))hdr="Authorization: Bearer [已设置]";
    if(cfgVal("mailto"))p.set("mailto",cfgVal("mailto"));
    url=EP_URL[a]+"?"+p;
  }else if(a==="semanticscholar"){
    url=EP_URL[a]+"?"+new URLSearchParams({query:q,limit:"10",fields:"title,year,venue,authors,externalIds"});
    if(cfgVal("api_key")||e.secrets.includes("api_key"))hdr="x-api-key: [已设置]";
  }else if(a==="scopus"){
    const p=new URLSearchParams({query:q,count:"10"});
    if(cfgVal("api_key")||e.secrets.includes("api_key"))hdr="X-ELS-APIKey: [已设置]";
    url=EP_URL[a]+"?"+p;
    if(cfgVal("inst_token")||e.secrets.includes("inst_token"))hdr+="\nX-ELS-Insttoken: [已设置]";
  }else if(a==="arxiv"){
    url=EP_URL[a]+"?"+new URLSearchParams({search_query:q,max_results:"10"});
  }else if(a==="dblp"){
    url=EP_URL[a]+"?"+new URLSearchParams({q:q,format:"json",h:"10"});
    if(cfgVal("cookie")||e.secrets.includes("cookie"))hdr="Cookie: [已设置]";
  }
  $("cfgPreview").textContent="GET "+url+(hdr?"\n"+hdr:"");
}
function syncCfgJson(){
  const e=EPS[CFG_ID];const o=Object.assign({},e.cfg);
  (EP_FIELDS[e.adapter]||[]).forEach(f=>{
    const el=$("cf_"+f.k);if(!el)return;
    const v=el.value.trim();if(v)o[f.k]=v;else delete o[f.k]});
  $("cfgJson").value=JSON.stringify(o,null,2);
}
function jsonToFields(){
  const e=EPS[CFG_ID];if(!e)return;
  let o;try{o=JSON.parse($("cfgJson").value)}catch(err){return}
  (EP_FIELDS[e.adapter]||[]).forEach(f=>{
    const el=$("cf_"+f.k);if(el)el.value=o[f.k]||""});
  cfgPreview();
}
function saveCfg(){
  let o;try{o=JSON.parse($("cfgJson").value)}catch(e){toast("JSON 格式错误");return}
  const e=EPS[CFG_ID];if(!e)return;

  api(`/api/endpoints/${CFG_ID}`,{method:"PATCH",body:JSON.stringify({config:o,clear_secrets:CFG_CLEAR_SECRETS})})
    .then(()=>{$("cfgBox").style.display="none";toast("配置已保存");refresh()})
    .catch(err=>toast(err.message));
}
function clearCfgKeys(){
  const e=EPS[CFG_ID];const o=Object.assign({},e.cfg);CFG_CLEAR_SECRETS=true;
  (EP_FIELDS[e.adapter]||[]).forEach(f=>{
    if(f.secret){delete o[f.k];const el=$("cf_"+f.k);if(el)el.value=""}});
  $("cfgJson").value=JSON.stringify(o,null,2);
  cfgPreview();
}
async function toggleEP(id,on){try{await api(`/api/endpoints/${id}`,{method:"PATCH",body:JSON.stringify({enabled:on})});refresh()}catch(e){toast(e.message)}}
async function delEP(id){if(!confirm("删除这个端点？"))return;
  try{await api(`/api/endpoints/${id}`,{method:"DELETE"});refresh()}catch(e){toast(e.message)}}
async function addEndpoint(){
  const name=$("neName").value.trim(),adapter=$("neAdapter").value;
  if(!name){toast("请填写名称");return}
  try{await api("/api/endpoints",{method:"POST",body:JSON.stringify({name,adapter})});
    $("neName").value="";refresh()}catch(e){toast(e.message)}
}
function renderKeys(st){
  const rows=(st.keys||[]).map(k=>`<tr>
    <td><b>${esc(k.name)}</b><br><span class="mono hint">${esc(k.prefix)}…</span></td>
    <td><label class="pill ${k.enabled?"on":""}" style="cursor:pointer">
      <input type="checkbox" ${k.enabled?"checked":""} onchange="toggleKey(${k.id},this.checked)" style="vertical-align:-2px"> ${k.enabled?"启用":"停用"}</label></td>
    <td class="mono">${k.rate_limit}/${k.window_seconds}s</td>
    <td class="hint">${k.allowed.includes("*")?"全部":esc(k.allowed.join(", "))}</td>
    <td class="hint">${esc(k.last_used||"未使用")}</td>
    <td style="white-space:nowrap"><button class="ghost danger" onclick="delKey(${k.id})">删除</button></td></tr>`).join("");
  $("keyTable").innerHTML=`<tr><th>密钥</th><th>状态</th><th>限频</th><th>允许数据源</th><th>最近使用</th><th></th></tr>`+rows;
}
async function toggleKey(id,on){try{await api(`/api/keys/${id}`,{method:"PATCH",body:JSON.stringify({enabled:on})});refresh()}catch(e){toast(e.message)}}
async function delKey(id){if(!confirm("删除这个密钥？使用它的调用将立即失效。"))return;
  try{await api(`/api/keys/${id}`,{method:"DELETE"});refresh()}catch(e){toast(e.message)}}
async function addKey(){
  const name=$("nkName").value.trim();
  if(!name){toast("请填写名称");return}
  const allowed=$("nkAllowed").value.trim()==="*"||!$("nkAllowed").value.trim()
    ?["*"]:$("nkAllowed").value.split(",").map(s=>s.trim()).filter(Boolean);
  try{const r=await api("/api/keys",{method:"POST",body:JSON.stringify({
      name,rate_limit:+$("nkRate").value||30,window_seconds:+$("nkWin").value||60,allowed})});
    $("nkName").value="";$("onceKey").textContent=r.api_key;$("onceBox").style.display="flex";refresh();}
  catch(e){toast(e.message)}
}
function copyOnce(){navigator.clipboard.writeText($("onceKey").textContent).then(()=>toast("已复制"))}
async function refresh(){try{enter(await api("/api/state"))}catch(e){}}
boot();
</script>
</body>
</html>"""

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(INDEX_HTML)

@app.get("/healthz")
async def healthz():
    return {"ok": True, "powered": cfg_get("powered", "1") == "1",
            "installation_id": cfg_get("installation_id")}

# ----------------------------------------------------------------------------
# 入口
# ----------------------------------------------------------------------------
if __name__ == "__main__":
    ap = argparse.ArgumentParser(description="LitGate 文献网关")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=8791)
    ap.add_argument("--db", default=DB_PATH)
    ap.add_argument("--no-browser", action="store_true", help="启动后不自动打开浏览器")
    args = ap.parse_args()
    DB_PATH = str(Path(args.db).resolve())
    init_db()
    url = f"http://127.0.0.1:{args.port}"
    print(f"* LitGate  http://{args.host}:{args.port}   数据库: {DB_PATH}")
    print("* 默认仅本机监听；对外开放请自行评估风险（--host 0.0.0.0）")
    if not args.no_browser:
        threading.Timer(1.5, lambda: webbrowser.open(url)).start()
        print(f"* 将自动打开浏览器：{url}（若未弹出请手动访问；--no-browser 可关闭此行为）")
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
