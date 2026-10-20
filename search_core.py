"""Portable search rules, source capabilities and public credential links."""
import copy
import re
import unicodedata
from urllib.parse import unquote

VERIFIED_ON = "2026-10-08"
SOURCE_INFO = {
    "crossref": {
        "name": "Crossref", "key_required": False,
        "links": [{"label": "无需密钥 · 官方 API 说明", "url": "https://www.crossref.org/documentation/retrieve-metadata/rest-api/"}],
        "verification": "官方文档可访问；mailto 为联系邮箱，非密钥。",
        "fields": ["all", "title", "author"], "citations": True,
        "note": "引用量为 Crossref Cited-by；无摘要定向检索。",
    },
    "openalex": {
        "name": "OpenAlex", "key_required": False,
        "links": [{"label": "申请 / 查询 / 更换 API 密钥", "url": "https://openalex.org/settings/api"},
                  {"label": "官方认证说明", "url": "https://help.openalex.org/api/authentication/"}],
        "verification": "官方文档明确指定该设置入口；账户页需 JavaScript 和登录。",
        "fields": ["all", "title", "abstract", "author"], "citations": True,
        "note": "引用量为 OpenAlex cited_by_count；额度以账户页为准。",
    },
    "semanticscholar": {
        "name": "Semantic Scholar", "key_required": False,
        "links": [{"label": "官方 API 申请入口（Request an API Key）", "url": "https://webflow.semanticscholar.org/product/api"},
                  {"label": "官方 API 文档", "url": "https://api.semanticscholar.org/api-docs/"}],
        "verification": "官方页面包含申请入口，密钥通过邮箱发放；规范域名页面在核验时返回403，使用官方可访问页面。",
        "fields": ["all", "title", "abstract"], "citations": True,
        "note": "引用量为 Semantic Scholar citationCount；排序仅对取回批次生效，作者定向检索不适用。",
    },
    "scopus": {
        "name": "Scopus", "key_required": True,
        "links": [{"label": "申请 / 查询 API 密钥（需 Elsevier 登录）", "url": "https://dev.elsevier.com/apikey/manage"},
                  {"label": "官方 Scopus API 文档", "url": "https://dev.elsevier.com/documentation/SCOPUSSearchAPI.wadl"}],
        "verification": "管理入口跳转至 Elsevier 登录，已核验登录跳转和官方文档；未登录查看个人密钥页。",
        "fields": ["all", "title", "abstract", "author"], "citations": True,
        "note": "引用量为 Scopus citedby-count；部分权限需要机构网络或 InstToken，后者向机构索取。",
    },
    "arxiv": {
        "name": "arXiv", "key_required": False,
        "links": [{"label": "无需密钥 · 官方 API 手册", "url": "https://info.arxiv.org/help/api/user-manual.html"}],
        "verification": "官方 API 手册可访问。",
        "fields": ["all", "title", "abstract", "author"], "citations": False,
        "note": "无引用量；年份取首次提交日期；提供预印本及公开全文链接。",
    },
    "dblp": {
        "name": "DBLP", "key_required": False,
        "links": [{"label": "无需 API 密钥 · 官方检索", "url": "https://dblp.org/search"}],
        "verification": "官方域名已核验；API/说明页可能出现浏览器人机验证，Cookie 不是 API 密钥。",
        "fields": ["all", "title", "author"], "citations": False,
        "note": "无引用量和摘要；标题/作者由取回记录本地筛选；可能触发浏览器验证。",
    },
}

SECRET_FIELDS = {"api_key", "inst_token", "cookie", "password", "secret", "token"}

def public_config(config):
    return {k: v for k, v in config.items() if k.lower() not in SECRET_FIELDS}

def update_config(existing, submitted, clear_secrets=False):
    """Missing secrets keep their old value; explicit empty values delete them."""
    out = dict(submitted)
    if not clear_secrets:
        for k, v in existing.items():
            if k.lower() in SECRET_FIELDS and k not in submitted:
                out[k] = v
    return {k: v for k, v in out.items() if not (k.lower() in SECRET_FIELDS and not v)}

def integer(value, name, minimum, maximum, default=None):
    if value is None or value == "":
        return default
    if isinstance(value, bool) or not re.fullmatch(r"\d+", str(value)):
        raise ValueError(f"{name} 必须是整数")
    result = int(value)
    if not minimum <= result <= maximum:
        raise ValueError(f"{name} 须在 {minimum}–{maximum} 之间")
    return result

def options(body):
    result = {
        "q": str(body.get("q") or "").strip(),
        "field": body.get("field") or "all", "sort": body.get("sort") or "relevance",
        "limit": integer(body.get("limit"), "每源取回量", 1, 50, 20),
        "year_from": integer(body.get("year_from"), "起始年", 1000, 2100),
        "year_to": integer(body.get("year_to"), "结束年", 1000, 2100),
        "cited_min": integer(body.get("cited_min"), "最小引用量", 0, 10**9),
        "cited_max": integer(body.get("cited_max"), "最大引用量", 0, 10**9),
        "venue": str(body.get("venue") or "").strip(),
        "author": str(body.get("author") or "").strip(),
        "exclude": str(body.get("exclude") or "").strip(),
        "oa": body.get("oa") or "any", "dedupe": body.get("dedupe", True),
    }
    if not result["q"] or len(result["q"]) > 1000:
        raise ValueError("检索词须为1–1000字符")
    if result["field"] not in ("all", "title", "abstract", "author"):
        raise ValueError("未知检索范围")
    if result["sort"] not in ("relevance", "newest", "oldest", "cited", "cited_asc"):
        raise ValueError("未知排序")
    if result["oa"] not in ("any", "yes"):
        raise ValueError("公开全文条件须为 any 或 yes")
    for low, high in (("year_from", "year_to"), ("cited_min", "cited_max")):
        if result[low] is not None and result[high] is not None and result[low] > result[high]:
            raise ValueError("范围下限不得大于上限")
    if not isinstance(result["dedupe"], bool):
        raise ValueError("dedupe 须为布尔值")
    if any(len(result[key]) > 500 for key in ("venue", "author", "exclude")):
        raise ValueError("附加筛选条件过长")
    return result

def doi_normalize(value):
    value = unquote(str(value or "")).strip().lower()
    value = re.sub(r"^(?:https?://(?:dx\.)?doi\.org/|doi:\s*)", "", value)
    return value if value.startswith("10.") else ""

def normalized(value):
    return "".join(c for c in unicodedata.normalize("NFKC", str(value or "")).casefold() if c.isalnum())

def number(value):
    try:
        return int(value) if value is not None and str(value).isdigit() else None
    except (ValueError, TypeError):
        return None

def accepted(record, opt):
    year, cited = number(record.get("year")), number(record.get("cited"))
    if (opt["year_from"] is not None or opt["year_to"] is not None) and year is None:
        return False
    if opt["year_from"] is not None and year < opt["year_from"]:
        return False
    if opt["year_to"] is not None and year > opt["year_to"]:
        return False
    # Unknown citation counts are never silently treated as zero.
    if (opt["cited_min"] is not None or opt["cited_max"] is not None) and cited is None:
        return False
    if opt["cited_min"] is not None and cited < opt["cited_min"]:
        return False
    if opt["cited_max"] is not None and cited > opt["cited_max"]:
        return False
    if opt["venue"] and opt["venue"].casefold() not in str(record.get("venue") or "").casefold():
        return False
    if opt["author"] and opt["author"].casefold() not in str(record.get("authors") or "").casefold():
        return False
    if opt["oa"] == "yes" and record.get("is_oa") is not True:
        return False
    hay = " ".join(str(record.get(key) or "") for key in ("title", "abstract", "authors", "venue")).casefold()
    return not any(term.strip().casefold() in hay for term in opt["exclude"].split(",") if term.strip())

def sort_records(records, order):
    if order == "relevance":
        return sorted(records, key=lambda r: (-r.get("rank_score", 0), str(r.get("title", ""))))
    key = "cited" if order.startswith("cited") else "year"
    descending = order in ("cited", "newest")
    return sorted(records, key=lambda r: (number(r.get(key)) is None,
                  (-number(r.get(key)) if descending else number(r.get(key))) if number(r.get(key)) is not None else 0,
                  str(r.get("title", ""))))

def combine(packets, opt):
    """Deduplicate conservatively; citation provenance is retained, never summed."""
    collected=[]
    for packet in packets:
        if not packet.get("ok"):
            continue
        for rank, value in enumerate(packet.get("results") or [], 1):
            item=copy.deepcopy(value)
            item["source"]=packet["source"]
            item["source_id"]=packet["adapter"]
            item["doi"]=doi_normalize(item.get("doi"))
            item["cited"]=number(item.get("cited"))
            item["year"]=number(item.get("year"))
            item["rank_score"]=1 / (60 + rank)
            item["sources"]=[packet["source"]]
            item["citations_by_source"]={packet["source"]: item["cited"]}
            collected.append(item)
    merged=[]
    by_doi={};by_title={}
    for item in collected:
        doi=item["doi"]
        # Title fallback requires same year and first author, not a short heading.
        title=normalized(item.get("title"))
        first=normalized(str(item.get("authors") or "").split(",")[0])
        title_key=(title,item.get("year"),first) if len(title)>=24 and first and item.get("year") else None
        previous=by_doi.get(doi) if doi else None
        if previous is None and title_key:
            matches=by_title.get(title_key,[])
            previous=next((r for r in matches if not doi or not r["doi"] or r["doi"]==doi),None)
        if not opt["dedupe"] or previous is None:
            merged.append(item)
            if doi:by_doi[doi]=item
            if title_key:by_title.setdefault(title_key,[]).append(item)
            continue
        if not previous["doi"] and doi:
            previous["doi"]=doi;by_doi[doi]=previous
        previous["rank_score"]+=item["rank_score"]
        for source in item["sources"]:
            if source not in previous["sources"]:previous["sources"].append(source)
        previous["citations_by_source"].update(item["citations_by_source"])
        # A fixed provider order avoids counting citations from different indexes together.
        for source in ("OpenAlex","Scopus","Semantic Scholar","Crossref"):
            count=previous["citations_by_source"].get(source)
            if count is not None:
                previous["cited"]=count;previous["citation_source"]=source;break
        for key in ("url","venue","authors","abstract","pdf_url","year"):
            if not previous.get(key) and item.get(key):previous[key]=item[key]
        if item.get("is_oa") is True:previous["is_oa"]=True
    for item in merged:
        item.setdefault("citation_source",item["source"] if item["cited"] is not None else None)
    filtered=[item for item in merged if accepted(item,opt)]
    return {
        "results":sort_records(filtered,opt["sort"]),
        "counts":{"fetched":len(collected),"unique":len(merged),"returned":len(filtered),
                  "duplicates_removed":len(collected)-len(merged),"filtered_out":len(merged)-len(filtered)},
        "scope":"仅对每源本次取回的最多50条记录合并、筛选与排序；不是全库命中数。",
        "ranking":"相关度使用来源内排名的倒数排名融合（RRF）；不直接比较来源相关度分数。",
        "citation_policy":"引用量不同来源不可相加；去重记录优先OpenAlex、Scopus、Semantic Scholar、Crossref；保留逐源值。",
    }
