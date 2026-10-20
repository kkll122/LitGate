"""LitGate stdio MCP client; all credentials are loaded after local installation."""
import os
import asyncio
from pathlib import Path
from typing import Optional
import httpx
from mcp.server.fastmcp import FastMCP
BASE=os.environ.get("LITGATE_URL","http://127.0.0.1:8791").rstrip("/")
mcp=FastMCP("litgate")

def client_key():
    value=os.environ.get("LITGATE_API_KEY","").strip()
    if value:return value
    filename=os.environ.get("LITGATE_API_KEY_FILE","")
    if filename:
        try:return Path(filename).read_text(encoding="utf-8-sig").strip()
        except OSError:return ""
    return ""

async def gateway(path,params=None):
    global BASE
    runtime=os.environ.get('LITGATE_INSTALL_DIR')
    if runtime:
        try:
            from deploy import ensure_running,gateway_url
            state=await asyncio.to_thread(ensure_running,Path(runtime).resolve())
            BASE=gateway_url(state)
        except (OSError,ValueError,RuntimeError) as ex:
            return {'error':f'本机网关启动失败（{type(ex).__name__}）；查看私有目录中的gateway.log。'}
        except Exception as ex:
            return {'error':f'本机网关启动失败（{type(ex).__name__}）；检查安装状态。'}
    key=client_key()
    if not key:return {"error":"先在LitGate管理页生成客户端密钥，再运行register-mcp.ps1或设置LITGATE_API_KEY。"}
    try:
        async with httpx.AsyncClient(timeout=100,follow_redirects=False,trust_env=False) as client:
            response=await client.get(BASE+path,params=params,headers={"X-Api-Key":key})
        data=response.json()
    except (httpx.HTTPError,ValueError) as ex:
        return {"error":f"网关连接或响应异常（{type(ex).__name__}）；检查网关是否运行和LITGATE_URL。"}
    if response.status_code!=200:
        return {"error":str(data.get("error") or f"HTTP {response.status_code}").replace(key,"[已隐藏]"),"sources":data.get("sources",[])}
    return data

@mcp.tool()
async def litgate_search(q:str,source:str="all",limit:int=20,field:str="all",sort:str="relevance",
    year_from:Optional[int]=None,year_to:Optional[int]=None,cited_min:Optional[int]=None,cited_max:Optional[int]=None,
    venue:str="",author:str="",exclude:str="",oa:str="any",dedupe:bool=True)->str:
    """多源文献检索。source=all或逗号分隔源；每源limit为1–50。
    field=all/title/abstract/author；sort=relevance/newest/oldest/cited/cited_asc。
    年份和引用量范围含端点；venue/author包含筛选；exclude逗号分隔；oa=any/yes；dedupe是否去重。
    合并与排序只针对本次取回批次，不代表全库命中数；来源能力和失败分别披露。
    """
    params=dict(q=q,source=source,limit=limit,field=field,sort=sort,year_from=year_from,year_to=year_to,
        cited_min=cited_min,cited_max=cited_max,venue=venue,author=author,exclude=exclude,oa=oa,dedupe=str(dedupe).lower())
    params={k:v for k,v in params.items() if v is not None and v!=""}
    data=await gateway("/v1/search",params)
    if data.get("error"):
        return "检索失败："+data["error"]+"；"+"；".join(s.get("source","")+": "+s.get("error","") for s in data.get("sources",[]))
    c=data.get("counts",{})
    lines=[f"取回{c.get('fetched',0)} · 去重后{c.get('unique',0)} · 筛选后{c.get('returned',0)}",data.get("scope",""),data.get("ranking",""),data.get("citation_policy","")]
    for s in data.get("sources",[]):
        lines.append(s.get("source","")+"："+(s.get("note","") if s.get("ok") else "失败/跳过："+s.get("error","")))
    for i,r in enumerate(data.get("results",[]),1):
        citation="未知" if r.get("cited") is None else str(r["cited"])+"（"+str(r.get("citation_source"))+"）"
        lines.append(f"{i}. {r.get('title','')}\n   {r.get('year') or '未知年份'} | {r.get('venue') or ''} | 引用{citation}\n   {r.get('authors') or ''}\n   DOI: {r.get('doi') or '未提供'} | {r.get('url') or ''}")
        if r.get("pdf_url"):lines.append("   公开全文："+r["pdf_url"])
    lines.append(f'等价调用：curl -H "X-Api-Key: $LITGATE_API_KEY" "{BASE}/v1/search?{str(httpx.QueryParams(params))}"')
    return "\n".join(lines)

@mcp.tool()
async def litgate_quota()->str:
    """查询本机客户端密钥配额，不是上游账户额度。"""
    d=await gateway("/v1/quota")
    return d["error"] if d.get("error") else f"本机配额：剩余{d.get('remaining')}次 / 每{d.get('window_seconds')}秒{d.get('limit')}次。"

@mcp.tool()
async def litgate_usage()->str:
    """返回参数、已核验的密钥申请入口和来源能力。"""
    from search_core import SOURCE_INFO,VERIFIED_ON
    links="\n".join(v["name"]+"："+"；".join(l["label"]+" "+l["url"] for l in v["links"])+"。"+v["verification"] for v in SOURCE_INFO.values())
    return f"""LitGate：{BASE}
source=all或crossref,openalex,semanticscholar,arxiv,dblp,scopus的子集（以客户端密钥权限为准）。
field=all/title/abstract/author；sort=relevance/newest/oldest/cited/cited_asc；每源limit=1–50。
year_from/year_to、cited_min/cited_max含端点；venue/author包含筛选；exclude逗号分隔；oa=any/yes；dedupe布尔。
只对返回批次合并筛选排序；缺失引用量不是零，各源引用量不相加。相关度为来源排名融合。
Google Scholar不是本网关的数据源。实际密钥不出现在工具示例中。
官方入口核验日期：{VERIFIED_ON}
{links}"""

if __name__=="__main__":mcp.run(transport="stdio")
