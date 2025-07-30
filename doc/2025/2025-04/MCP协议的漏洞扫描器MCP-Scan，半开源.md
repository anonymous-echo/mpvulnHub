#  MCP协议的漏洞扫描器MCP-Scan，半开源   
原创 孙志敏  AI与安全   2025-04-20 03:57  
  
前边我们介绍了MCP的工具投毒攻击(TPA)，恶意MCP服务器可以对客户端发动攻击，那么，针对MCP服务器的扫描就显得非常必要。  
  
还是Invariant LAB，在发现了TPA后，推出了MCP服务的扫描器，MCP-Scan，并部分开源。简单介绍一下。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fRp5p4jMuDQjdXQXUMBDtPtLS0iaiaxVKblUBecgRUn30Lv2liaIUfnwcVib2D28Om4F0LpOd4oiah0psOJlRBHqewA/640 "")  
  
MCP-Scan能扫什么  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jLdw7EZFJmIjAic1276gZeyjcsS9UMqa3VkvD2WgU11EyJAoVCSagkO3Kmia89jgusIXDficZIgTTb6ia32cibxVKgQ/640 "")  
  
  
MCP-Scan 主动扫描已安装的 MCP 服务器及其工具描述，包括：  
  
Claude desktop,cursor,vscode等的配置文件（也可以指定）  
  
能够识别：  
  
工具中毒攻击(TPA)： MCP 工具描述中嵌入隐藏的恶意指令。  
  
MCP Rug Pulls：在获得用户初步批准后，未经授权更改 MCP 工具描述。  
  
跨域升级：通过恶意描述危害可信工具的暗影攻击。  
  
提示注入攻击：工具描述中包含可由代理执行的恶意指令。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fRp5p4jMuDQjdXQXUMBDtPtLS0iaiaxVKblUBecgRUn30Lv2liaIUfnwcVib2D28Om4F0LpOd4oiah0psOJlRBHqewA/640 "")  
  
如何使用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jLdw7EZFJmIjAic1276gZeyjcsS9UMqa3VkvD2WgU11EyJAoVCSagkO3Kmia89jgusIXDficZIgTTb6ia32cibxVKgQ/640 "")  
  
  
扫描器的使用非常简单，直接  
```
uvx mcp-scan@latest
```  
  
或者从源码启动  
```
uv run pip install -e .
uv run -m src.mcp_scan.cli
```  
  
扫描结果例子如下  
  
![IMG_256](https://mmbiz.qpic.cn/sz_mmbiz_png/rhmRSVBNbicqmHBtyO4oNtEoXqGxshBmTDmaNzdUIh3T7Dj5GxTQWvneOMmuFK1d3iaic5JMc39a4hX7x9Eia5b4FA/640?wx_fmt=png&from=appmsg "")  
  
对配置文件中的每个server里的所有工具做验证。  
  
扫描原理是值得关注的地方，但有点可惜，这块没有开源，实际扫描是把文件上传到https://mcp.invariantlabs.ai/进行扫描的。  
  
工具名称和描述会与 invariantlabs.ai 共享。  
  
好吧，虽然开源不彻底，但至少有个东西可以用了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/fRp5p4jMuDQjdXQXUMBDtPtLS0iaiaxVKblUBecgRUn30Lv2liaIUfnwcVib2D28Om4F0LpOd4oiah0psOJlRBHqewA/640 "")  
  
小结  
  
![](https://mmbiz.qpic.cn/mmbiz_png/jLdw7EZFJmIjAic1276gZeyjcsS9UMqa3VkvD2WgU11EyJAoVCSagkO3Kmia89jgusIXDficZIgTTb6ia32cibxVKgQ/640 "")  
  
  
之前我们已经分析过，MCP最初设计是考虑的本地应用，安全设计很少，但现在被做成了远程的服务，安全风险就不得不考虑。  
  
MCP的相关漏洞已经被验证，说明风险真实存在，这就需要有消减手段。扫描是第一步，也是非常有效的一步。相信会有更多的扫描器及其它防护手段出来，我们将持续跟踪。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/55LhWNqR1eEIvTRaeSGqOic2WdN4owxXx4UzauQgeevfp7WbH82nic0ict9rBIHza7ZkYRxXupK0a8IIPDyicUpjPg/640 "")  
  
END  
  
  
推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg5NTMxMjQ4OA==&mid=2247485810&idx=1&sn=9902c36a58683c730b94712a935741d2&scene=21#wechat_redirect)  
  
[MCP协议漏洞：工具投毒攻击（TPA）](https://mp.weixin.qq.com/s?__biz=Mzg5NTMxMjQ4OA==&mid=2247485810&idx=1&sn=9902c36a58683c730b94712a935741d2&scene=21#wechat_redirect)  
  
  
  
  
