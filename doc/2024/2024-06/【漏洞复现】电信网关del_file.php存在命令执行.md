#  【漏洞复现】电信网关del_file.php存在命令执行   
mole5  云鸦安全   2024-06-14 09:48  
  
一、产品描述  
  
电信公网网关是一种由电信运营商提供的服务设施，它连接用户和互联网，充当双方之间的连接桥梁。其核心职能包括执行网络地址转换(NAT)、执行安全审查和保护措施、管理网络流量、进行数据的加密与解密，以及对数据进行压缩和解压，确保用户与互联网之间通信的顺畅和安全。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LwcxufKobwdrjtYW614clNER7axJjuufTeAuKCnIhzvSaMhtqhd3PBh5kcFw94jNy8JAlmiaDdRDA/640?wx_fmt=png&from=appmsg "")  
  
二、漏洞复现  
  
fofa  
:  
```
body="a:link{text-decoration:none;color:orange;}"
body="img/login_bg3.png" && body="系统登录"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LwcxufKobwdrjtYW614clNHTicgDSgicskf0t914dF0usoasiaKm9nxDo5biabWzupn9ZFlOrZzzaueQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LwcxufKobwdrjtYW614clNwicicEl0MhyPcYVh5vSlvAu0g6vtzMxHlLpwDYiafZxiaOPZwvDSZ8JibHQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LwcxufKobwdrjtYW614clNx7arR1ASjCiaMsgF3RLgkboqqQK6Wj7qtsGrXyVl7aLxGXA6O7qTEgQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/AbAaoHnsh8LwcxufKobwdrjtYW614clNflNvNleksBIV3Yt9DyMV7lInnz7CHRfopqwc5lZuoibibInZTg9b0E3g/640?wx_fmt=png&from=appmsg "")  
  
  
关注微信公众号回复0614获取POC  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/AbAaoHnsh8LwcxufKobwdrjtYW614clN9YnHnRHGFbraFWW0cxiafW1uWfKBPmO68J1fkRJbxDkgEKar306icM3w/640?wx_fmt=other&from=appmsg "")  
  
> 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试。读者在使用本文提供的信息时，应自行判断其适用性，并承担由此产生的一切风险和责任。本文作者对于读者基于本文内容所做出的任何行为或决定不承担任何责任。在任何情况下，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
