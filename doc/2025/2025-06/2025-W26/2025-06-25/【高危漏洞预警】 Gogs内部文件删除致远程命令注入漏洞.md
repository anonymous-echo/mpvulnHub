> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI3NzMzNzE5Ng==&mid=2247490307&idx=1&sn=bac7469bf34eee680054d677b1c056ec

#  【高危漏洞预警】 Gogs内部文件删除致远程命令注入漏洞  
cexlife  飓风网络安全   2025-06-25 09:33  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02iaHZvNNicsjd4dA2lUPfzfMa7KFMyCEb0XnJybgFeg7libUj4ibuOR1BDAOyX5p7munIZ7IHXH9ejkA/640?wx_fmt=png&from=appmsg "")  
  
漏洞描述:  
  
Gogs是一款开源的自主托管Git服务,CVE-2024-56731中,攻击者可构造请求删除.git目录下的文件覆写相关敏感配置并实现远程命令执行控制服务器,官方已发布0.13.3版本修复该漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu02iaHZvNNicsjd4dA2lUPfzfMKfYHe7rCTEZicBzGYPkaPz45mojG3BX7eQhfJ7v75G7zSfYlbuVCNbg/640?wx_fmt=png&from=appmsg "")  
  
攻击场景:  
  
攻击者可能通过未经授权的方式访问Gogs实例,删除.git目录下的文件并实现远程命令执行  
  
影响产品:  
  
0.13.3及之前版本   
  
修复建议:  
  
补丁名称:  
  
Gоɡѕ信息泄露漏洞的补丁-更新至最新版本0.13.３  
  
文件链接:  
  
https://github.com/gogs/gogs/releases/tag/v0.13.3   
  
  
  
  
  
