> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247485108&idx=1&sn=5e17051f4252967b4072d091e4d81ddf

#  远程命令执行、文件上传、SQL 注入……Jeecg 一站式漏洞神器揭秘  
原创 跟着斯叔唠安全  跟着斯叔唠安全   2025-07-14 23:00  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
      
Jeecg综合漏洞利用工具集成了多模块漏洞利用，包括一键漏洞检测，单独选择模块检测,cmdshell模块，文件上传模块，批量检测模块等 v3.0版本内置的标准库外，在检测模块加入了okhttp的三方库，支持https网站检测，以及优化了基于jeecg queryUser漏洞的接口测试  

```
https://github.com/MInggongK/jeecg-
```

  
  
2  
  
Action  
  
      
默认模块可一键扫描所有漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UY30FvHgeicekwybJsCaWu3lxOHVBaejOnGqJWmyNyOhV1QsdAibJyv9sGRTT92In7sSk7lM184a8Zw/640?wx_fmt=png&from=appmsg "")  
  
选择模块可单独选择你要检测的漏洞  
  
cmdshel模块  
  
如存在jeecg-boot queryFieldBySql远程命令执行漏洞  
  
选择cmd模块的jeecg-boot queryFieldBySql远程命令执行漏洞  
  
输入你要执行的命令即可  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UY30FvHgeicekwybJsCaWu3l5xuhZcEQMBwxQ0hpoUXtt3iczVSe9yib6RJiac7ia4lTcoORiavkLCf4XIA/640?wx_fmt=png&from=appmsg "")  
  
文件上传模块：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UY30FvHgeicekwybJsCaWu3luePl4bBJIIuLkCRqWy9Ud6XA4XPOMqcw4ibgCEedqJ9cAhhD6CzuPCA/640?wx_fmt=png&from=appmsg "")  
  
如存在jeecg-boot jmreport任意文件上传漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UY30FvHgeicekwybJsCaWu3lMazeiaTFahAXV7LAZSh3dKkxuibNN5RRUYP2nODJmCM5PgWI5OD1kibXQ/640?wx_fmt=png&from=appmsg "")  
  
批量检测模块：  
  
下载jeecgExploitss jar程序，本地新建文本urls.txt  
  
选择你要检测的模块，点击检测，即可开始批量检测  
  
批量检测，默认只输出存在漏洞的网站  
  
后续根据版本优化再添加其他的批量检测模块  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UY30FvHgeicekwybJsCaWu3lARLewg5djMjA61s5fH3Hg4VicFnjM30Mb7R5OT0ZicJGLFQPCCXvIlDg/640?wx_fmt=png&from=appmsg "")  
  
  
  
3  
  
End  
  
🚀 **新圈子上线 | 高质量安全内容持续更新中！**  
  
我最近在纷传上建立了一个全新的安全技术圈子，主要聚焦于 **WEB安全、APP安全、代码审计、漏洞分享**  
 等核心方向。目前圈子刚刚建立，内容还不算多，但会**持续高频更新**  
，只分享真正有价值、有深度的干货文章。  
  
📚 圈子中包含：  
- 高质量原创或精选的安全技术文章  
  
- 公众号历史付费内容免费查看（如：小程序RPC、APP抓包解决方案）  
  
- 一些只在圈子内分享的独家思路和实战经验  
  
- 不定期分享0/1day  
  
文章中涉及的完整POC及代码审计报告已上传至纷传圈子中，需要的师傅可以自取哈  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
