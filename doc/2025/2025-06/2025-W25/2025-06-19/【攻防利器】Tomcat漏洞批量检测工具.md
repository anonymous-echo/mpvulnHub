> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247484866&idx=1&sn=65eb8293ccb79f02d72c47f620a51d97

#  【攻防利器】Tomcat漏洞批量检测工具  
 跟着斯叔唠安全   2025-06-19 23:04  
  
免责声明  
：  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
  
1  
  
Start  
  
项目地址  

```
https://github.com/lizhianyuguangming/TomcatScanPro
```

  
  
该项目是一款针对 Tomcat 服务的漏洞检测工具，支持利用 CVE-2017-12615 、 CNVD-2020-10487 漏洞、弱口令检测和直接后台部署war包功能，帮助用户高效获取服务器敏感信息。工具支持多目标并发检测，并通过动态线程池提升资源利用率和检测效率。  
  
2  
  
Action  
  
使用方法也很简单：  
1. 首先准备包含URL、用户名和密码的文本文件，分别命名为：
```
urls.txt
```

  
、
```
user.txt
```

  
 和 
```
passwd.txt
```

  
。  
  
1. 
```
urls.txt
```

  
 中的格式为：
```
https://127.0.0.1/
```

  
 或 
```
https://127.0.0.1/manager/html
```

  
，脚本会自动判断路径进行检测。  
  
1. 在 
```
config.yaml
```

  
 文件中配置上述文件路径及相关参数。  
  
1. 运行脚本后，成功利用漏洞的信息将被记录到 
```
success.txt
```

  
 文件中。  
  

```
python TomcatScanPro.py
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UbwLgAVFlIibicg3ibWA1SU5UnJHLjRls9WhmiaZz6g9w1HONqDiacQoK0oMVpBdT6RZqYHdlqhhM9dOwg/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaQw8cfe5zo87XFXicicayuia9gvdmBnX6lOnSygn4NFJlzqeyxyes0uIYicDwGwh3rbAYicdwYFhK3Ang/640?wx_fmt=png&from=appmsg "")  
  
  
  
  
