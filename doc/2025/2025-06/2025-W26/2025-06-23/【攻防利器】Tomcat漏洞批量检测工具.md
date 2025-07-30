> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzAxMjE3ODU3MQ==&mid=2650611143&idx=4&sn=7272666d2f3b722d3e6e8273a0263842

#  【攻防利器】Tomcat漏洞批量检测工具  
 黑白之道   2025-06-23 01:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
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

  
![图片](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UbwLgAVFlIibicg3ibWA1SU5UnKiaZ17j1dOU7wWBBl3zs0gDeD2fVWiagSrPnHrfOocOjpfvticHwhpyJQ/640?wx_fmt=png&from=appmsg&watermark=1&tp=wxpic&wxfrom=5&wx_lazy=1 "")  
  
  
  
> **文章来源：跟着斯叔唠安全**  
  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
