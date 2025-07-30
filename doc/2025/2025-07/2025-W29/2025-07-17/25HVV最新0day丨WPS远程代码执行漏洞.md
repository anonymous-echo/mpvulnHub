> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2MTg4NTMzNw==&mid=2247484469&idx=1&sn=598ed0fdbc5d4173c2b4f452925cdf3f

#  25HVV最新0day丨WPS远程代码执行漏洞  
原创 喵星不安全  喵星安全研究所   2025-07-17 06:31  
  
接上文：  
> 由于修改字数有限，新增补充  
  
> 喵星不安全，公众号：喵星安全研究所[25HVV紧急通报丨WPS存在RCE漏洞](https://mp.weixin.qq.com/s/Utr7ddNRZuU6O7CLCgI71g)  
  
  
  
漏洞描述  
  
WPS 文档中心和文档中台存在未授权访问接口，导致远程代码执行  
  
漏洞分析  
  
通过未授权拿到AK，解密后修改K8s配置文件，通过未授权访问路由，调用api实现远程代码执行  
  
影响范围  
  
WPS 中台版本 v6.0.2205<=version<v7.1.2405  
  
WPS 中心版本 v7.0.2306b<=version<v7.0.2405b  
  
缓解措施  
  
建议受影响的用户尽快完成版本更新  
  
  
  
必要可联系厂商进行修复  
  
