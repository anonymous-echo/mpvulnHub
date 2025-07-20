> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyMzI3MTI5Mg==&mid=2247485443&idx=1&sn=b0fc551b2ab431110e845fb515357e84

#  中科汇联Easysite反序列化漏洞  
原创 Ha1ey  安全白白   2025-07-20 09:25  
  
   
  
**Ha1ey@深蓝攻防实验室**  
  
**本文章仅供学习交流使用，文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途以及盈利等目的，否则后果自行承担！**  
## 前言  
  
帮助大家发现一些小（lao）问题，由于该系统被多个金融、政府行业作为门户官网，这里不公布POC，只提供问题简单分析和安全修复建议。  
## 简单分析  
  
前面的路由一系列就不分析了，jetspeed的有兴趣的同学可以自行研究，直接来到问题入口点
```
com.huilan.easysite.newMedia.action.WxMessageAcceptAction
```

  
的accept方法  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9rpBqMmHOBib0icliclEJATGIQ0anlwogpAHmHA8aA6L8iayqpAMNNMIvZLkQhMzviaJyRc2BMYL22hs4w/640?wx_fmt=png&from=appmsg "")  
  
  
  
获取请求的流赋值给到reqXmlData  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9rpBqMmHOBib0icliclEJATGIQWmlg3ByicZx0Xdib7r2mRwdyc3hx82iarq9YuBnPJBgm0KLV5a2HV4riag/640?wx_fmt=png&from=appmsg "")  
  
  
  
最后来到触发点  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9rpBqMmHOBib0icliclEJATGIQ8DDlbAdD8YAgWx9GFqmzcFF5upwZeib4DAfJKbqJvNnFxJHia8QQBEJA/640?wx_fmt=png&from=appmsg "")  
  
  
  
系统的xstream依赖的版本  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9rpBqMmHOBib0icliclEJATGIQvJbsGtA4ns8I4w5SJOKycHgrttnZXEDISefiauhhWLOH55gZGc55CCA/640?wx_fmt=png&from=appmsg "")  
  
  
  
最后本地poc效果  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9rpBqMmHOBib0icliclEJATGIQ1fzxp9jNic7ZnEfj1TQlFOUJKQr0EZDdZKicLfzAsCKLO2sywS3VjcCA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/f9GYWLMlB9rpBqMmHOBib0icliclEJATGIQx37tOCbzwicBxSzZGozgwAOIXKHWO4hbP9jB4kMzuRaB9A7ZD91nRFQ/640?wx_fmt=png&from=appmsg "")  
  
## 防护建议  
  
升级Xstream依赖的版本  
  
  
WAF加URL规则
```
/eportal/ui?portal.url=/portlet/wx-message-accept!accept.portlet&moduleId=0
```

  
  
  
   
  
  
