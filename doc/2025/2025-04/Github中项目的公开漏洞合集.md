#  Github中项目的公开漏洞合集   
进击的hack  进击的HACK   2025-04-21 23:49  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DuibU3GqmxVmRsdItbBVRKegNHicHQvAHDdZsGpLVU7touSU1AU1twHTfRjG3Vu5aUh0RnPPllfVUhs4qdWF5QYQ/640?wx_fmt=png&wxfrom=13 "")  
  
声明：  
文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途给予盈利等目的，否则后果自行承担！  
如有侵权烦请告知，我们会立即删除并致歉。谢谢  
！  
  
文章有疑问的，可以公众号发消息问我，或者留言。我每天都会看的。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9zYJrD2VibHmqgf4y9Bqh9nDynW5fHvgbgkSGAfRboFPuCGjVoC3qMl6wlFucsx3Y3jt4gibQgZ6LxpoozE0Tdow/640?wx_fmt=png&wxfrom=13 "")  
  
  
   
  
> 字数 216，阅读大约需 2 分钟  
  
## 前言  
  
最近在搜CVE的时候，意外发现了GitHub Security Advisories  
。  
  
可能对一些人来说，已经是老东西了。但我还是第一次见到。  
  
觉得挺好用的，就分享出来。  
## GitHub Security Advisories  
  
GitHub Security Advisories 是 GitHub 提供的一项重要功能，用于帮助开发者和项目维护者管理和披露软件项目中的安全漏洞，覆盖的语言包含Java、Go、Python、Rust、Swift、Php等。  
  
相当于是一个Github中项目的公开漏洞合集。  
  
URL地址：https://github.com/advisories  
  
Github advisories的介绍：https://docs.github.com/zh/code-security/security-advisories/working-with-global-security-advisories-from-the-github-advisory-database/about-the-github-advisory-database  
## 使用  
  
比如我们想搜索某个项目的漏洞，就可以在搜索框输入项目的名称。  
  
比如 vitejs/vite  
  
https://github.com/advisories?query=vitejs%2Fvite  
  
![aa9735a393d037dae79cfca55a595938.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgpqc140otYA7PTuvlvn4ibshj23uYsw7YVJQmmsHL3N88TEY72DBAoFsO8GpQQLmR4JerXnBRLfQg/640?from=appmsg "null")  
  
aa9735a393d037dae79cfca55a595938.png  
  
然后其中就可能存在相关的漏洞和补丁信息  
  
![228a28b2c94d1f837724759835dc1d67.png](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgpqc140otYA7PTuvlvn4ibs6mFMgRQ0iaUwMT2f1prGkJEjpLIiaAh3ztiaIyfFOpR3B6XlbTbwBlFYw/640?from=appmsg "null")  
  
228a28b2c94d1f837724759835dc1d67.png  
  
方便我们去验证漏洞，搜索Poc。  
  
   
  
我们搜索ruoyi。  
  
https://github.com/advisories?query=ruoyi  
- • Unreviewed 代表未验证  
  
  
  
   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/a1BOUvqnbrgpqc140otYA7PTuvlvn4ibsicyxCWib2GWrMAk84X44TzPJwCzD52LsKgtfJvRRQiafoVib9r0lfkOKbg/640?wx_fmt=png&from=appmsg "")  
  
看了下具体的漏洞，是同一个师傅刷的登录后的鉴权问题。## 其他类似的  
- • https://github.com/trickest/cve  
  
- • https://github.com/CVEProject/cvelist  
  
- • https://github.com/cisagov/vulnrichment  
  
- • https://github.com/github/advisory-database  
  
  
  
   
  
  
  
  
  
