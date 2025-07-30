> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324483&idx=2&sn=7b7840a855c25cff444583b7d7681c6f

#  FreeBuf周报 | Linux高危Sudo漏洞可提权至root并绕过限制；Lucee应用服务器曝高危漏洞  
 FreeBuf   2025-07-05 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJ1UiaObonmWJbuLyoLXdutZ6T0GL6AXwFA0IHVJ9Tl93JicaeTmN55VJBw0JKrJg4sQXdypbdzqibg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**🤯Linux高危Sudo漏洞，可提权至root并绕过限制，PoC已公开**  
  
**👾高危Lucee漏洞通过计划任务滥用实现认证RCE，Metasploit模块已公开**  
  
**🌀Apache组件遭大规模攻击：高危RCE漏洞引发数千次利用尝试**  
  
**💻新型macOS恶意软件利用进程注入与远程通信窃取钥匙串凭证**  
  
**🛜思科修复统一通信管理器静态SSH root凭证高危漏洞**  
  
✨Nessus严重漏洞允许覆盖任意本地系统文件  
### 🔗大语言模型随意猜测网址引发网络安全危机  
### 🥷揭秘ClickFix：朝鲜Kimsuky组织将PowerShell转化为心理欺骗武器  
### ✉️谷歌紧急修复已被利用的Chrome零日漏洞：CVE-2025-6554  
### 🔈MCP Inspector 高危远程代码执行漏洞威胁AI开发者  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5NY7KgXpwrAo5WHiaX2SOibeoicce3vxyZozGALjYSLtYPrDiceL0UV2D3A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
###   
  
  
Linux高危Sudo漏洞，可提权至root并绕过限制，PoC已公开  
###   
  
Sudo曝高危漏洞CVE-2025-32463（CVSS 9.3）和CVE-2025-32462，攻击者可绕过权限限制提权至root。前者利用chroot选项执行任意命令，后者通过主机参数绕过主机限制。影响Sudo 1.8.8至1.9.17版本，需升级至1.9.17p1修复。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vibA19CgCE6jHU3bXVzd60lssmD9Y00qOnicXsJ9eSxIaFXO4UBk21tOw/640?wx_fmt=png&from=appmsg "")  
  
  
高危Lucee漏洞通过计划任务滥用实现认证RCE，Metasploit模块已公开  
###   
###   
  
### Lucee应用服务器曝高危漏洞CVE-2025-34074（CVSS 9.4），允许认证管理员通过计划任务功能执行任意远程代码，影响所有版本。建议立即限制管理界面访问、审计任务、监控文件变更并应用补丁。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ica9YjnMjbyPguILa0zKicqhA6VAFf1szrOokO8SDPk9SLiah0AWqng9jk2yK0D6scFhgYMVE2TmfYQ/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
###   
  
### Apache组件遭大规模攻击：Tomcat与Camel高危RCE漏洞引发数千次利用尝试  
###   
###   
  
###   
  
Apache Tomcat和Camel关键RCE漏洞（CVE-2025-24813等）遭全球攻击激增，3月超12万次利用尝试。攻击者可劫持系统执行任意代码，利用PUT请求缺陷或HTTP头部过滤漏洞。建议禁用Tomcat部分功能、严格校验Camel输入并立即更新补丁。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ica9YjnMjbyPguILa0zKicqhicnOlE1F7YSxlE0icNql7PR73mkCsu5rEQHGLq4KL7FL1Jkwrf2tdSUw/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
新型macOS恶意软件利用进程注入与远程通信窃取钥匙串凭证  
###   
###   
  
###   
  
新型macOS恶意软件NimDoor通过社交工程攻击植入，采用多语言架构、进程注入和信号拦截技术窃取Web3与加密货币数据，其复杂性和隐蔽性标志着macOS威胁显著升级。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vkClW1H2cO35xm6tJSHNVcW3zu38BCexd8PnX9J4hv2F9NwrohCyreg/640?wx_fmt=png&from=appmsg "")  
###   
  
  
思科修复统一通信管理器静态SSH root凭证高危漏洞  
  
思科修复了统一通信管理器中的高危漏洞CVE-2025-20309（CVSS 10分），该漏洞因开发阶段遗留的静态SSH凭证导致攻击者可远程获取root权限。影响15.0.1特定版本，建议升级至修复版本15SU3或应用补丁。目前未发现攻击利用。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAQoue6wgHf164hWwTEak1rKwUNlAC5nXrNDOpfemqtuXFUHZexCYgfUhMkl3AKQOHukIuNrlbJg/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
Nessus严重漏洞允许覆盖任意本地系统文件  
###   
###   
  
###   
  
###   
  
Tenable披露Nessus漏洞扫描器存在3个高危漏洞(CVE-2025-36630等)，影响10.8.5之前版本，其中Windows权限提升漏洞CVSS评分8.4。建议立即升级至10.8.5/10.9.0版本修复漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vPHpq10gHDz8TOPWUb5IGFMfQvHx9Uz1jdJgFdQpoZy5vRAFHcWBSvg/640?wx_fmt=png&from=appmsg "")  
  
  
大语言模型随意猜测网址引发网络安全危机  
###   
  
###   
  
###   
  
###   
  
AI生成品牌网址错误率高达34%，5%指向钓鱼网站，威胁用户安全。攻击者利用AI幻觉抢注域名，GitHub投毒污染训练数据。专家建议验证域名所有权，加强数据审核，防范钓鱼攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vAnpI5Z5icib6HcCQlAgMVztvGnqKddicPkcerbDRC8w16bUe0wdhjpNVg/640?wx_fmt=png&from=appmsg "")  
  
  
揭秘ClickFix：朝鲜Kimsuky组织如何将PowerShell转化为心理欺骗武器  
  
###   
  
###   
  
###   
  
###   
  
中东冲突加剧网络战升级：GPS欺骗、虚假警报、加密货币攻击和IP监控交织，黑客活动爆发式增长，电子战与物理战界限模糊，威胁关键基础设施和民众安全，凸显网络-物理冲突新时代的严峻挑战。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icgUvC6BMWGzibeXeQBrsXKkODXhyI1eQWHvdLcNRZVblNNqkGpyZxeicXK4dBNtLlQFO8dSkhLwlMQ/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
谷歌紧急修复已被利用的Chrome零日漏洞：CVE-2025-6554  
  
###   
  
###   
###   
  
###   
  
###   
  
谷歌紧急修复Chrome高危零日漏洞CVE-2025-6554，该漏洞影响V8引擎，可导致远程代码执行，已被野外利用。补丁已发布，建议用户立即更新。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib2oZzz7fu5ib8DRjTvSTx5XlkqHPQoeJcm78iaAuVzEuOzFto2XCibDXAoDibCKpLVx4V6dpVlI3viaYw/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
MCP Inspector 高危远程代码执行漏洞威胁AI开发者（CVE-2025-49596）  
  
###   
  
###   
###   
  
###   
  
###   
  
Anthropic公司MCP Inspector调试工具存在高危RCE漏洞（CVE-2025-49596，CVSS 9.4），攻击者通过浏览器即可控制开发者电脑。漏洞源于默认配置缺陷，0.14.1版本已修复，新增认证和CSRF防护。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR38MSC47SvZnR0Q8u4CiadMkO4CyfwqRtBiart2SoHVE8cwWQnlPmBicT2Tt3geYibMN0HsPZk0rt1ciaJg/640?wx_fmt=webp&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5Ce9OricKgAogLRlHYat9jaelbVESLOylPBnQQrU63TlHEs2zCbdNrKg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**本周好文推荐指数**  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS59ZQ6EsSUehyHWzxq6tIFG5b5TmautNPF3E0YDL2xav0dFmmibp2oT0w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
###   
  
  
Kerberos 票据攻击：黄金、白银、钻石、蓝宝石票据的攻防全解析  
###   
###   
  
### Kerberos票据攻击（黄金、白银、钻石、蓝宝石票据）利用关键Hash伪造身份，黄金票据伪造TGT，白银票据伪造服务票据，钻石票据自定义PAC权限，蓝宝石票据跨域攻击。防御需轮换krbtgt密码、最小化权限、启用AES加密和PAC验证，监控异常票据使用。  
  
![What is Kerberos? How Does It Work & Kerberos Authentication Explained](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vR73MXfWU5XvnpMooSEU60mr49s8NRW8wEsuPNRY2TVegnrWgEARUAw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Java 内存马：原理、种类与企业级深度查杀与防御实战  
###   
###   
  
### Java内存马利用动态注入技术将恶意逻辑植入运行时内存，绕过传统防护。常见类型包括Filter、Servlet、Spring Controller等，危害严重。企业需结合运行时巡检、内存分析、字节码校验及流量监控等多层防御，构建主动检测与快速响应体系，实现深度查杀。  
  
![The Path Ahead for Java: 7 Key Trends in 2025](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vONgXN58BL3268lqBM7pMpko8f10n6JJgjRf4LoEHiaPib1dJu0NKgPaA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
内存马连接工具：技术特性与攻防分析  
###   
###   
  
###   
  
### 冰蝎、哥斯拉和蚁剑是主流内存马工具，分别以AES加密、多语言支持和自定义编码器为特点，通过动态注入Filter、Servlet等实现隐蔽控制。防御需监控动态加载、加固上传点、部署EDR和定期内存巡检。  
###   
###   
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324107&idx=1&sn=f89429997e0347cfe1580cc8ca6e858b&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
