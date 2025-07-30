> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324439&idx=2&sn=a0d16ac6b452dc408664fce07a3204cd

#  高危Lucee漏洞通过计划任务滥用实现认证RCE，Metasploit模块已公开  
 FreeBuf   2025-07-04 11:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ica9YjnMjbyPguILa0zKicqhA6VAFf1szrOokO8SDPk9SLiah0AWqng9jk2yK0D6scFhgYMVE2TmfYQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
高性能开源CFML（ColdFusion Markup Language）应用服务器Lucee近日曝出严重安全漏洞。该漏洞编号为CVE-2025-34074，CVSS评分高达9.4，允许已认证管理员通过滥用Lucee计划任务功能执行任意远程代码。  
  
  
**Part01**  
## 漏洞技术细节  
##   
  
Lucee凭借对Java集成、HTTP、ORM和动态脚本的支持，被开发者广泛用于构建可扩展的高速应用程序。但这种灵活性若缺乏严格控制，也会带来严重安全隐患。  
  
  
漏洞存在于Lucee管理界面中，具体涉及计划任务处理机制。拥有/lucee/admin/web.cfm访问权限的认证用户可配置任务，从攻击者控制的服务器获取远程.cfm文件（CFML脚本）。Lucee会将该文件写入其webroot目录，并以Lucee服务器进程的完整权限自动执行。  
  
  
CVE描述明确指出："由于Lucee未对计划任务获取实施完整性检查、路径限制或执行控制，该功能可被滥用以实现任意代码执行。"  
  
  
**Part02**  
### 影响范围与攻击场景  
  
  
该漏洞影响所有支持计划任务功能的Lucee版本：  
- Lucee 5.x  
  
- Lucee 6.x  
  
- 所有存在计划任务功能的早期版本  
  
  
攻击者一旦通过暴力破解、钓鱼攻击、内部人员泄露或先前泄露的凭据获取管理员权限，即可轻松部署恶意负载控制整个服务器。更严重的是，该漏洞的Metasploit模块已公开发布，大幅降低了攻击门槛。  
  
  
成功利用此漏洞可导致：  
- 系统完全沦陷  
  
- 后门程序安装  
  
- 凭据窃取或内网横向移动  
  
- 数据泄露或销毁  
  
- 服务器被滥用于横向渗透或C2托管  
  
**Part03**  
### 缓解措施建议  
  
  
鉴于Lucee广泛应用于企业和政府系统，建议组织立即采取以下措施：  
- 通过IP白名单或VPN限制Lucee管理界面访问  
  
- 审计所有现有计划任务，排查可疑远程文件拉取  
  
- 监控webroot目录文件变更，特别是异常.cfm文件  
  
- 审查管理员登录尝试并轮换凭据  
  
- 及时应用Lucee开发团队发布的补丁或热修复  
  
  
如非必要使用场景，管理员可考虑临时禁用计划任务功能。  
  
  
**参考来源：**  
  
Critical Lucee Flaw (CVE-2025-34074, CVSS 9.4): Authenticated RCE Via Scheduled Task Abuse, Metasploit Module Out  
  
https://securityonline.info/critical-lucee-flaw-cve-2025-34074-cvss-9-4-authenticated-rce-via-scheduled-task-abuse-metasploit-module-out/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324107&idx=1&sn=f89429997e0347cfe1580cc8ca6e858b&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
