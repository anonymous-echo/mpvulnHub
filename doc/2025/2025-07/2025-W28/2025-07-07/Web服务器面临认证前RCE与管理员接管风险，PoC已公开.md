> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324554&idx=3&sn=6d8a6aafd07ad3be4a5c0f54d00e56f5

#  Web服务器面临认证前RCE与管理员接管风险，PoC已公开  
 FreeBuf   2025-07-07 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3iccHKkcenMzvkibHR8MbiaVBkZYeVnSsDLS0ENfu9lHem3cuYaWicre0I4iciaIOYyOHVWvhqEDBhtehGA/640?wx_fmt=png&from=appmsg "")  
  
  
**Part01**  
## 漏洞概况  
  
  
网络安全公司Synacktiv近日发布安全公告，披露了ScriptCase生产环境模块（即"prod console"）中两个可串联利用的漏洞，攻击者无需认证即可实现远程命令执行（RCE），直接威胁Web服务器及敏感数据库凭证安全。  
  
  
![ScriptCase RCE认证前漏洞](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3iccHKkcenMzvkibHR8MbiaVBkZKk2yXE1iazcIPicN1mzG48aMslmAAdsIarQNzCGE5f9GFwMyvDp2kMg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part02**  
## 漏洞技术细节  
  
  
CVE-2025-47227：管理员密码重置漏洞  
  
  
该漏洞允许攻击者利用登录流程中is_page会话变量的设置缺陷，在未认证状态下重置prod console管理员密码。攻击仅需三个HTTP请求：  
  
  
1. 访问login.php初始化会话，构造特定PHPSESSID  
  
2. 获取与该会话关联的验证码图片  
  
3. 发送包含验证码、新密码和任意邮箱的密码重置POST请求  
  
  
研究报告指出："明显可见只需提供邮箱和新密码即可完成重置，无需旧密码"，且"prod console仅存在单一用户"，使得权限提升极为简单。  
  
  
CVE-2025-47228：SSH连接设置中的命令注入漏洞  
  
  
攻击者通过构造HTTP请求，可利用SSH端口转发功能实现系统命令注入。数据库连接测试代码中未过滤用户输入，直接传入shell_exec()函数执行。研究团队演示称："当注入命令; touch ghijkl ;#时，服务器成功创建了ghijkl文件"。  
###   
  
**Part03**  
## 自动化攻击实现  
  
  
虽然密码重置表单设有验证码保护，但Synacktiv证实攻击者可通过Tesseract等OCR工具实现自动化破解："验证码始终由4个大写字母组成...使得漏洞利用中唯一的手动步骤也可自动化"。研究团队已成功提取NKUN、NKUW等验证码。  
  
  
**Part04**  
## 漏洞影响与利用工具  
  
  
Synacktiv发布的Python利用工具可实现：  
  
- 串联实现认证前RCE  
  
- 执行认证后RCE  
  
- 单独进行密码重置  
  
- 检测ScriptCase非标准部署路径  
  
研究人员强调："当两个漏洞串联利用时...密码重置会使当前会话获得认证状态，因此可使用同一cookie执行命令注入"。  
  
  
**Part05**  
## 自动化攻击实现  
  
  
1. 通过反向代理阻断对prod console的访问（特别是login.php、nm_ini_manager2.php和测试向导端点）  
  
2. 重构输入处理逻辑，避免使用shell_exec()  
，采用phpseclib等安全库  
  
强化验证码生成机制，防范自动化破解  
  
3. 由于应用本身不记录活动日志，需通过审查HTTP访问日志进行威胁检测。  
  
  
常见攻击目标包括：  
  
- /prod/lib/php/devel/iface/login.php  
  
- /prod/lib/php/devel/lib/php/secureimage.php  
  
- /prod/lib/php/devel/iface/admin_sys_allconections_test.php  
  
**参考来源：**  
  
ScriptCase Flaws (CVE-2025-47227/47228): Pre-Auth RCE & Admin Takeover Risk for Web Servers, PoC Published  
  
https://securityonline.info/scriptcase-flaws-cve-2025-47227-47228-pre-auth-rce-admin-takeover-risk-for-web-servers-poc-published/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324107&idx=1&sn=f89429997e0347cfe1580cc8ca6e858b&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
