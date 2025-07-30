#  FreeBuf周报 | 谷歌收集用户数据且无需打开应用；近5万访问管理系统存严重漏洞   
Zicheng  FreeBuf   2025-03-08 18:29  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
各位 Buffer 周末好，以下是本周「FreeBuf周报」，我们总结推荐了本周的热点资讯、一周好文，保证大家不错过本周的每一个重点！  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ic3uh9utNGk4yQjUfl8SUEGUDlJnTe6iboGkyd8Lmic4Lz6ricN9NEv3iay0icOGRDHohIUVo7KiaP1LxHQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**热点资讯**  
  
  
##   
###   
### 1. 最新黑产技术曝光，只需19分钟即可劫持AI大模型  
  
最新研究表明，网络攻击者正在利用泄露的云凭证在几分钟内劫持企业AI系统。近期事件显示，攻击者能够在19分钟内攻破大型语言模型（LLM）的基础设施。  
### 2. 最新研究，谷歌大量收集用户数据，无需打开应用  
  
都柏林三一学院教授D.J.雷斯的这项研究首次记录了，预装谷歌应用如何在未经用户同意且不提供退出选项的情况下进行静默追踪。  
### 3. 塔塔科技遭勒索攻击，1.4TB数据被泄露  
  
塔塔科技（Tata Technologies）近期遭受了勒索软件组织“猎手国际”（Hunters International）的攻击。该组织声称已从这家工程公司窃取了高达 1.4TB 的数据，涉及超过 73 万份文件，并威胁若不支付赎金将公开这些数据。  
### 4. 麒麟勒索软件团伙宣称入侵乌克兰外交部  
  
麒麟（Qilin）勒索软件团伙近日宣称成功入侵乌克兰外交部，并窃取了敏感数据。这一事件标志着针对乌克兰的重大网络安全攻击。  
### 5. WordPress曝9.8分高危漏洞，可执行远程代码攻击  
  
GiveWP Donation插件中存在一个严重的安全漏洞（编号为CVE-2025-0912），该漏洞已导致超过10万家WordPress网站面临未经身份验证的远程代码执行（RCE）攻击风险。该漏洞的CVSS评分为9.8（严重），其根源在于插件在处理Donation 表单时未能正确验证用户输入的数据。  
### 6. CISA警告VMware漏洞正遭积极利用，敦促企业立即修补  
  
Vim 文本编辑器的漏洞 CVE-2025-27423 是一个高严重性问题，攻击者可以通过恶意 TAR 文件实现任意代码执行。该漏洞影响 Vim 9.1.1164 之前的版本，涉及 tar.vim 插件，当用户处理特制的 TAR 文件时，可能导致命令注入攻击。该漏洞于 2025 年 3 月修复，暴露了文件处理流程中输入验证的关键缺陷。  
### 7. Vim 编辑器漏洞：恶意 TAR 文件触发代码执行风险  
  
Have I Been Pwned（HIBP）数据泄露通知服务近日新增了2.84亿个被信息窃取木马（infostealer）窃取的账户。这些账户数据是在一个名为“ALIEN TXTBASE”的Telegram频道中被发现的。  
### 8. Windows KDC曝代理RCE漏洞：攻击者可远程控制服务器  
  
安全研究人员近日在微软的Windows密钥分发中心（KDC）代理中发现了一个严重的远程代码执行漏洞（CVE-2024-43639），攻击者可能利用该漏洞完全控制受影响的服务器。该漏洞源于KDC代理服务中缺乏对Kerberos响应长度的检查，导致整数溢出，从而使得未经身份验证的远程攻击者能够以目标服务的权限执行任意代码，可能导致系统完全沦陷。  
### 9. 全球近5W个访问管理系统存在严重安全漏洞  
  
荷兰IT安全咨询公司Modat发现，全球范围内部署的约49,000个访问管理系统（AMS）存在严重的安全漏洞。这些系统本应通过密码、生物识别和多因素认证等身份验证方法控制建筑物访问，然而却因关键配置错误导致敏感数据暴露，使设施面临未经授权进入的风险。  
### 10. VMware ESX曝3个0Day漏洞，已被黑客利用  
  
Broadcom公司近日修复了VMware ESX产品中的三个0Day漏洞，这些漏洞已被恶意利用。攻击者如果拥有管理员或root权限，可以链式利用这些漏洞，从虚拟机中逃脱沙盒限制。  
  
**一周好文共读**  
  
  
##   
###   
### 1. 探秘条件漏洞：系统安全的潜在隐患  
  
竞争条件是一种常见的漏洞，与业务逻辑缺陷密切相关。当网站在没有足够保护措施的情况下并发处理请求时，会发生竞争条件。这可能导致多个不同的线程同时与相同的数据交互，从而导致应用程序中的“碰撞”，引发意外行为。竞争条件攻击通过精心计时的请求来故意引发碰撞，并利用这种意外行为进行恶意目的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ib5uR1uuYphkz6JyavO9icTgkQVzpNdBv4H020mNxThREvD4gHibc7ibIbJ0R4MicTXeqo4RHibaSarS9A/640?wx_fmt=png&from=appmsg "")  
### 2. 企业云安全中的存储桶攻击手法及防御策略  
  
本文将深入探讨企业云安全中存储桶的常见攻击手法，包括Bucket公开访问、Bucket桶爆破、特定的Bucket策略配置、Bucket Object遍历、任意文件上传与覆盖、AccessKeyId/SecretAccessKey泄露、Bucket劫持与子域接管、存储桶的配置可写、修改Bucket策略为Deny使业务瘫痪、修改网站引用的S3资源进行钓鱼等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ib5uR1uuYphkz6JyavO9icTg5BPfhKgFZbia5V9TrwdnUIOibbJBNE4ktZPwU80Q9qtibqNDDlhicDNFsQ/640?wx_fmt=png&from=appmsg "")  
### 3. 影响200万+网站 Wordpress插件漏洞复现  
  
Essential Addons for Elementor Pro是一款高级WordPress插件，为Elementor页面构建器提供丰富的扩展功能和高级模块，帮助用户轻松创建出色的网站。Elementor 插件 Essential Addons 遭受了反射型跨站点脚本 (XSS) 漏洞。漏洞的发生是由于对 popup-selector 查询参数的验证和清理不足，导致恶意值被反射回用户。该漏洞已在 6.0.15 版中修复，并被标记为 CVE-2025-24752。  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ib5uR1uuYphkz6JyavO9icTg10wH761mboib3ianP2JUhYxEkVGPhGXFf3Su5RPkOhjTFrrxHaoeWIow/640?wx_fmt=png&from=appmsg "")  
  
*点击  
【阅读原文】  
可查看完整文章内容，付费文章购买FVIP方可阅读全文。  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651312407&idx=1&sn=60289b6b056aee1df1685230aa453829&token=1964067027&lang=zh_CN&scene=21#wechat_redirect)  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
