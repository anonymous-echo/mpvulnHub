#  CrushFTP 漏洞概念验证代码公开后遭攻击者利用   
 FreeBuf   2025-04-04 18:07  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
安全研究人员证实，在概念验证（PoC）利用代码公开后，针对CrushFTP关键身份验证绕过漏洞（CVE-2025-2825）的攻击尝试已经开始活跃。  
  
  
根据Shadowserver基金会最新监测数据，截至2025年3月30日，全球仍有约1512个未打补丁的实例处于暴露状态，其中北美地区占比最高（891台）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJ1UiaObonmWJbuLyoLXdutG2VKSSo4xiaCvhnuicmyosMXwp12vzpnhqPP42byNeQYXuIZ9xdgwjbw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
该漏洞CVSS评分为9.8分，影响CrushFTP 10.0.0至10.8.3版本以及11.0.0至11.3.0版本。  
  
  
该漏洞于2025年3月26日首次披露，攻击者可通过构造特殊的HTTP请求绕过身份验证，最终可能导致系统完全沦陷。  
  
  
"我们观察到基于公开PoC利用代码的CrushFTP CVE-2025-2825漏洞利用尝试，"Shadowserver基金会在最新公告中表示，"全球约有1800个未修复实例，其中美国超过900个。"  
  
  
我们观察到基于公开PoC利用代码的CrushFTP CVE-2025-2825漏洞利用尝试。您可以通过我们的仪表板追踪攻击尝试https://t.co/PNW2ZzS9Gy截至2025-03-30仍有1512个未修复实例易受CVE-2025-2825影响https://t.co/PNW2ZzS9Gyhttps://t.co/w0CkIHWxk8pic.twitter.com/MCFnwsjmP0  
  
— The Shadowserver Foundation (@Shadowserver) 2025年3月31日  
  
  
**漏洞利用技术细节**  
  
  
  
ProjectDiscovery安全研究人员发布详细分析报告，揭示攻击者可通过相对简单的三步流程利用该漏洞：  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icJ1UiaObonmWJbuLyoLXdutrS5oJyBDvibRSHwZfE7EUuX6KHCI5a9Dj3Dv4MJwYtnXwEo9rBWWcNA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**攻击利用三个关键组件：**  
  
- 伪造的AWS标头，利用CrushFTP默认"crushadmin"用户名处理S3协议  
  
- 包含特定44字符CrushAuth值的伪造cookie  
  
- 使用c2f参数绕过密码验证检查的参数操控  
  
该漏洞源于处理S3风格请求时的认证逻辑缺陷，系统错误地将"crushadmin/"凭证视为有效而不进行正确的密码验证。  
  
  
Shadowserver监控仪表板最新数据显示，欧洲以490个易受攻击实例位居第二，其次是亚洲（62个）、大洋洲（45个），南美和非洲各有12个。  
  
  
**缓解措施**  
  
  
  
CrushFTP已发布11.3.1版本，通过以下方式修复漏洞：  
  
- 默认禁用不安全的S3密码查找  
  
- 新增安全参数"s3_auth_lookup_password_supported=false"  
  
- 实施正确的认证流程检查  
  
安全专家建议立即采取以下措施：  
  
- 立即升级至CrushFTP 11.3.1+或10.8.4+版本  
  
- 若无法立即打补丁，可启用DMZ功能作为临时缓解措施  
  
- 使用ProjectDiscovery免费检测工具：nuclei -t https://cloud.projectdiscovery.io/public/CVE-2025-2825  
  
- 审计服务器日志中可疑的/WebInterface/function/ GET请求  
  
这是CrushFTP继CVE-2023-43177后再次出现安全问题，该漏洞同样允许未认证攻击者访问文件并执行任意代码。文件传输解决方案中反复出现的认证漏洞反映出令人担忧的趋势，攻击者持续将这些关键基础设施组件作为入侵企业网络的入口。各组织应立即优先修补此漏洞。  
  
  
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
  
