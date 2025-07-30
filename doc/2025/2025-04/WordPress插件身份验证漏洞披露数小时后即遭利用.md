#  WordPress插件身份验证漏洞披露数小时后即遭利用   
 FreeBuf   2025-04-11 11:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
在公开披露仅数小时后，黑客就开始利用WordPress的OttoKit（原SureTriggers）插件中一个可绕过身份验证的高危漏洞。安全专家强烈建议用户立即升级至本月初发布的OttoKit/SureTriggers最新版本1.0.79。  
  
  
![Hackers exploit WordPress plugin auth bypass hours after disclosure](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibfHJsFO5icMuraoNACD1HJWTiamOsxZWoLI3IGg2EtKPys2JAvTvDcdDqgiaziahib2LhbXxXj2sH9o0w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
  
**插件功能与影响范围**  
  
  
OttoKit插件允许用户无需编写代码即可连接WooCommerce、Mailchimp和Google Sheets等外部工具，实现发送邮件、添加用户或更新客户关系管理系统（CRM）等自动化操作。据统计，该插件目前被10万个网站使用。  
  
  
**02**  
  
  
  
**漏洞技术细节**  
  
  
Wordfence安全团队昨日披露了编号为CVE-2025-3102的身份验证绕过漏洞，影响所有1.0.78及之前版本的SureTriggers/OttoKit插件。漏洞根源在于处理REST API身份验证的_authenticate_user()_函数未对空值进行检查——当插件未配置API密钥时，存储的_secret_key_将保持为空值。  
  
  
![存在漏洞的代码](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibfHJsFO5icMuraoNACD1HJWQso783HGrcUbmibYRibbMZY7Ejrlzic4iaia8GDoS52GPeaytmEIdKJibK9Q/640?wx_fmt=jpeg&from=appmsg "")  
  
  
攻击者通过发送空的_st_authorization_请求头即可绕过检查，获得受保护API端点的未授权访问权限。该漏洞本质上允许攻击者在未经认证的情况下创建新的管理员账户，存在网站完全被接管的高风险。  
  
  
**03**  
  
  
  
**漏洞披露与修复时间线**  
  
  
安全研究员"mikemyers"于3月中旬发现该漏洞并报告给Wordfence，获得了1,024美元的漏洞赏金。插件开发商于4月3日收到完整漏洞详情后，当天即发布1.0.79版本修复补丁。  
  
  
**04**  
  
  
  
**黑客快速利用情况**  
  
  
WordPress安全平台Patchstack研究人员警告称，漏洞公开后仅数小时就监测到实际攻击尝试。"攻击者迅速利用该漏洞，我们数据库添加漏洞补丁记录后仅四小时就捕获到首次攻击尝试，"Patchstack报告指出。研究人员强调："这种快速利用现象凸显了漏洞公开后立即应用补丁或缓解措施的极端重要性。"  
  
  
攻击者使用随机生成的用户名/密码和邮箱组合尝试创建管理员账户，显示出自动化攻击特征。安全团队建议所有OttoKit/SureTriggers用户立即升级至1.0.79版本，并检查日志中是否存在异常管理员账户创建、插件/主题安装、数据库访问事件以及安全设置修改等可疑活动。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317737&idx=1&sn=99fed7dcc16d21127eb031fd187b35f5&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317886&idx=1&sn=50bb777ea9b038b842812efd1d390806&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317886&idx=2&sn=d71ff253383c30e9a56386b7e7ef8f45&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
