#  CVSS 10.0！Apache Roller 曝高危漏洞：密码修改后会话仍持续有效   
 FreeBuf   2025-04-16 07:23  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
Apache Roller 开源博客服务器软件近日曝出一个高危安全漏洞，攻击者可利用该漏洞在用户修改密码后仍保持未授权访问。这款基于 Java 的博客平台存在会话管理缺陷，被赋予最高危险等级的 CVSS 10.0 评分。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icsRjQ1n84ibTh5iaPiaOFVqNcemIrCnsSUpIf4uZVfYCYEE5ZsS61VibJUicRYVLrXpFKKSOx3zBrf2xA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
  
  
**漏洞详情（CVE-2025-24859）**  
  
  
该漏洞编号为 CVE-2025-24859，影响 Roller 6.1.4 及之前所有版本。项目维护团队在公告中指出："Apache Roller 6.1.5 之前版本存在会话管理漏洞，当用户密码被修改后，活动会话未能正确失效。  
无论是用户自行修改密码还是管理员操作，现有会话仍保持活跃可用状态。"  
  
  
这意味着攻击者即使在被修改密码后，仍可通过原有会话持续访问系统。若用户凭证已遭泄露，攻击者更可获得不受限制的访问权限。  
  
  
**02**  
  
  
  
**修复方案**  
  
  
开发团队已在 6.1.5 版本中修复该漏洞，通过实施集中式会话管理机制，确保密码修改或用户禁用操作会使所有活动会话立即失效。安全研究员 Haining Meng 因发现并报告此漏洞获得致谢。  
  
  
**03**  
  
  
  
**近期相关漏洞**  
  
  
此次漏洞披露前数周，Apache Parquet Java 库刚曝出另一个高危漏洞（CVE-2025-30065，CVSS 10.0），攻击者可利用该漏洞在受影响实例上远程执行任意代码。  
  
  
上月，Apache Tomcat 的关键安全漏洞（CVE-2025-24813，CVSS 9.8）在细节公开后不久即遭活跃利用。这些连续出现的高危漏洞凸显了开源组件安全维护的重要性。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317804&idx=2&sn=3d017ae8749aa67775bcd2302b38931b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317737&idx=1&sn=99fed7dcc16d21127eb031fd187b35f5&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651316669&idx=1&sn=5ab3662670a61b2547721688803a0ec1&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
