#  ChatGPT在公开漏洞利用代码发布前成功生成CVE有效攻击程序   
 FreeBuf   2025-04-23 10:42  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ibm8NVibGM2wDbV1XDA5fgnh24phUJB0dWWVyerhw42yV7LI5LOqfFB3b7dHoCJAEbILBmVJd5sF2A/640?wx_fmt=png&from=appmsg "")  
  
  
  
安全研究员Matt Keeley近期演示了人工智能如何在公开概念验证（PoC）攻击代码发布前，就成功生成针对关键漏洞的有效利用程序。这一突破可能彻底改变漏洞研究领域的现状。  
  
  
Keeley使用GPT-4为CVE-2025-32433开发出功能性攻击程序，该漏洞是Erlang/OTP SSH组件中的高危漏洞，CVSS评分达到满分10.0。这一成果展示了AI在网络安全领域日益增长的能力。  
  
  
"GPT-4不仅能理解CVE描述，还能定位修复提交、比对旧版代码、发现差异、找到漏洞位置，甚至编写出概念验证代码。当代码不工作时，它还能自行调试修复。"Keeley在2025年4月17日发布的详细博文中解释道。  
  
  
![image](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibm8NVibGM2wDbV1XDA5fgnhluCFxJb4f3iaHYwy3J3jQlUZA7PtqUbWIicXmxJMfxDrzFCcnSoicAIzg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**01**  
  
  
  
**漏洞技术细节分析**  
  
  
该漏洞于2025年4月16日披露，影响Erlang/OTP的SSH服务器实现，允许攻击者无需认证即可远程执行代码。该高危缺陷源于SSH协议消息在连接初期的处理不当，使得攻击者能在受影响系统上以提升权限执行任意代码。  
  
  
Keeley的研究始于注意到Horizon3.ai研究人员提及已创建但未公开PoC的推文。仅凭这条有限信息，他引导GPT-4分析漏洞。AI系统性地完成了以下工作：  
  
  
1. 定位不同版本的代码  
  
2. 创建比对漏洞代码与修复代码的工具  
  
3. 确定漏洞的确切成因  
  
4. 生成攻击代码  
  
5. 调试修复代码直至可用  
  
  
**02**  
  
  
  
**网络安全格局面临重构**  
  
  
"这引发了一个严峻问题：AI能以多快速度协助漏洞研究，甚至自动化整个流程。几年前，这个过程需要专业的Erlang知识和数小时手动调试。如今，只需一下午的正确提示就能完成。"Keeley指出。  
  
  
安全专家对此既兴奋又担忧。虽然AI使安全研究更易获得，但也可能降低恶意分子开发攻击程序的门槛。漏洞披露仅一天后，就有多名研究人员开发出有效攻击程序，其中Platform Security已在GitHub发布其AI辅助的PoC。  
  
  
受影响Erlang/OTP版本（OTP-27.3.2及更早版本、OTP-26.2.5.10及更早版本、OTP-25.3.2.19及更早版本）已在新版本中修复。使用Erlang/OTP SSH服务器的组织应立即升级至修复版本：OTP-27.3.3、OTP-26.2.5.11或OTP-25.3.2.20。  
  
  
该案例凸显AI正在重塑网络安全格局。随着这些工具日益成熟，漏洞披露与攻击程序开发的时间窗口持续缩小，迫使组织必须加快补丁实施速度。  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319086&idx=1&sn=e2ff862babd7662c4fa06b0e069c03f2&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651319171&idx=2&sn=9ae825f6633d32e60f1f2474c29e4e20&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651318673&idx=1&sn=fc4885839a5fa2d029e0e95474e9432b&scene=21#wechat_redirect)  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
