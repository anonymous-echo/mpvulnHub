#  Erlang/OTP SSH存在CVSS 10.0级高危远程代码执行漏洞   
 FreeBuf   2025-04-20 10:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
安全研究人员披露了编号为CVE-2025-32433的漏洞，该漏洞存在于Erlang/OTP SSH组件中，CVSS评分为10.0分（最高危险等级），攻击者可利用此漏洞在未经验证的情况下在暴露系统上执行任意代码。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icWJxQGpmdcL3xJefu6qYSibpibtuAm8N5vTibgJT0wgicXUV5jCaagiaHVAysYkX7tdRr3bxjZGTAbJzQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
研究人员在Erlang/OTP的SSH实现中发现一个新漏洞，攻击者无需登录即可在受影响系统上运行代码。该漏洞由波鸿鲁尔大学的研究团队发现，由于可能影响广泛部署的Erlang库，其CVSSv3评分达到最高10.0分。  
  
  
通过oss-security邮件列表披露的漏洞涉及Erlang/OTP中SSH协议消息处理机制，攻击者可在认证阶段前发送特制消息。若被利用，该漏洞可导致任意代码执行。当SSH守护进程以root权限运行时，攻击者可能完全控制系统。  
  
  
**01**  
  
  
  
**受影响范围**  
  
  
所有基于Erlang/OTP SSH库构建的SSH服务器应用或服务均可能受到影响，这包括各类依赖Erlang的高可用性系统环境，特别是电信设备、工业控制系统和联网设备等关键基础设施。  
  
  
研究人员强调："任何使用Erlang/OTP SSH进行远程访问的应用都应视为受影响系统。"  
  
  
**02**  
  
  
  
**漏洞原理**  
  
  
该漏洞源于SSH服务器在初始连接阶段（认证前）处理特定消息的方式。具备网络访问权限的攻击者可在认证步骤前发送连接协议消息，绕过常规检查并触发远程代码执行。  
  
  
根据安全公告，该漏洞可使未授权用户获得与SSH守护进程相同的权限。这意味着若守护进程以root身份运行，攻击者将获得系统无限制访问权。  
  
  
**03**  
  
  
  
**应对措施**  
  
  
Erlang官方已在GitHub安全页面发布公告。对于无法立即升级的系统，建议通过防火墙规则限制SSH服务器仅接受可信来源的访问。  
  
  
该漏洞的严重性不仅在于其利用方式，更在于其存在位置。Erlang/OTP广泛嵌入于众多生产系统中，却常在常规审计中被忽视，这使得漏洞影响范围可能极为广泛。  
  
  
当Erlang/OTP这类基础库出现漏洞时，其影响会迅速扩散。CVE-2025-32433就是典型案例，尤其威胁依赖远程访问和自动化的系统。因此，管理员和供应商应立即评估系统，确认是否使用Erlang/OTP SSH组件，并尽快修补或隔离。  
  
  
**04**  
  
  
  
**专家观点**  
  
  
Qualys安全研究经理Mayuresh Dani评价该漏洞"极其危险"："由于对认证前SSH协议消息处理不当，远程攻击者可绕过安全检查执行系统代码。当SSH守护进程以root权限运行时（这在许多部署中很常见），攻击者将获得完全控制权。"  
  
  
Dani指出，Erlang因其出色的并发处理能力常被用于高可用系统："许多思科和爱立信设备都运行Erlang。任何使用Erlang/OTP SSH库进行远程访问的服务（如OT或IoT环境中的系统）均面临风险。"  
  
  
Dani建议升级至最新修补版本：OTP-27.3.3、OTP-26.2.5.11或OTP-25.3.2.20。需要更多时间升级的组织，应将SSH端口访问限制为可信IP。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1y91mvSZuxibf3Q3g2rJ32FNzoYfx4yaBmWbfwcRaNicuMo3AxIck2bCw/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651318777&idx=1&sn=1c9c7f2561b2b3ce09438b7f1ff25807&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651318673&idx=1&sn=fc4885839a5fa2d029e0e95474e9432b&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317804&idx=2&sn=3d017ae8749aa67775bcd2302b38931b&scene=21#wechat_redirect)  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651317737&idx=1&sn=99fed7dcc16d21127eb031fd187b35f5&scene=21#wechat_redirect)  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR39ibFdyjP3Qp8CEJxFWljbW1uEIoRxNoqa17tBBrodHPbOERbZXdjFvNZC5uz0HtCfKbKx3o3XarGQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3icFibibPIGEfXsibI0C3or4BS5KDnCKUfVLVQGsc9BiaQTUsrwzfcianumzeLVcmibOmm2FzUqef2V6WPQQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38mFMbqsUOVbBDicib7jSu7FfibBxO3LTiafGpMPic7a01jnxbnwOtajXvq5j2piaII2Knau7Av5Kxvp2wA/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
