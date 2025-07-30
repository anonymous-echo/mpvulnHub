#  物联网云平台 OvrC 曝一系列漏洞，黑客可远程执行恶意代码   
安世加  安世加   2024-11-18 10:34  
  
11 月 16 日消息，安全公司 Claroty 发布报告，曝光了一款海外流行的物联网设备云端管理平台 Ovr 内含的一系列重大漏洞。安全公司声称黑客可以接连利用这些漏洞实现在物联网设备上远程执行恶意代码，而根据 CVSS 风险评估，部分曝光的漏洞风险评分高达 9.2（满分 10 分）。  
  
  
据悉，OvrC 物联网平台的主要功能是通过移动应用或基于 Web Socket 的界面为用户提供远程配置管理、运行状态监控等服务。自动化公司 SnapOne 在 2014 年收购了该平台，在 2020 年声称 OvrC 已拥有约 920 万台设备，而如今该平台预计坐拥 1000 万台设备。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/UZ1NGUYLEFiacOUmAVvfIGZicxPN4WVv6DJP47gYlNUIy8X4ib6ZlicquGZQaR5GRjEf6QSdr83kGXwvEiaYfbDjegw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
▲ OvrC 物联网平台下的设备  
  
  
参考安全报告获悉，相关漏洞主要包括输入验证不足、不当的访问控制、敏感信息以明文传输、数据完整性验证不足、开放式重定向、硬编码密码、绕过身份验证等，此类漏洞大多源于设备与云端接口的安全设计缺陷，黑客可利用漏洞绕过防火墙，避开网络地址转换（NAT）等安全机制，从而在平台设备上运行恶意代码。  
  
  
参考 CVSS 风险评分，4 个被评为高危的漏洞分别是：输入验证不足漏洞 CVE-2023-28649、不当访问控制漏洞 CVE-2023-31241、数据完整性验证不足漏洞 CVE-2023-28386，以及关键功能缺乏认证漏洞 CVE-2024-50381，**这些漏洞的评分在 9.1 至 9.2 之间**。  
  
  
关于漏洞的具体利用方式，研究人员指出，黑客可以先利用 CVE-2023-28412 漏洞获取所有受管设备的列表，再通过 CVE-2023-28649 和 CVE-2024-50381 漏洞强制设备进入“未声明所有权”（Unclaim）状态。随后黑客即可利用 CVE-2023-31241 漏洞将 MAC 地址与设备 ID 匹配，并通过设备 ID 重新声明设备所有权，最终实现远程执行代码。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/UZ1NGUYLEFiacOUmAVvfIGZicxPN4WVv6DQficjOC9vRqOY5RZdEFyia5k0cdiaI9XTu75ALayIyRfsiazq9o9qG8gUQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
值得注意的是，在研究人员报告后，大部分问题已于去年 5 月被修复，但仍有两个漏洞直到本月才得到解决，目前，该平台已完全修复相应漏洞。  
  
  
  
本公众号发布的文章均转载自互联网或经作者投稿授权的原创，文末已注明出处，其内容和图片版权归原网站或作者本人所有，并不代表安世加的观点，若有无意侵权或转载不当之处请联系我们处理！  
  
文章来源：IT之家  
  
**点击图片即可跳转**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540573&idx=1&sn=4905af05cd4027398427f2f63fa060e3&chksm=fc7b5b80cb0cd296123c62f1e6a9881dcee148084179180934dd7ac9520e469c8605eb2802eb&scene=21#wechat_redirect)  
  
**点击图片即可跳转**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540490&idx=1&sn=8d0fa1665ab08ef79c32f24c533cc464&chksm=fc7b5bd7cb0cd2c17b5c360e3a49e0ca2bcf14df07ffb9849e2690701298c18c2d49dd6fb3dd&scene=21#wechat_redirect)  
  
**点击图片即可跳转**  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540617&idx=1&sn=e0f834aa41ea18c25142064225a9f385&chksm=fc7b5b54cb0cd242d91f8caf91a52302d599b6ecb206b18c60671594e5aaecfd18a084dc5c7d&scene=21#wechat_redirect)  
  
  
  
  
安世加为出海企业提供SOC 2、ISO27001、PCI DSS、TrustE认证咨询服务（点击图片可详细查看）  
  
[](http://mp.weixin.qq.com/s?__biz=MzU2MTQwMzMxNA==&mid=2247540448&idx=1&sn=165f2bc3b3233827b2c601a32073aca8&chksm=fc7b5a3dcb0cd32bc659d53ad5b9eb040f9b3cd6b6289e425c96abb0848d51cf08e178907778&scene=21#wechat_redirect)  
  
  
