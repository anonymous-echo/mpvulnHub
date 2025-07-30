#  【安全圈】VMware 关键漏洞修复程序已发布，请立即更新   
 安全圈   2024-06-19 19:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=png&from=appmsg "微信图片_20230927171534.png")  
  
  
**关键词**  
  
  
  
信息安全  
  
  
近日，Broadcom 发布了影响 VMware vCenter 的三个漏洞的修复程序，其中两个是严重漏洞，允许远程代码执行 (RCE)。由于虚拟机（VM）往往存放大量敏感数据和应用程序，因此这些漏洞的披露引起了黑客的注意。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg6CkQbGQ0939LQOaXQZfL2rjhmibwemRpvFgOlSiapUicdwLVkjnJfT7uYye77xzOTuHuDh4HYh2e1Q/640?wx_fmt=jpeg&from=appmsg "")  
vCenter 是 VMware 虚拟环境的集中管理控制台，用于从单个集中位置查看和管理虚拟机、多个 ESXi 主机和所有附属组件。CVE-2024-37079 和 CVE-2024-37080 是 vCenter 实现 DCERPC（Distributed Computing Environment/Remote Procedure Call 的缩写）时存在的堆溢出漏洞。  
  
对于黑客而言，DCERPC 在与远程机器交互时非常有用。利用特制的网络数据包，拥有网络访问权限的攻击者可以利用这些漏洞在 vCenter 管理的虚拟机上远程执行自己的代码。这两个漏洞的潜在危害在 CVSS 评级中都获得了 9.8 分的高分（满分 10 分）。  
  
Broadcom 还修补了一些因 vCenter 中 sudo 配置错误而导致的本地权限升级漏洞。sudo是 "superuser do "或 "substitute user do "的缩写，它允许 Unix 系统中的用户以另一个用户（默认为root级）的权限运行命令。通过身份验证的本地用户可以利用标有 CVE-2024-37081 的漏洞获得 vCenter Server 设备的管理权限。该漏洞的 CVSS 得分高达 7.8。  
  
到目前为止，还没有证据表明这三个漏洞中的任何一个在野外被利用过，不过这种情况可能会很快改变。有关补救措施及相关问答，可以参考：  
- https://support.broadcom.com/web/ecx/support-content-notification/-/external/content/SecurityAdvisories/0/24453  
  
- https://core.vmware.com/resource/vmsa-2024-0012-questions-answers  
  
## 云虚拟机的风险  
  
根据 VMware 公布的文件，VMware 拥有 40 多万家客户，其中包括财富 500 强和财富全球 100 强企业。其技术为 80% 以上的虚拟化工作负载和大量关键业务应用提供支持。  
  
"随着云计算的日益普及，虚拟机的使用量也相应激增，多个应用程序被整合到一台物理服务器上，"Keeper Security 公司安全和架构副总裁 Patrick Tiquet 解释说。"这种整合不仅提高了运行效率，也为攻击者提供了通过单一漏洞入侵各种服务的机会。"  
  
vCenter Server 就是这种风险的缩影。作为支持 VMWare vSphere 和 Cloud Foundation 平台的集中管理软件，它为 IT 管理员和黑客提供了一个启动点，使他们可以接触到运行在各个组织中的许多虚拟机。  
  
Tiquet 警告说："成功的漏洞攻击不仅会中断服务并造成经济损失，还可能导致敏感数据的暴露和违反监管要求，严重损害组织的声誉。"因此，修补新出现的漏洞非常必要。  
  
另外，除了网络分段、漏洞审计和其他安全加固策略（如事件响应计划和维护强大的备份）之外，网络管理员的工作还包括从正面进行引导。Tiquet 表示："管理员应该始终确保使用的是安全的保险库和机密管理解决方案，并且尽快应用必要的更新，还应该检查云控制台的安全控制，以确保遵循了最新的建议。"  
  
  
   END    
  
  
阅读推荐  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg6CkQbGQ0939LQOaXQZfL2iacySs55gAKme74zVrng4BWDD6LPbwZd2euNoElnu7n3MzXdVHiaVmDQ/640?wx_fmt=jpeg "")  
[【安全圈】华硕曝出高危漏洞，影响 7 款路由器](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061782&idx=1&sn=e8894306d0de41042737e971d78c8b8a&chksm=f36e6c16c419e5004b19a53b8b3234b933baf78377a98a37f33af00ea578f30b64518a9ab4a8&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg6CkQbGQ0939LQOaXQZfL25yNMyR7JgVwKVefdrCH2FicA5KfI8ZJKzl2IDmAaKBtqfnsrS2hTQpA/640?wx_fmt=jpeg "")  
[【安全圈】勒索攻击致使英国首都近千台手术被迫取消](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061782&idx=2&sn=2e796e3d62764cf829f9077ec87c5fbf&chksm=f36e6c16c419e5002d7eab7661542b73cc6001b796a745d35747d152a049ee0bdc25dbc2477b&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylhlUxdWpmlcvwUPZnTYQKbhpFoCgibTicOGk8VxUiaa7jULw6Lo5icEap7jicUVBsrQOfOp6UmgeKibYt3g/640?wx_fmt=jpeg "")  
[【安全圈】黑客入侵 Tile 内部工具，数百万用户数据或被泄露](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061782&idx=3&sn=6d01309363b21ab1686b7ddb08b420ce&chksm=f36e6c16c419e500d9b56c4bfa33670f45acb8ea3f949cd9e2181d53f4aeedaa76e20e7056ee&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGylg6CkQbGQ0939LQOaXQZfL2pH6K2PibAjOqpexZoY32ibjZy9eZn5JhOrKGOdlnJfMIG5Aia1mdHOSRQ/640?wx_fmt=jpeg "")  
[【安全圈】微软修补可能很快被利用的零点击 Outlook 漏洞](http://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652061782&idx=4&sn=cd9dcd21f22bdec6faab966918bfe055&chksm=f36e6c16c419e5007bfa00c6fe9614a140bf7a0b20266a7c1ea8106c406b27fc916835370d9e&scene=21#wechat_redirect)  
  
  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
