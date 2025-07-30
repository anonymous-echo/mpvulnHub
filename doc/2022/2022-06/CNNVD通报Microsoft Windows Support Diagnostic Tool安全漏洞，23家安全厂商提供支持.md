#  CNNVD通报Microsoft Windows Support Diagnostic Tool安全漏洞，23家安全厂商提供支持   
 安全牛   2022-06-08 11:42  
  
**点击蓝字，关注我们**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/kuIKKC9tNkDiclRgYicuY227qN31I4icJCuIV5GFauaSOGcKAX7NicMpjy0vIom9WhQiaC84lUroPSFxKwiaic9IHPMQQ/640?wx_fmt=jpeg "")  
  
  
日前，国家信息安全漏洞库（CNNVD）正式发布了关于Microsoft Windows Support Diagnostic Tool安全漏洞（CNNVD-202205-4277、CVE-2022-30190）的情况通报。成功利用此漏洞的攻击者，可在目标主机执行恶意代码。Windows 11、Windows 10 、Windows 8、Windows 7、Windows Server 2022、Windows Server 2016、Windows Server 2012、Windows Server 2008、Windows Server version 20H2、Windows Server 2022等多个系统版本均受此漏洞影响。目前，微软官方发布了临时修补措施缓解漏洞带来的危害，请用户及时确认是否受到漏洞影响，尽快采取修补措施。  
  
  
**01**  
  
points  
  
**漏洞介绍**  
  
Microsoft Windows Support Diagnostic Tool是美国微软公司Windows操作系统内的一个程序，用于排除故障并收集诊断数据以供技术人员分析和解决问题。该漏洞源于Microsoft Windows Support Diagnostic Tool中的URL协议存在逻辑问题，攻击者可诱使目标主机的应用（如word）通过Microsoft Windows Support Diagnostic Tool中的URL协议下载并打开特制的文件，进而在目标主机执行恶意代码。  
  
**02**  
  
points  
  
**危害影响**  
  
成功利用此漏洞的攻击者，可在目标主机执行恶意代码。以下操作系统版本受漏洞影响：  
  
Windows Server 2012 R2 (Server Core installation)  
  
Windows Server 2012 R2  
  
Windows Server 2012 (Server Core installation)  
  
Windows Server 2012  
  
Windows Server 2008 R2 for x64-based Systems Service Pack 1 (Server Core installation)  
  
Windows Server 2008 R2 for x64-based Systems Service Pack 1  
  
Windows Server 2008 for x64-based Systems Service Pack 2 (Server Core installation)  
  
Windows Server 2008 for x64-based Systems Service Pack 2  
  
Windows Server 2008 for 32-bit Systems Service Pack 2 (Server Core installation)  
  
Windows Server 2008 for 32-bit Systems Service Pack 2  
  
Windows RT 8.1  
  
Windows 8.1 for x64-based systems  
  
Windows 8.1 for 32-bit systems  
  
Windows 7 for x64-based Systems Service Pack 1  
  
Windows 7 for 32-bit Systems Service Pack 1  
  
Windows Server 2016  (Server Core installation)  
  
Windows Server 2016  
  
Windows 10 Version 1607 for x64-based Systems  
  
Windows 10 Version 1607 for 32-bit Systems  
  
Windows 10 for x64-based Systems  
  
Windows 10 for 32-bit Systems  
  
Windows 10 Version 21H2 for x64-based Systems  
  
Windows 10 Version 21H2 for ARM64-based Systems  
  
Windows 10 Version 21H2 for 32-bit Systems  
  
Windows 11 for ARM64-based Systems  
  
Windows 11 for x64-based Systems  
  
Windows Server, version 20H2 (Server Core Installation)  
  
Windows 10 Version 20H2 for ARM64-based Systems  
  
Windows 10 Version 20H2 for 32-bit Systems  
  
Windows 10 Version 20H2 for x64-based Systems  
  
Windows Server 2022 Azure Edition Core Hotpatch  
  
Windows Server 2022 (Server Core installation)  
  
Windows Server 2022  
  
Windows 10 Version 21H1 for 32-bit Systems  
  
Windows 10 Version 21H1 for ARM64-based Systems  
  
Windows 10 Version 21H1 for x64-based Systems  
  
Windows Server 2019  (Server Core installation)  
  
Windows Server 2019  
  
Windows 10 Version 1809 for ARM64-based Systems  
  
Windows 10 Version 1809 for x64-based Systems  
  
Windows 10 Version 1809 for 32-bit  Systems      
  
  
**03**  
  
points  
  
**修复建议**  
  
目前，微软官方发布了临时修补措施缓解漏洞带来的危害，请用户及时确认是否受到漏洞影响，尽快采取修补措施。官方链接如下：  
  
https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30190  
  
  
本通报由CNNVD技术支撑单位——华为技术有限公司、北京启明星辰信息安全技术有限公司、深信服科技股份有限公司、北京天融信网络安全技术有限公司、北京奇虎科技有限公司、北京神州绿盟科技有限公司、亚信科技（成都）有限公司、北京知道创宇信息技术股份有限公司、奇安信网神信息技术（北京）股份有限公司、长春嘉诚信息技术股份有限公司、北京永信至诚科技股份有限公司、北京微步在线科技有限公司、天翼数智科技（北京）有限公司、新华三技术有限公司、杭州安恒信息技术股份有限公司、腾讯公司、北京华顺信安科技有限公司、南京铱迅信息技术股份有限公司、远江盛邦（北京）网络安全科技股份有限公司、北京华云安信息技术有限公司、西安四叶草信息技术有限公司、上海斗象信息科技有限公司、上海安几科技有限公司提供支持。  
  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。联系方式: cnnvdvul@itsec.gov.cn  
  
  
文章来源：CNNVD  
  
  
相关阅读  
   
  
[英特尔芯片连续爆出三个高危漏洞](https://mp.weixin.qq.com/s?__biz=MjM5Njc3NjM4MA==&mid=2651107483&idx=2&sn=380119f2824c0122978416fc3a90e9dc&scene=21#wechat_redirect)  
  
  
[最常被利用的三类API漏洞](https://mp.weixin.qq.com/s?__biz=MjM5Njc3NjM4MA==&mid=2651105195&idx=3&sn=2a7a08b0aab6e23a5965a346da3ab226&scene=21#wechat_redirect)  
  
  
[BitDefender 发现首个利用Log4Shell漏洞的勒索软件](https://mp.weixin.qq.com/s?__biz=MjM5Njc3NjM4MA==&mid=2651108296&idx=3&sn=a815ca69cfa7eafcd4e78baddc8f2cf7&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAZYNibk7aDDd0hAkQGzOfLPfjXUPaypbuDrr5exabqWXmSOeZVUZtP6zqw9YGWib9xNQdvx1iaCicTUA/640?wx_fmt=gif "")  
  
合作电话：18311333376  
  
合作微信：aqniu001  
  
投稿邮箱：editor@aqniu.com  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/kuIKKC9tNkAfZibz9TQ8KWj4voxxxNSGMAGiauAWicdDiaVl8fUJYtSgichibSzDUJvsic9HUfC38aPH9ia3sopypYW8ew/640?wx_fmt=gif "")  
  
