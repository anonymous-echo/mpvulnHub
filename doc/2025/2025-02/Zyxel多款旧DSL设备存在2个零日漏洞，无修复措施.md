#  Zyxel多款旧DSL设备存在2个零日漏洞，无修复措施   
Zicheng  FreeBuf   2025-02-07 11:15  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
Zyxel周二发布消息称，涉及多款旧DSL用户端设备（CPE）产品中的两个零日漏洞将不再提供修复措施。  
此前，威胁情报公司GreyNoise曾发出警告，有1500多台设备受到一个严重的命令注入漏洞影响，而且这个漏洞正在被基于Mirai的僵尸网络大肆利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibI6a5L6aGWsGUxVcibC1CIbicxYpAXKhaLUdbIK73HdlZurI4AHpAXZYZ0T28t8UJ69ho54BcxeuYA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
GreyNoise公司表示：“在发现利用CVE - 2024 - 40891的IP地址与被归类为Mirai的IP地址存在显著重叠后，我们对Mirai的一个近期变种展开了调查，结果确认利用CVE - 2024 - 40891的能力已经被整合到某些Mirai变种之中。”  
  
  
CVE - 2024 - 40891这个漏洞，于2024年中旬和CVE - 2024 - 40890（也是一个类似的命令注入漏洞）一同被披露出来。它们的主要区别在于攻击向量，一个是HTTP，另一个是Telnet。  
  
  
攻击者能够利用这些安全漏洞，在易受攻击的设备上执行任意命令，进而完全掌控设备并窃取数据，这极有可能危及部署这些产品的所在网络。  
  
  
周二当天，Zyxel 明确表示，这两个问题会影响到多款DSL CPE型号，具体包含VMG1312 - B10A、VMG1312 - B10B、VMG1312 - B10E、VMG3312 - B10A、VMG3313 - B10A、VMG3926 - B10B、VMG4325 - B10A、VMG4380 - B10A、VMG8324 - B10A、VMG8924 - B10A、SBG3300以及SBG3500。  
  
  
Zyxel 还指出，在这些设备上，广域网（WAN）接入和用于利用漏洞的Telnet功能，默认是处于禁用状态的。而且，攻击者若要利用这些漏洞，需要使用被攻破的凭据登录受影响的设备才行。  
  
  
按照供应商的说法，由于受影响的型号是多年前就已经停止支持的老旧设备，所以针对这两个漏洞都不会发布补丁。对于在这些DSL CPE产品中新发现的一个漏洞（编号CVE - 2025 - 0890，该漏洞允许攻击者使用默认凭据登录管理界面），同样也不会有补丁发布。  
  
  
VulnCheck公司向合勤科技报告了这些漏洞，并且解释说，受影响的设备预先配置有三个硬编码账户，分别是“supervisor”、“admin”和“zyuser”。  
  
  
其中，supervisor在网络界面不可见，但在Telnet界面具备相应功能，包括能够访问一个隐藏命令，通过这个命令它可以获得对系统的无限制访问权限。而zyuser账户在用户表中是可见的，并且具有提升后的权限，攻击者可利用它通过已被利用的CVE - 2024 - 40891漏洞实现完全远程代码执行。  
  
  
VulnCheck公司表示：“虽然这些设备已经老化，按道理应该停止支持了，但目前仍有数千台设备处于在线暴露的状态。默认凭据与命令注入这两者相结合，使得它们成为容易被攻击的目标，这也凸显出不安全默认配置以及糟糕的漏洞透明度所带来的危险。”  
  
  
据Zyxel 称，VulnCheck公司在2024年7月就报告了CVE - 2024 - 40890和CVE - 2024 - 40891这两个漏洞，不过当时并没有提供详细报告，而是直接公开披露了这些漏洞。直到GreyNoise上周发出野外利用警告之后，VulnCheck公司才发送了关于所有三个漏洞的详细信息。  
  
  
供应商还发出警告，受影响的设备“是已经达到产品生命周期终止（EOL）状态多年的老旧产品。按照行业产品生命周期管理惯例，合勤科技建议客户用新一代设备替换这些老旧产品，这样才能实现最佳保护。”  
  
  
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
  
