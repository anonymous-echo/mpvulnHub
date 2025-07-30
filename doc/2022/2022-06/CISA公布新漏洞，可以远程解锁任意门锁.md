#  CISA公布新漏洞，可以远程解锁任意门锁   
 关键基础设施安全应急响应中心   2022-06-14 14:52  
  
专家发现 HID Mercury Access Controller 中的漏洞可被攻击者利用来远程解锁门。  
  
安全公司 Trellix 的研究人员在 HID Mercury Access Controller 中发现了一些严重漏洞，攻击者可以利用这些漏洞远程解锁门。  
  
这些缺陷影响了 LenelS2 制造的产品，LenelS2 是 HVAC 巨头 Carrier 旗下的高级物理安全解决方案（即访问控制、视频监控和移动认证）提供商。  
  
Trellix 威胁实验室的研究人员在Hardwear.io 安全培训和会议期间披露了这些漏洞， 他们分析了用于授予对特权设施的物理访问权限的工业控制系统 (ICS)。专家们专注于由 HID Mercury 制造的 Carrier LenelS2 门禁控制面板。  
  
“分析从最低级别的硬件开始。通过使用制造商的内置端口，我们能够操纵板载组件并与设备交互。结合已知和新技术，我们能够实现对设备操作系统的 root 访问并拉取其固件以进行仿真和漏洞发现。” 阅读Trellix 发布的帖子。  
  
Trellix 发现了8 个漏洞，其中 7 个被评为“严重”，远程攻击者可以利用这些漏洞执行任意代码、执行命令注入、信息欺骗、写入任意文件和触发拒绝服务 ( DoS) 条件。以下是研究人员发现的缺陷列表：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QmbJGbR2j6zBZMfN2UVicsSDiaM4iaTicgM83K9ia88gJmA8E8RCjyD5rS2WZ3ycq4ut3Yic5kSpoEONcibcn8yNBxC7Q/640?wx_fmt=png "")  
  
大多数这些漏洞可以在没有身份验证的情况下被利用，但利用需要直接连接到目标系统。  
  
研究人员对固件和系统二进制文件进行了逆向工程，并进行了实时调试，发现了八个问题，其中六个未经身份验证，两个经过身份验证的漏洞可通过网络远程利用。  
  
“通过将两个漏洞链接在一起，我们能够利用访问控制板并远程获得设备的根级别权限。有了这种访问级别，我们创建了一个程序，可以与合法软件一起运行并控制门。” 继续发帖。“这使我们能够解锁任何门并颠覆任何系统监控。”  
  
专家们还开发了一个概念验证（PoC）漏洞来解锁任何门和黑客监控系统。在研究人员发布的视频 PoC 下方：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/QmbJGbR2j6zBZMfN2UVicsSDiaM4iaTicgM8IjFG1PqR5Ly5zWaeXwpX6OGBxbAY7kFogBgm3HMzKhbB2ia2mb4KLTA/640?wx_fmt=png "")  
  
Carrier 已发布产品安全公告 ，以警告客户有关漏洞并敦促他们安装固件更新。  
  
“通过使用我们负责任的披露程序对 HID Mercury™ 进行独立渗透测试，据报道，LenelS2 销售的访问面板包含网络安全漏洞。” 阅读咨询。“这些漏洞可能会导致正常的面板操作中断。受影响的 LenelS2 部件号包括：  
- LNL-X2210  
  
- S2-LP-1501  
  
- LNL-X2220  
  
- S2-LP-1502  
  
- LNL-X3300  
  
- S2-LP-2500  
  
- LNL-X4420  
  
- S2-LP-4502  
  
- LNL-4420  
  
前几代 HID Mercury 控制器不受影响。  
  
美国网络安全和基础设施安全局 (CISA) 也发布了有关这些漏洞的公告。  
  
  
  
原文来源：E  
安全  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogucKMiatGyfBHlfj74r3CyPxEBrV0oOOuHICibgHwtoIGayOIcmJCIsAn02z2yibtfQylib07asMqYAEw/640?wx_fmt=jpeg "")  
  
