#  【漏洞预警】Apache OpenMeetings未授权 反序列化漏洞   
cexlife  飓风网络安全   2025-01-10 04:06  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01e1WZfk9xnSibsFVx78sFwGytycRcapQlPaAwoG1jnuMgA5OAWVmCnoXicQ0QFpZD4pjFWQgicIB0dg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述:**  
Apache OpenMeetings是一个开源的网络会议软件‌,由TheApache Software Foundation创建并维护‌。Apache OpenMeetings发布安全公告,披露了一个未授权反序列化漏洞,该漏洞是由于OpenMeetings所使用的Java持久化框架OpenJPA缺乏适当的白名单和黑名单配置所致,恶意行为者可利用此漏洞注入恶意代码，该漏洞影响Apache OpenMeetings集群模式,攻击者可能通过此漏洞获得对整个集群的完全控制,极大地扩大攻击影响，Apache已发布新版本修复此漏洞,建议受影响用户及时升级到安全版本。**修复建议:**正式防护方案:1.针对此漏洞,官方已经发布了漏洞修复版本,请立即更新到安全版本:Apache OpenMeetings >= 8.0.0**下载链接:**https://openmeetings.apache.org/downloads.html2.更新启动脚本,请结合自身业务代码,在启动参数中添加以下黑名单和白名单配置:- openjpa.serialization.class.blacklist=<不受信任的类列表>- openjpa.serialization.class.whitelist=<受信任的类列表>修复前,请确保备份所有关键数据,并按照官方指南进行操作。修复后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
