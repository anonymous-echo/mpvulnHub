#  【漏洞预警】DrayTek Vigor2960 Router命令注入漏洞   
cexlife  飓风网络安全   2024-10-31 22:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01KdlKovDEZkJfACVDBXp7tngdsvC13eN3ISkxJbDjSHDac7FY10zypgVbbh0KQFChNO4iaS4W8orA/640?wx_fmt=png&from=appmsg "")  
  
**漏洞描述：**DrayTek Vigor2960路由器版本1.4.4中存在一个需授权的命令注入漏洞漏洞细节及Poc当前已经公开,攻击者可以在cgi-bin/mainfunction.cgi路由中的doPPPoE函数的table参数中放置恶意命令,可能导致设备被完全接管,进而窃取敏感数据、发起进一步攻击或扰乱网络运行,DrayTek 已针对此漏洞并发布了补丁,建议用户采取升级固件、禁用远程访问、更改默认凭证和监控网络活动等措施以防范攻击。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ibhQpAia4xu01KdlKovDEZkJfACVDBXp7txwTt1QvShibQibHlgTs2MJcPH7lAiaXLrVeJkyCFKtG3ibnodS3MtGg0NA/640?wx_fmt=png&from=appmsg "")  
  
**修复建议:正式防护方案:**针对此漏洞,官方已经发布了漏洞修复版本,下载链接:https://www.draytek.co.uk/support/downloads/vigor-2960/安装前,请确保备份所有关键数据,并按照官方指南进行操作,安装后,进行全面测试以验证漏洞已被彻底修复,并确保系统其他功能正常运行。  
  
