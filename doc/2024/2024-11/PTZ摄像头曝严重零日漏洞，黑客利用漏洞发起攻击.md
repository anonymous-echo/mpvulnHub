#  PTZ摄像头曝严重零日漏洞，黑客利用漏洞发起攻击   
 网络安全与人工智能研究中心   2024-11-02 15:17  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/ezpQRXtYHibw4dySDkrQpo0dd5dnR2u37gPCTjvia4VEdTaymicjbuMnVtb2CjAONY915picE4e1u4aN6icDNaSIk9Q/640?wx_fmt=gif "")  
  
近日，安全研究机构GreyNoise披露，PTZOptics品牌的PTZ摄像头存在两个严重的零日漏洞，编号为CVE-2024-8956和CVE-2024-8957，黑客正在积极利用这些漏洞发起网络攻击。**PTZ摄像头**因其集成的平移(Pan)、倾斜(Tilt)和变焦(Zoom)功能，**在工业、医疗保健、商务会议、政府和法庭等多种环境中被广泛使用。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibzecYczooJ19bUtWllzlYOgaq2fP2jo0SzwY7hhZlRezlZz8kYIzZHjrWhdqpGpTibTicUuYoJMsKlg/640?wx_fmt=png&from=appmsg "")  
  
**漏洞详情**  
CVE-2024-8956是“lighthttpd”Web服务器中的一个弱身份验证问题，未经授权的用户可以在没有授权标头的情况下访问CGI API，这可能导致用户名、MD5密码哈希值和网络配置的泄露。CVE-2024-8957则是由“ntp.conf”中的输入清理不足引起的，攻击者可以通过特制的有效负载插入用于远程代码执行的命令，完全控制摄像头或导致视频源中断。  
  
**影响与风险**  
受影响的是基于Hisilicon Hi3516A V600 SoC V60、V61和V63的支持NDI的摄像头，运行早于6.3.40的VHD PTZ相机固件版本。这些漏洞可能导致摄像头被完全接管、机器人感染、转向连接在同一网络上的其他设备或视频源中断。  
  
  
**修复与建议**  
  
PTZOptics已于9月17日发布了安全更新，但部分型号如PT20X-NDI-G2和PT12X-NDI-G2因已达到使用寿命而未获得固件更新。对于这些型号的用户，建议尽快升级到最新的固件版本，并持续监控网络活动以检测任何异常，同时采取额外的安全措施，如更改默认凭据、限制远程访问和强化身份验证机制，以减少潜在的风险。  
  
  
资讯来源：bleepingcomputer  
  
![](https://mmbiz.qpic.cn/mmbiz_png/ezpQRXtYHibw4dySDkrQpo0dd5dnR2u37LOW9y4urp43vAdtNYM42sbWic0ZPL8M5x6Y9J6nU38zHlxeXCbpm8eQ/640?wx_fmt=png "")  
  
来源｜“看雪学苑”公众号  
  
编辑｜音叶泽  
  
审核｜秦川原  
  
  
