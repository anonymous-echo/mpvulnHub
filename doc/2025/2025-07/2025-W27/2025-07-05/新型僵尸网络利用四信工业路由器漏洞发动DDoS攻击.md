> **原文链接**: https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324483&idx=3&sn=1ef1f6e0a656c9697273135ef8bdf2d5

#  新型僵尸网络利用四信工业路由器漏洞发动DDoS攻击  
 FreeBuf   2025-07-05 11:01  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vmFJwOZAEXM3U7RfUshsesp6hbCbpDoicjWhcOtTh46XtYicHwub3ASVw/640?wx_fmt=jpeg "")  
  
  
FortiGuard实验室近日发现一个名为RondoDox的隐蔽且高度自适应的僵尸网络，该网络正在积极利用两个关键漏洞——CVE-2024-3721和CVE-2024-12856，借助包括四信  
F3x24和F3x36在内的工业路由器产品发动攻击。  
  
  
据Fortinet威胁情报团队分析，RondoDox采用"高级逃逸与持久化技术"针对未打补丁的Linux设备，对设备安全及整体网络完整性构成严重威胁。  
  
  
**Part01**  
## 漏洞利用细节  
##   
  
RondoDox通过两个独立漏洞实现远程命令执行：  
  
****  
CVE-2024-12856：  
针对四信（Four-Faith）F3x24和F3x36路由器，已认证的攻击者可滥用apply.cgi接口在修改系统时间时执行任意命令  
  
  
CVE-2024-3721：  
影响TBK品牌的DVR-4104和DVR-4216等型号，源于对/device.rsp?opt=sys&cmd=___S_O_S_T_R_E_A_MAX___路径的不当处理，攻击者可通过操纵mdb和mdc参数注入操作系统命令  
  
  
FortiGuard指出："RondoDox整合了定制化库文件，并伪装成游戏平台或VPN的流量以规避检测"。  
  
  
**Part02**  
### 技术特征演变  
  
  
该恶意软件最初针对ARM和MIPS架构的Linux系统，现已扩展至x86-64、Intel 80386、PowerPC、AArch64等多种平台。其Shell脚本下载器会检测可写目录的执行权限，在安装有效负载的同时删除日志记录以保持隐蔽。  
  
  
通过基于XOR的混淆算法解码配置后，恶意软件会植入多层持久化脚本：  
- 修改http://etc/rcS  
等系统启动文件  
  
- 操纵crontab定时任务  
  
- 创建/etc/rc3.d/S99rondo等符号链接确保重启后控制  
  
  
![RondoDox僵尸网络](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibAnU4vEr36WbU2bsWK319vYnJJDiaQ2KTfptrcwjk9HPBlRWUicJkjomgMBNsZtzvnvKUqlAUFI3cg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
**Part03**  
### 反取证与破坏行为  
  
  
RondoDox会扫描系统并终止以下进程：  
- 取证工具：wireshark、gdb、tcpdump  
  
- 竞争性恶意软件：xmrig、Redtail  
  
更具破坏性的是，它会将iptables、passwd、shutdown等关键系统程序重命名为随机字符串，既破坏系统功能又增加应急响应难度。  
  
  
**Part04**  
### 攻击实施阶段  
  
  
建立持久化后，恶意软件将解码C2服务器地址83[.]150[.]218[.]93并建立通信，随后可发起三类DDoS攻击：  
- HTTP洪水攻击  
  
- UDP泛洪攻击  
  
- TCP连接耗尽攻击  
  
其流量会伪装成Minecraft、Discord、Valve、Fortnite、OpenVPN等合法平台的通信数据包。FortiGuard强调："通过仿冒这些正规服务，恶意软件极大增加了防御者有效识别和拦截其流量的难度"。  
  
  
**Part05**  
### 威胁评估  
  
  
与普通Mirai变种不同，RondoDox具有以下显著特征：  
- 多层持久化机制  
  
- 合法服务流量模拟  
  
- 系统性破坏能力  
  
FortiGuard最终结论指出："RondoDox是采用高级逃逸技术的复杂新兴恶意软件威胁...凸显了及时为受影响系统打补丁的极端重要性"。  
  
  
**参考来源：**  
  
RondoDox: Sophisticated Botnet Exploits TBK DVRs & Four-Faith Routers for DDoS Attacks  
  
https://securityonline.info/rondodox-sophisticated-botnet-exploits-tbk-dvrs-four-faith-routers-for-ddos-attacks/  
  
  
###   
###   
###   
  
**推荐阅读**  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651324107&idx=1&sn=f89429997e0347cfe1580cc8ca6e858b&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
   
  
