#  手把手玩转路由器漏洞挖掘系列-WIFI安全威胁   
原创 nil  山石网科安全技术研究院   2024-04-17 13:53  
  
#   
  
**基本介绍**  
  
  
**1.1 概要**  
  
Wi-Fi是一种无线技术，用于在电子设备之间进行无线网络连接。Wi-Fi协议指的是一系列标准，如802.11a、802.11b、802.11g、802.11n、802.11ac和802.11ax，它们规定了无线网络设备之间通信的规则和方式。这些协议定义了无线信号的频率、速率、传输方式等，以确保设备可以在同一无线网络上进行有效通信。Wi-Fi协议的不断发展使得无线网络连接变得更快速、更稳定，同时提供更好的覆盖范围和连接质量。  
###   
  
**1.2 协议标准**  
- 802.11a  
  
工作频率 - 5Ghz频段  
  
传输速率 - 54Mbps  
- 802.11b  
  
工作频率 - 2.4Ghz频段  
  
传输速率 - 11Mbps  
- 802.11g  
  
工作频率 - 2.4Ghz频段  
  
传输速率 - 54Mbps  
- 802.11n  
  
- 802.11ac  
  
WIFI - 第五代标准  
  
工作频率 - 5Ghz频段  
- 802.11ax      
  
WIFI - 第六代标准  
###   
  
**1.3 协议建立过程**  
- 扫描 - 扫描周围WIFI信道  
  
- 关联请求 - 选择网络发送关联请求  
  
- AP响应 - 接收到关联请求后，发送关联响应给设备  
  
- 认证 - 设备与接入点验证，确保设备有权限连接到网络  
  
- 关联确认 - 发送关联确认给设备，表示连接已建立  
  
- IP分配 - 获取IP地址，以便在网络中进行通信  
  
- 数据传输 - 设备与接入点之间开始数据传输，实现无线通信  
  
- 断开连接 - 设备或接入点可以随时断开连接，结束通信  
  
**1.4 协议报文**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSiaYtUYC7oLBBzAGrOEu4ja4Av2EnMVDYdE61340p1CZzhZ9MItf3SZWUd4q0AXj2AWDI3mhB543w/640?wx_fmt=png&from=appmsg "")  
- 帧控制字段（Frame Control Field）：包含帧类型、子类型和帧控制信息。  
  
- 目标地址（Destination Address）：指示接收报文的设备的MAC地址。  
  
- 源地址（Source Address）：指示发送报文的设备的MAC地址。  
  
- 接入点地址（Access Point Address）：指示接入点的MAC地址（仅在与接入点通信时存在）。  
  
- 序列控制字段（Sequence Control Field）：用于管理数据包的顺序和重传。  
  
- 帧体（Frame Body）：包含实际传输的数据或管理信息。  
  
- FCS字段（Frame Check Sequence）：用于检测数据传输过程中是否发生错误。  
  
**安全风险**  
  
- 弱密码  
  
使用弱密码或默认密码的Wi-Fi网络容易受到密码破解攻击，黑客可以通过暴力破解手段获取网络访问权限。  
- 中间人攻击  
  
黑客可以在用户和Wi-Fi网络之间插入自己的设备，窃取传输的数据或篡改数据。  
- 无线劫持      
  
黑客可以通过伪造Wi-Fi信号来欺骗设备连接到恶意网络，从而进行攻击。  
  
**威胁分析**  
  
  
**3.1 暴力破解**  
  
无线网络设备由于配置不当可能导致无线加密被破解。  
  
**加密方式**  
- WEP加密 - 加密比较老旧，现在的路由器已经很少使用此类加密方式，破解只需要大量的数据包即可  
  
- WPA/WPA2 PSK加密 - 加密很安全，破解的方式是抓握手包然后跑字典  
  
#### 3.1.1 破解工具    
  
Aircrack是一套用于破解WEP和WPA的工具套装，一般用于无线网络的密钥破解，从而非法进入未经许可的无线网络。  
#### 3.1.2 破解过程    
  
常用命令  
```
shell $ iwconfig wlan0 down $ iwconfig wlan0 mode moniter $ iwconfig wlan0 up
```  
  
- 扫描周围WIFI信号  
  
```
shell $ airodump-ng wlan0
```  
  
  
附近WIFI信号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSiaYtUYC7oLBBzAGrOEu4jasrHc32qic58Dpx3KclbYVC5frPPzWB9FlfhjGFeZHibPW39A6Rz3zbAQ/640?wx_fmt=png&from=appmsg "")  
- 监听数据包  
  
```
shell $ airodump-ng -w freedom -c 11 --bssid mac地址 wlan0 --ignore-negative-one
```  
  
- 伪造报文  
  
```
shell $ airodump-ng -w freedom -c 11 --bssid mac地址 wlan0 --ignore-negative-one
```  
  
- 报文破解      
  
```
shell $ airodump-ng -w freedom -c 11 --bssid mac地址 wlan0 --ignore-negative-one
```  
  
  
密码破解  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSiaYtUYC7oLBBzAGrOEu4jabhpXicTTTEVicMsxf0y9Qrjv7mzl0xtlWzbG5zGEibkxWTkeD4hpD8ia7w/640?wx_fmt=png&from=appmsg "")  
  
**3.2 流量获取**  
#### 3.2.1 获取工具    
  
tcpdump是一个常用的网络抓包工具，可以在命令行下对网络数据包进行捕获、分析和显示。它可以监视网络接口上进出的数据包，并将其以文本形式输出到终端上，用户可以根据需要进行进一步的分析和调试。  
#### 3.2.2 获取过程    
  
条件 - 已获取设备最高权限  
```
shell $ tcpdump -i <interface> -w test.pcap
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnSiaYtUYC7oLBBzAGrOEu4jaYVd8Al0tLXJeG58Cao6BibGrryIK7ydlLLMnQ7dsbPf5xctM0joPKIQ/640?wx_fmt=png&from=appmsg "")  
  
  
**安全风险**  
  
  
①代理跳板:黑客可以利用路由器的某些服务接管路由器的设备权限。  
  
②内网渗透:边界设备开启UPNP没有做好鉴权处理，会导致攻击者通过该服务队内部网络进行内部渗透。  
  
**攻击面**  
  
- 通过密码破解获  
得设备WIFI凭据，对设备进一步渗透。  
  
- 通过挖掘设备漏洞，获得设备权限，后续可以监听用户流量。  
  
**总结**  
  
  
为了保护Wi-Fi网络安全，建议采取以下措施：使用强密码、启用加密、定期更新设备固件、避免连接到公共无线网络时传输敏感信息等。对于企业和组织来说，还应该实施网络安全策略，以确保Wi-Fi网络的安全性。     
  
