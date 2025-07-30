#  Mirai 恶意软件借 Edimax 相机 RCE 漏洞大肆传播   
山卡拉  嘶吼专业版   2025-03-17 14:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibovuRIMVDWna3ue7JnfaRECurLuVEkoiaxGxdjxcjcyIJ9jiaibc5ibibgBzwpRlRumEW01WiaH9Fz1t2w/640?wx_fmt=jpeg&from=appmsg "")  
  
Akamai 安全情报和响应团队（SIRT）近期发布警报，着重指出 Edimax 物联网（IoT）设备中存在严重的命令注入漏洞。该漏洞被编号为 CVE - 2025 - 1316，已被多个僵尸网络频繁利用，用于传播臭名昭著的 Mirai 恶意软件。Mirai 恶意软件向来以危害物联网设备、发动分布式拒绝服务（DDoS）攻击而闻名。  
# 漏洞概述  
  
CVE - 2025 - 1316 漏洞主要针对 Edimax 设备中的 /camera - cgi/admin/param.cgi 端点，攻击者能够借此将命令注入到 ipcamSource 参数内的 NTP_serverName 选项中。成功利用该漏洞需要使用默认凭据，例如 admin:1234。虽然 CVE 特别提及 Edimax 的 IC - 7100 网络摄像头，但实际上该漏洞可能影响范围更广的 Edimax 设备。  
  
Akamai SIRT 早在 2024 年 10 月初就在蜜罐中首次检测到针对此漏洞的攻击活动。  
  
![image-5.jpeg](https://mmbiz.qpic.cn/sz_mmbiz_jpg/wpkib3J60o2ibovuRIMVDWna3ue7JnfaREJnRsXsAK4eDibYPGVdV0ag4Hfrc8ebx2ufdiaW7GYiakHjhibGGRy0OOIw/640?wx_fmt=jpeg&from=appmsg "")  
  
Mirai恶意软件样本主要功能  
  
而该漏洞的概念验证（PoC）可追溯至 2023 年 6 月。最早的漏洞利用尝试出现在 2024 年 5 月，在 2024 年 9 月以及 2025 年 1 月至 2 月期间达到高峰。这些攻击源于不同的僵尸网络，其中就包括 Mirai 变种。  
# 漏洞代码示例  
  
此漏洞通过注入命令，在设备上执行 shell 脚本。以下是一个请求负载示例：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibovuRIMVDWna3ue7JnfaRETNDHTI2TSDS89tCARSJxH1l2kZ3JKByDEZnJowwywxrgXX9KicU9ibuA/640?wx_fmt=png&from=appmsg "")  
  
上述脚本会下载并执行针对 ARM、MIPS 和 x86 等不同架构的 Mirai 恶意软件变体。  
# 恶意软件执行命令  
  
恶意软件下载完成后，将通过以下命令执行：  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibovuRIMVDWna3ue7JnfaREKvFGAicj6QrzuxLEOJRWfSJvk0txgK5xzEuF5aibuHQGztHSJdCQmCAQ/640?wx_fmt=png&from=appmsg "")  
  
类似的命令也用于 MIPS 和 ARM 等其他架构。  
# Mirai 僵尸网络  
  
目前已发现两个不同的僵尸网络利用此漏洞：  
  
· 第一个僵尸网络：该僵尸网络利用漏洞下载并执行 curl.sh 脚本，通过 angela.spklove [.] com 和端口 3093 与命令和控制（C2）服务器进行通信。恶意软件执行时会打印 “VagneRHere”。  
  
· 第二个僵尸网络：此僵尸网络下载并运行 wget.sh 脚本，进而执行 Mirai 恶意软件。该恶意软件具备反调试功能，执行时会打印 “Hello, World!”。  
  
这两个僵尸网络还利用了其他几个已知漏洞，如 Docker API 漏洞以及影响 TOTOLINK 设备的 CVE - 2024 - 7214。  
# 缓解措施和建议  
  
为有效防范这些威胁，可采取以下措施：  
  
· 升级设备：将过时或易受攻击的设备更换为较新的型号。  
  
· 更改默认凭证：务必确保所有设备都设置强大且唯一的密码。  
  
· 监控网络：密切留意可疑活动，如异常的流量模式。  
  
· 实施安全措施：利用防火墙和入侵检测系统，阻止攻击尝试。  
  
鉴于 Mirai 恶意软件对物联网安全的持续威胁，及时了解相关信息并主动采取防范措施，对于保护物联网设备至关重要。  
  
参考及来源：https://gbhackers.com/edimax-camera-rce-vulnerability/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibovuRIMVDWna3ue7JnfaRE2iceUiaroL8d43ny5ib1I7qksxsXYlvSusIRd8qJwsWzDtictQaOTZFc1Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibovuRIMVDWna3ue7JnfaREI40o4gcZASh64K6LyDcyrmHEpichuu0Wxia5OZ2grWHIKKIgBGJ65Lxw/640?wx_fmt=png&from=appmsg "")  
  
  
