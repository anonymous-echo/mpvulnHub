> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NjY2MTI3Mg==&mid=2247500442&idx=1&sn=52027ffabc04dda5db949e53107c5e7c

#  Kali Linux 2025.2发布：智能手表Wi-Fi注入、Android广播和黑客工具  
原创 铸盾安全  河南等级保护测评   2025-06-13 23:24  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoG234xzvpCJUGqsiaYL6u6ZjEn4meuUWuos95qS5niakglBiaCUkSfoA52ErnO9mjSa1ibZ8PCvnKjP7g/640?wx_fmt=png&from=appmsg "")  
  
随着 Kali Linux 2025.2 的发布，渗透测试社区获得了重大升级，这标志着这一重要网络安全平台发展的又一个里程碑。  
  
此最新版本引入了突破性的智能手表功能、完全重新设计的菜单系统以及一套全面的新工具，有望增强红队和蓝队的行动。  
  
Kali Linux 2025.2 中最令人兴奋的发展可能是推出了第一款具有实际无线注入支持、新工具和 Android 无线电的智能手表。  
  
经过三年的开发，TicWatch Pro 3（所有配备bcm43436b0 芯片组的版本）现在支持完整的无线注入功能，包括取消身份验证攻击和 WPA2 握手捕获。  
  
这一突破是通过开发人员和 NexMon 团队之间的卓越合作实现的，代表了便携式渗透测试能力的重大进步。  
## Kali Linux 2025.2 新功能  
  
Kali Linux 2025.2 具有完全重新设计的菜单系统，它放弃了传统的 BackTrack 结构，转而采用MITRE ATT&CK框架。  
  
此次重组使得红队和蓝队的工具发现更加直观，解决了工具组织和可访问性方面长期存在的问题。  
  
新系统完全自动化，取代了以前的手动管理方法，因为随着工具收集的增加，维护变得越来越困难。  
  
该版本对桌面环境进行了重大改进，GNOME 升级至 481 版本。主要增强功能包括通知堆叠、性能改进、动态三重缓冲、增强的图像查看器功能、数字健康功能和 HDR 支持。  
  
KDE 用户将获得 Plasma 6.3，其特点是对分数缩放进行了重大改进，通过夜灯提高了屏幕色彩准确度，并增强了系统监控功能。  
  
值得一提的是，新的 GNOME VPN IP 扩展功能现已推出，它可以直接在面板中显示当前 VPN 连接的 IP 地址，并支持一键剪贴板复制。这项由社区贡献的功能与之前仅在 Xfce 环境中提供的类似功能类似。  
  
通过集成 BloodHound 社区版， Active Directory侦察功能得到显著提升。此次更新包含一整套采集器：azurehound、bloodhound-ce-python 和 sharphound。  
  
此次升级提供了更流畅的界面、更好的性能以及增强的映射复杂 Active Directory 环境的功能。  
  
Kali Linux 2025.2 版本引入了一项预告功能，展示了在 Android 无线电系统上运行的 Kali NetHunter KeX。这项开发似乎代表了同类产品中的首个用例，它作为即将推出的 Android Auto 支持的预览，可与任何支持 Android Auto 的非 Android 主机兼容。  
  
Android 无线电集成利用了 Kali NetHunter 桌面体验 (KeX) 技术。KeX 允许用户运行完整的 Kali Linux 桌面会话，并支持通过 HDMI 或无线屏幕投射进行屏幕镜像。  
  
在 Android 无线电环境中，您可以使用 Android 主机作为 KeX 客户端连接到运行 KeX 服务器的手机。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoG234xzvpCJUGqsiaYL6u6ZjG81AhjdtLtOlJm2m0LWUChGRGvgpibRVGVRPtUYjhuH2xjnMgeGvb3g/640?wx_fmt=png&from=appmsg "")  
  
Kali Linux 2025.2 向网络存储库引入了 13 个新工具，包括用于 Microsoft Azure 数据收集的 azurehound、用于固件分析的 binwalk3 和用于智能单词表生成的 bopscrk。  
  
其他工具包括用于 CRLF 漏洞扫描的 crlfuzz、用于位置无关 shellcode 生成的 donut-shellcode 和用于 GitHub 存储库分析的 gitxray。  
  
NetHunter 平台获得了重大更新，包括推出全面的汽车黑客工具集 CARsenal（以前称为 CAN Arsenal）。  
  
新的内核支持扩展到更多设备，包括小米 Redmi 4/4X 和 Redmi Note 11。ARM 单板计算机支持已得到整合，Raspberry Pi 5 现已由统一的 64 位映像支持，并升级到基于 6.12 的内核。  
  
Kali Linux 2025.2 代表了渗透测试能力的重大进步，结合了创新的硬件支持和全面的软件改进。  
  
仅智能手表的 Wi-Fi 注入功能就使该版本成为移动安全评估的游戏规则改变者，而重组的菜单系统和扩展的工具集合确保了全球网络安全专业人士的持续相关性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/sNicKB84ZxoG234xzvpCJUGqsiaYL6u6ZjBhBRO0h2icpVAR8Q0Yd0cBHd8D2iaMmCTyJbLK9vceOqaIhVUZXWpB6Q/640?wx_fmt=png&from=appmsg "")  
  
官方的 Kali Linux 2025.2 镜像现在可以通过 kali 的主要下载门户获取，该门户提供经过测试且质量有保证的发布镜像。  
  
用户可以选择下载 Kali Linux 2025.2 的新映像或升级其当前安装以利用最新的功能和增强功能。  

```
┌──(kali㉿kali)-[~] 
└─$ echo &#34;deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware&#34; | sudo tee /etc/apt/sources.list 
[...] 

┌──(kali㉿kali)-[~] 
└─$ sudo wget https://archive.kali.org/archive-keyring.gpg -O /usr/share/keyrings/kali-archive-keyring.gpg 
[...] 

┌──(kali㉿kali)-[~] 
└─$ sudo apt update && sudo apt -y full-upgrade 
[...] 

┌──(kali㉿kali)-[~] 
└─$ cp -vrbi /etc/skel/. ~/ 
[...] 

┌──(kali㉿kali)-[~] 
└─$ [ -f /var/run/reboot-required ] && sudo restart -f
```

  
检查版本  

```
┌──(kali㉿kali)-[~] 
└─$ grep VERSION /etc/os-release 
VERSION_ID=&#34;2025.2&#34; 
VERSION=&#34;2025.2&#34; 
VERSION_CODENAME=kali-rolling 

┌──(kali㉿kali)-[~] 
└─$ uname -v 
#1 SMP PREEMPT_DYNAMIC Kali 6.12.25-1kali1 (2025-04-30) 

┌──(kali㉿kali)-[~] 
└─$ uname -r 
6.12.25-amd64
```

  
  
