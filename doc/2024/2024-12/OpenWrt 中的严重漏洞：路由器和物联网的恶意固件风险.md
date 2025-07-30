#  OpenWrt 中的严重漏洞：路由器和物联网的恶意固件风险   
很近也很远  网络研究观   2024-12-14 15:59  
  
![](https://mmbiz.qpic.cn/mmbiz_png/yvLFKBRPQxOvUC5jYusB4W2bleAaTgkj8RbuOgJGbTyiaJtnLuI6zRGDxiaPzyFP0IyMnB9k1bcSg3R4d7nfZO2g/640?wx_fmt=png&from=appmsg "")  
  
用于创建自定义固件映像的 OpenWrt 参加的 Sysupgrade 功能中存在一个严重漏洞，可能允许分发恶意版本。****  
  
**OpenWrt是一个基于****Linux**的操作系统，专为路由器、接入点和物联网设备而设计。  
  
由于其定制功能以及对华硕、D-Link、Zyxel 等不同品牌设备的支持**，**该系统通常被用作**工厂固件的替代品。**  
  
漏洞 CVE-2024-54143（CVSS 评分：9.3）是  
 Flatt Security 专家在更新家庭路由器时发现的。  
  
该问题允许通过处理 sysupgrade.openwrt.org 服务的输入来执行任意命令。  
  
此外，还发现了服务运行中的第二个问题：使用**长度为 12 个字符的截断 SHA-256 哈希**来缓存程序集，这会降低安全机制的强度，从而允许使用自定义工具进行**强力碰撞**。  
  
这允许攻击者制作一个请求，重用在合法固件版本中找到的缓存密钥。  
  
这两个错误一起允许您修改固件映像并将其替换为恶意版本。  
  
私下举报后，OpenWrt团队立即禁用**sysupgrade.openwrt.org服务，修补漏洞，并于12月4日3小时内恢复平台**。  
  
开发人员确信该漏洞不太可能被利用，并且主下载服务器上可用的图像并未受到损害。  
  
不过，由于可用日志仅涵盖最近 7 天**，强烈建议所有用户更新其设备的固件。**  
  
