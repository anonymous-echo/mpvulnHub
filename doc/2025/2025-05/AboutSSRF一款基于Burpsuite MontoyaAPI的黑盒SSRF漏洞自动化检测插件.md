#  AboutSSRF一款基于Burpsuite MontoyaAPI的黑盒SSRF漏洞自动化检测插件   
hnking-star  渗透安全HackTwo   2025-05-21 16:01  
  
0x01 工具介绍SSRF_Detector是一款基于Burpsuite MontoyaAPI的黑盒SSRF漏洞自动化检测工具，用于检测无回显&全回显SSRF漏洞，提供了多种功能供用户自定义，包括但不限于关键字配置，Payload配置以及检测字符串配置。注意：现在只对常读和星标的公众号才展示大图推送，建议大家把渗透安全HackTwo"设为星标⭐️"否则可能就看不到了啦！#渗透安全HackTwo  
**下载地址在末尾**  
0x02 功能简介### 插件功能配置  
###   
### 扫描流量配置  
  
**(1) 被动扫描：**  
  
不建议开启此功能，Burpsuite  
自带扫描器会触发企业SRC内部告警导致IP被封禁  
  
**(2) HTTP history流量扫描：**  
  
扫描Proxy  
中HTTP history  
模块中的流量，利用RequestResponseFilter  
过滤器筛选出存在关键参数的流量进行SSRF  
漏洞检测  
  
**(3) Repeater流量扫描：**  
  
扫描Repeater  
模块中发送过的数据包流量，利用RequestResponseFilter  
过滤器筛选出存在关键参数的流量进行SSRF  
漏洞检测  
#### 缓存文件配置  
#### 用户可以自定义缓存文件位置，扫描过的流量信息会自动存储在缓存文件中，避免对某一流量包进行重复无效扫描  
### 扫描参数配置  
###   
### 关键字配置  
### 用户可以自定义添加/删除流量检测关键字，以关键字url为例，若某一流量包如下所示：  
```
GET /ssrf.php?url=/imgRes/user.pngHost: xxx.xx.xx.xxxCookie: PHPSESSID=xxxxxxxxxxxxReferer: xxx.xx.xx.xxx
```  
### 则会匹配到url=/imgRes/user.png中的url参数，并对此流量请求包进行SSRF漏洞检测  
#### Payload 配置  
#### 插件默认提供两种无回显SSRF漏洞自动化检测方式  
  
**(1) collaborator：**  
  
利用Burpsuite  
内置的Collaborator  
模块进行无回显SSRF  
漏洞检测，但是很多厂商WAF  
会将Collaborator  
模块的Payload  
写进黑名单，导致漏检，于是提供了第二种检测方式 -> DNSLog  
  
**(2) dnslog：**  
  
利用广为人知dnslog  
平台(http://dnslog.cn  
)进行无回显SSRF  
漏洞检测，自动化获取dnslog  
的Payload  
和响应信息  
#### 检测字符串配置  
#### 用于证明全回显SSRF漏洞存在  
  
用户在挖掘企业SRC进行黑盒测试时，企业通常会提供全回显SSRF  
测试靶机，靶机的回显通常为一个标志性字符串，如flag{tencent_ssrf_vuln}  
  
二者起到对应关系  
```
http://ssrf.tencent.com/flag.html ---> flag{tencent_ssrf_vuln}
```  
  
于是可以在Payload  
配置模块和检测字符串配置模块添加这种对应关系  
  
![image-20250403140436720](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7KzKYPXolkvsK6XjtBe05icJl81gvfB5EMsmD9BsC9glbRdUBfqicCo75MwqUqFcPBAplWVBz3DKjg/640?wx_fmt=png&from=appmsg "")  
### 扫描流量概览  
### 这里会显示所有包含检测关键字的流量请求包  
  
![image-20250403140712482](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7KzKYPXolkvsK6XjtBe05icb3TSj95uTln3PAa4QNrsu3diaH3tFgr0P9sXjvYpcibqm60bIwu5zoAw/640?wx_fmt=png&from=appmsg "")  
### 疑似存在漏洞  
### 若配置的Payloads列表中有任意大于等于1个Payload探测存在SSRF漏洞成功，该流量数据包的状态(Status)就会自动更新为 "疑似漏洞"，并在 "疑似存在漏洞" 列表中显示  
  
每一个检测存在SSRF  
漏洞的Payload  
都会单独显示，如下所示  
  
**(1) Collaborator payload检测存在SSRF漏洞：**  
  
![image-20250403141634651](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7KzKYPXolkvsK6XjtBe05icmdh3rtzWaJ6pTGAiaFwGD6IEPjDxfMiaBSf7Ik7hLicUnM0hrO2l4hLicQ/640?wx_fmt=png&from=appmsg "")  
  
**(2) DNSLog payload检测存在SSRF漏洞：**  
  
![image-20250403141726178](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7KzKYPXolkvsK6XjtBe05icUxJu6DBBsLxMn5ap2JQo4wc7hmncjPn6MwsOp9wGc9AezrSjeq2UDg/640?wx_fmt=png&from=appmsg "")  
  
**(3) 企业SRC 全回显SSRF靶机回显flag字符串：**  
  
![image-20250403142045779](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7KzKYPXolkvsK6XjtBe05ic0vDxThQRuegQPNEDZ14WRBo9o6PTNc3viceNalPIWg0hDcfmgb1TODQ/640?wx_fmt=png&from=appmsg "")  
##   
0x03 更新说明```
SSRF_Detector_v1.0.0为系列插件的第一个版本，提供以下功能：
(1) 用户自定义检测关键字
(2) 用户自定义检测payloads
(3) 在 Collaborator模块的基础上额外提供 dnslog测试提高检测容错率
(4) 提供自定义全回显SSRF验证字符串功能，以供在企业SRC黑盒测试中检测全回显SSRF漏洞
(5) 缓存文件，避免重复无效检测
```  
0x04 使用介绍## 📦jar下载后Burpsuite加载扩展即可使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq7OuEB2v6Ca1ymc8GQlbGMhkUpDyB2cIVCI0NYapN0pOEOWUAKtKib210diccrkwCoZVEf2ibiaiatqMKA/640?wx_fmt=png&from=appmsg "")  
##   
0x05 内部VIP星球介绍-V1.4（福利）        如果你想学习更多渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点欢迎加入我们内部星球可获得内部工具字典和享受内部资源和内部交流群，每1-2天更新1day/0day漏洞刷分上分(2025POC更新至3800+)，包含网上一些付费工具及BurpSuite自动化漏洞探测插件，AI代审工具等等。shadon\Quake\Fofa高级会员，CTFshow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复" 星球 "有优惠券名额有限先到先得！全网资源最新最丰富！（🤙截止目前已有1700多位师傅选择加入❗️早加入早享受）  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250522获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
一款快速识别网站指纹3W+的Google插件|「指纹猎手」  
  
