#  Bp神级插件：二次开发，让API漏洞挖掘，效率倍增！   
原创 ZYC  无尽藏攻防实验室   2025-01-13 00:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84yA83erVx1s3r6pckbia7wyux16qNavjsnZCnEuJoKyyYdiaZuQfmx4oZf6XP1jmsvLg9gRtYolZI6A/640?wx_fmt=png&from=appmsg "null")  
  
# 网络安全为人民  
  
师傅们好👋：本公众号现在已开启对常读和星标的公众号展示大图推送，为了不错过我们的网络安全干货，请星标🌟我们。这样，您就能快速掌握最新动态，与我们共同守护网络空间！感谢您的关注和支持！💖  
## 工具介绍  
  
**APIKit**  
是  
APISecurity社区  
发布的第一个开源项目。  
  
**APIKit**  
是基于BurpSuite  
提供的JavaAPI  
开发的插件。  
  
**APIKit**  
可以主动/被动扫描发现应用泄露的API文档  
，并将API文档  
解析成BurpSuite  
中的数据包用于**API安全测试**  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQziaGHgwqUu1f9hO9xUrSQQstQvKZgibUjficBmExoKDFviaia7OdR3N6b9Q/640?wx_fmt=png&from=appmsg "")  
  
实际使用效果如图：  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQelSib2XaGLH5DQ9Vydk7PM6NqyTw719bo6x6ib1YaBPPAYXYtYqbL1ug/640?wx_fmt=png&from=appmsg "")  
- 该版本APIKit是对API-Security项目的APIKit1.0进行的二开，增加了扫描开关，避免直接打开burp乱扫被抓起来。  
  
- 修复了输出页面卡死的问题。  
  
- Do Target API Scan页面将cookie的输入框变大了一些，更美观的输入。  
  
### 安装  
  
打开BurpSuite  
页面,点击Extender(扩展)  
然后选择Add(添加)  
,添加APIKit.jar  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQVO8x2VxFUGdyQWxcRltEicdAsBo4sGROLYb1iciaKhDl5gD3Izu9E5GJA/640?wx_fmt=png&from=appmsg "")  
  
然后APIKit会对进入到BurpSuite  
的流量进行被动扫描。解析完成后可以在APIKit面板查看结果，同样Burpsuite的DashBoard也会有issue提示。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQelSib2XaGLH5DQ9Vydk7PM6NqyTw719bo6x6ib1YaBPPAYXYtYqbL1ug/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQv2lic6K83c3wZkN0moiaqacKHgLeloXfrxXVE9V4DHCW1viatjVVKVqCA/640?wx_fmt=png&from=appmsg "")  
### API技术指纹支持  
  
APIKit v1.0支持的API技术的指纹：  
- • GraphQL  
  
- • OpenAPI-Swagger  
  
- • SpringbootActuator  
  
- • SOAP-WSDL  
  
- • REST-WADL  
  
### 配置  
  
默认情况下Request和Cookie都不开启。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQ6IAeADqcSIb0aXeNc3dGEy1libezVABg9YbYPOK68SL6ETHlGkgicc2Q/640?wx_fmt=png&from=appmsg "")  
#### Send with Cookie  
  
开启Cookie，可以把响应包的Cookie存下来，生成请求的时候保留Cookie。  
#### Auto Request Sending  
  
开启对API的请求，注意开启API请求后。你需要明确以下几点：  
  
**1. 本工具仅面向合法授权的企业安全建设行为，如您需要测试本工具的可用性，请自行搭建靶机环境。**  
  
**2. 在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。请勿对非授权目标进行请求。**  
  
**3. 如您在使用本工具的过程中存在任何非法行为或造成其他损失，您需自行承担相应后果，我们将不承担任何法律及连带责任。**  
  
**4. 在安装并使用本工具前，请您务必审慎阅读、充分理解各条款内容，限制、免责条款或者其他涉及您重大权益的条款可能会以加粗、加下划线等形式提示您重点注意。 除非您已充分阅读、完全理解并接受本协议所有条款，否则，请您不要安装并使用本工具。您的使用行为或者您以其他任何明示或者默示方式表示接受本协议的，即视为您已阅读并同意本协议的约束。**  
  
选择开启Auto Request Sending  
后，可以对子API进行自动化鉴权测试，快速发现API未授权访问漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQ12DsCLsrKg4Xg5BpndReCiadQl8W3u6blMou1v5fYKarjXDUVysXFtA/640?wx_fmt=png&from=appmsg "")  
#### Clear history  
  
点击清除所有API文档记录。  
### 被动扫描  
  
默认情况下流经BurpSuite的流量都会进行API探测解析和扫描。  
### 主动扫描  
#### Do Auto API scan  
  
**Do Auto API scan**  
可以指定任意一个请求进行API指纹探测。  
  
在任何一个Burpsuite可以右键打开更多选项的页面中，都可以**点击右键**  
，选择**Do Auto API scan**  
来发起一次主动扫描，进行API指纹探测。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQAuJ9bicrhTjwPDr71fibEbQ4zISqozu83Of873EzWB4Kxcvj0CPIrDfw/640?wx_fmt=png&from=appmsg "")  
#### Do Target API Scan  
  
**Do Target API scan**  
可以指定任意API技术、任意BasePath、任意API文档Path、和任意Header进行API请求的生成和探测。  
  
在任何一个Burpsuite可以右键打开更多选项的页面中，都可以**点击右键**  
，选择**Do Target API scan**  
来打开选项框。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQaqN0ll8gUTEkmS60MsEWwPLoMN4THy6jLW6PGkwaSpDexKUU6YJrTQ/640?wx_fmt=png&from=appmsg "")  
  
填写指定任意API技术、任意BasePath、任意API文档Path、和任意Header，再点击Scan进行API请求的生成和探测。  
  
**注意BasePath要以/结尾。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQLOZ016xiahib0FpZbDUJh0iaUSX4S4BWBvQHzuXo3DR2zjy1BIMh9Kic6w/640?wx_fmt=png&from=appmsg "")  
### API漏洞自动扫描  
  
所有与BurpSuite  
联动的工具均可联动APIKit。比如xray。  
#### BurpSuite配置  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQKJNnKRDB4sL4p5et42Jv0sfeRBXXMmhe2PXNYTicswaYgrEicW1zu2qA/640?wx_fmt=png&from=appmsg "")  
#### xray配置  
  
shell  
```
.\xray.exe webscan --listen 127.0.0.1:8880 --html-output test.html
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84z5oCmiaASNCLw2nONdV0LCQvQKOgTn8XzSD59ZSIqISgbxZ72mfgYGkBJP8IrW3SUv73EVAyamCBw/640?wx_fmt=png&from=appmsg "")  
### 更多实用功能  
- • Fuzz鉴权绕过漏洞  
  
- • 检测请求返回包中敏感信息  
  
- • 发现js中泄露的API  
  
- • 常见数据解析依赖库识别，比如Fastjson等  
  
- • 更多实用功能...  
  
## 工具获取  
```
公众号回复20250109获取工具
```  
  
  
   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OKTibHnkK84yA83erVx1s3r6pckbia7wyun1qzrrxZGmnRXgZc4l1xUFiaXBEgqxg05W0uO7PT4r0WG8u5fibG1bdw/640?wx_fmt=png&from=appmsg "")  
  
  
免责声明：  
  
无尽藏攻防实验室（本文公众号）的技术文章仅供学习参考，禁止用于其他！！！未经授权请勿利用文章中的技术资料对任何计算机系统进行入侵操作。由于传播、利用此文所提供的信息而造成的直接或间接后果和损失，均由使用者本人负责，无尽藏攻防实验室及作者不为此承担任何责任。如有侵权烦请告知,我们会立即删  
除  
文章并致歉，感谢您的理解和支持！  
  
使用前请遵守法律法规，使用本文章内容及POC等资源默认代表自愿遵守国家法律并由使用者本人承担一切法律后果。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/OKTibHnkK84yA83erVx1s3r6pckbia7wyuZCw2OVWY5X5ltH671MNxzmAayviaVEpzLcD3ZKILLia7aKU9yLQFy7eA/640?wx_fmt=gif&from=appmsg "")  
  
  
   
  
   
  
   
  
   
### 参考文章  
  
https://www.cnblogs.com/mr-ryan/p/17774683.html  
  
https://github.com/XF-FS/APIKit  
  
