#  亚马逊Ring安卓app漏洞可窃取个人信息   
ang010ela  嘶吼专业版   2022-08-22 12:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
亚马逊Ring安卓app漏洞可以访问摄像头记录。  
  
Ring 是亚马逊运行的家用安全环境产品，包含户内外监控摄像头。其中Ring安卓APP下载次数超过1000万次。Checkmarx 安全研究人员在亚马逊Ring安卓APP中发现了一个安全漏洞，攻击者利用该漏洞可以截取受害者手机中的个人数据、位置信息、和摄像头记录。  
# 技术细节  
  
该漏洞位于com.ringapp/com.ring.nh.deeplink.DeepLinkActivity中，该activity在安卓manifest中是导出的，因此可以被相同设备上的其他应用访问。这些应用有可能是用户安装的恶意应用。  
  
该activity可以接受、加载、和执行来自任意服务器的web内容，因为intent的目标URL中包含字符串“/better-neighborhoods/”。研究人员用adb复制了有效的intent：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icD98x1PVQP513VPDOD5dWh8GibibkERfWL9tgnSqJSWrZeL9C1Iice23ru7lmwPfib5Z09dnB9x0PpqA/640?wx_fmt=png "")  
  
然后，攻击者控制的web页面就可以与WebView的JS接口进行交互，其中子域名为“ring.com” 或 “a2z.com”。  
  
研究人员在cyberchef.schlarpc.people.a2z.com上发现了一个反射性XSS漏洞，可以完成该攻击链。利用该漏洞，攻击者可以诱使受害者安装可以触发以下intent来完成攻击的恶意应用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icD98x1PVQP513VPDOD5dWh1EMwe1KOiaVylKnaE8zuv6CJOAAYXubRCWdyXibSLrLJ1GvD8gGT2Kew/640?wx_fmt=png "")  
  
Payload会重定向WebView到恶意web页面，该页面可以访问授予Authorization Token访问权限的JS接口——__NATIVE__BRIDGE__.getToken()，然后攻击者控制的服务器可以窃取Authorization Token。  
  
Authorization Token是一个Java Web Token (JWT)，还不足以授权对Ring的多个API的调用。授权强制使用rs_session cookie。  
  
但是该cookie可以通过调用https://ring.com/mobile/authorize加上有效的Authorization Token和对应的设备硬件ID来获得。研究人员发现，硬件ID也是硬编码在token中的。  
  
有了该token，就可能使用Ring API来提取用户的个人数据，包括全名、邮件地址、手机号码、以及其他Ring设备数据，比如地理位置、地址和录像。具体来说，使用的API包括：  
  
https://acount.ring.com/account/control-center –用来获取受害者的个人数据和设备ID  
  
https://account.ring.com/api/cgw/evm/v2/history/devices/{{DEVICE_ID}} – 用来获取设备数据和录像  
  
为进一步证明该漏洞的影响和危害性，研究人员证明了如何利用该服务来读取敏感信息，以追踪用户的移动。PoC视频参见：https://youtu.be/eJ5Qsx4Fdks  
# 漏洞影响  
  
该漏洞影响Ring v .51版本，包括安卓的3.51.0版本和iOS的5.51.0版本。亚马逊已于2022年5月27日修复了该漏洞。  
  
参考及来源：  
https://checkmarx.com/resources/checkmarx-blog/amazon-quickly-fixed-a-vulnerability-in-ring-android-app-that-could-expose-users-camera-recordings  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icD98x1PVQP513VPDOD5dWhEYrLH8EpUH8Tuerrz12CNPqrgV9f5PmSpdDTmEyvAujP3OKGibbb5QA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2icD98x1PVQP513VPDOD5dWhKYYHBnBSzkOq3ov4Yt3bBpGwSDZqKElWHdpJKaHsyctO8eZl9Aiaqyg/640?wx_fmt=png "")  
  
