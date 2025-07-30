#  TP-Link智能灯泡漏洞可窃取目标WiFi密码   
ang010ela  嘶吼专业版   2023-08-24 12:22  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/wpkib3J60o297rwgIksvLibPOwR24tqI8dGRUah80YoBLjTBJgws2n0ibdvfvv3CCm0MIOHTAgKicmOB4UHUJ1hH5g/640?wx_fmt=gif "")  
  
研究人员在TP-Link Tapo智能灯泡和APP中发现4个安全漏洞，可用于窃取目标WiFi密码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibNxWjKibCgKgKTiadTJ4DXObIYnRkrVdvPE5ayJQuuuYxwzLQ3lnwpmml2CVDBYCaI3Fk2VDj9sJRA/640?wx_fmt=png "")  
  
TP-Link Tapo L530E是一款销量很高的智能灯泡，TP-link Tapo APP是一款智能设备管理应用程序，谷歌应用商店下载量超过1000万。来自意大利和英国的研究人员分析了这款智能灯泡和控制应用程序的安全性，并在其中发现了4个安全漏洞，攻击者利用这些漏洞可以窃取目标的WiFi密码。漏洞影响数百万智能物联网设备，使得用户数据传输和认证存在风险。  
# 智能灯泡漏洞  
  
第一个漏洞是Tapo L503E智能灯泡中的认证不当引发的，攻击者可以在密钥交换过程中假冒设备，漏洞CVSS评分8.8分。攻击者利用该漏洞可以提取Tapo用户密码并操纵Tapo设备。  
  
第二个漏洞是硬编码的校验和共享秘密引发的，漏洞CVSS评分7.6分。攻击者可以通过暴力破解或反编译Tapo应用程序的方式获取校验和共享秘密。  
  
第三个漏洞是对称加密过程中缺乏随机性引发的，该漏洞使得所使用的加密方案可预测。  
  
第四个漏洞是未对接收的消息的新鲜性进行检查，session key（会话密钥）的有效性达到了24小时，攻击者在会话密钥有效期内可以发起重放攻击。  
# 攻击场景  
  
对用户影响最大的攻击场景是利用漏洞1和漏洞2来假冒灯泡，并提取Tapo的用户账户信息。然后攻击者可以访问Tapo app，并提取受害者的WiFi SSID和密码，并访问所有连接到该WiFi网络的设备。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibNxWjKibCgKgKTiadTJ4DXObXt37odMM0I3PuyWmRWK0Y6UAibrsp1F2S2QcqYkZVhRKUDC2e3W8pqA/640?wx_fmt=png "")  
  
图 假冒攻击图  
  
要实现假冒攻击，需要设备处于设置模式。但攻击者也可以通过去除灯泡授权的方式迫使用户重新对灯泡进行设置。  
  
另外一个攻击类型是中间人攻击（MITM）。利用漏洞1和拦截和操作APP和灯泡之间的通信，然后获取最后用户数据交换的RSA加密密钥。  
  
中间人攻击还可以在WiFi设置阶段对未配置的Tapo设备发起，通过桥接2个不同网络、路由发现消息等方式，最终提取base64编码的Tapo的密码、SSID、WiFi密码等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibNxWjKibCgKgKTiadTJ4DXObibWCphHjoWN2of7Jq015loSZpsaQGftMDd6icoZvDLvLddSc1libq81tA/640?wx_fmt=png "")  
  
图 MITM攻击图  
  
最后，利用漏洞4发现重放攻击，重返之前嗅探到了可以改变灯泡功能的消息。  
# 漏洞补丁和修复  
  
研究人员已将相关漏洞提交给了TP-Link，厂商也告知研究人员已经修复了相关漏洞。但论文中未给出详细的漏洞和补丁信息，以及受影响的版本。  
  
论文下载地址：https://arxiv.org/pdf/2308.09019.pdf  
  
参考及来源：https://www.bleepingcomputer.com/news/security/tp-link-smart-bulbs-can-let-hackers-steal-your-wifi-password/  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibNxWjKibCgKgKTiadTJ4DXOborMluZyqByLibm3Am2vxz6wQkdSbv6cHTVC32SwDmUVP7ykcF3dfUtQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wpkib3J60o2ibNxWjKibCgKgKTiadTJ4DXObhDf1gtS9pg5yatoTER6Mr4ZCgmXhS7daAibnFLkB9hxhecZPZEf1cOQ/640?wx_fmt=png "")  
  
  
