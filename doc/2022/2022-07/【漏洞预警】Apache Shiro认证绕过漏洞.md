#  【漏洞预警】Apache Shiro认证绕过漏洞   
安识科技  SecPulse安全脉搏   2022-06-30 12:03  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ku0nsiagdhZ9kibMY9pUOGdBncITwAvicQeeuiaicSCVicKic2vwDia14DHgndlQTwHzB8M0PlShruddeHfkeorBjdotg/640?wx_fmt=png "")  
  
1. **通告信息**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PiapXScWtibK67XvgLiaz6hQibAvcPPHRqNZGYltRKU2WaibdTo9wtQafErQMNA34QBtGgQiazJibwGLlwwN2srxqxapw/640?wx_fmt=png "")  
  
  
  
近日，  
安识科技  
A-Team团队  
监测到一则   
Apache Shiro 组件存在认证绕过漏洞的信息，漏洞编号：CVE-2022-32532，漏洞威胁等级：高危。该漏洞是由于 RegexRequestMatcher 不正当配置存在安全问题，攻击者可利用该漏洞在未授权的情况下，构造恶意数据绕过 Shiro 的权限配置机制，最终可绕过用户身份认证，导致权限校验失败。  
  
对此，安识科技建议广大用户及时升级到安全版本，并做好资产自查以及预防工作，以免遭受黑客攻击。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ku0nsiagdhZ9kibMY9pUOGdBncITwAvicQeeuiaicSCVicKic2vwDia14DHgndlQTwHzB8M0PlShruddeHfkeorBjdotg/640?wx_fmt=png "")  
  
2. **漏洞概述**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PiapXScWtibK67XvgLiaz6hQibAvcPPHRqNZGYltRKU2WaibdTo9wtQafErQMNA34QBtGgQiazJibwGLlwwN2srxqxapw/640?wx_fmt=png "")  
  
  
  
CVE  
：  
CVE-2022-32532  
  
简述：  
Apache Shiro 是一个可以提供身份验证、授权、密码学和会话管理等功能的开源安全框架。Shiro 框架不仅直观、易用，同时也能提供强大的安全性。  
  
使用   
Shiro 可以轻松地、快速地保护任何应用程序，从小型的移动应用程序到大型的 Web 和企业应用程序。其内置了可以连接大量安全数据源（又名目录）的 Realm，如 LDAP、关系数据库（ JDBC ）、类似INI 的文本配置资源以及属性文件等。  
  
该漏洞是由于   
RegexRequestMatcher 不正当配置存在安全问题，攻击者可利用该漏洞在未授权的情况下，构造恶意数据绕过 Shiro 的权限配置机制，最终可绕过用户身份认证，导致权限校验失败。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ku0nsiagdhZ9kibMY9pUOGdBncITwAvicQeeuiaicSCVicKic2vwDia14DHgndlQTwHzB8M0PlShruddeHfkeorBjdotg/640?wx_fmt=png "")  
  
3. **漏洞危害**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PiapXScWtibK67XvgLiaz6hQibAvcPPHRqNZGYltRKU2WaibdTo9wtQafErQMNA34QBtGgQiazJibwGLlwwN2srxqxapw/640?wx_fmt=png "")  
  
  
  
攻击者可利用该漏洞在未授权的情况下，构造恶意数据绕过   
Shiro 的权限配置机制，最终可绕过用户身份认证，导致权限校验失败。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ku0nsiagdhZ9kibMY9pUOGdBncITwAvicQeeuiaicSCVicKic2vwDia14DHgndlQTwHzB8M0PlShruddeHfkeorBjdotg/640?wx_fmt=png "")  
  
4. **影响版本**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PiapXScWtibK67XvgLiaz6hQibAvcPPHRqNZGYltRKU2WaibdTo9wtQafErQMNA34QBtGgQiazJibwGLlwwN2srxqxapw/640?wx_fmt=png "")  
  
  
##   
  
目前受影响的   
Apache Shiro 版本：  
  
  
	  
Apache Shiro < 1.9.1  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ku0nsiagdhZ9kibMY9pUOGdBncITwAvicQeeuiaicSCVicKic2vwDia14DHgndlQTwHzB8M0PlShruddeHfkeorBjdotg/640?wx_fmt=png "")  
  
5. **解决方案**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PiapXScWtibK67XvgLiaz6hQibAvcPPHRqNZGYltRKU2WaibdTo9wtQafErQMNA34QBtGgQiazJibwGLlwwN2srxqxapw/640?wx_fmt=png "")  
  
  
##   
  
	  
当前官方已发布最新版本，建议受影响的用户及时更新升级到最新版本。链接如下：  
  
https://shiro.apache.org/download.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8ku0nsiagdhZ9kibMY9pUOGdBncITwAvicQeeuiaicSCVicKic2vwDia14DHgndlQTwHzB8M0PlShruddeHfkeorBjdotg/640?wx_fmt=png "")  
  
6. **时间轴**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PiapXScWtibK67XvgLiaz6hQibAvcPPHRqNZGYltRKU2WaibdTo9wtQafErQMNA34QBtGgQiazJibwGLlwwN2srxqxapw/640?wx_fmt=png "")  
  
  
  
【  
-  
】  
202  
2  
年  
0  
6月29日 安识科技A  
-T  
eam团队监测到Apache Shiro 官方发布安全补丁  
  
【  
-  
】  
2  
02  
1年  
0  
6月29日 安识科技A-Team团队根据漏洞信息分析  
  
【  
-  
】  
2  
02  
1年  
0  
6月30日 安识科技A-Team团队发布安全通告  
  
  
