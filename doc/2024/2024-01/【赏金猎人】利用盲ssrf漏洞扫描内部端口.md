#  【赏金猎人】利用盲ssrf漏洞扫描内部端口   
原创 Fighter  重生者安全   2024-01-21 14:31  
  
这是一个hackerone的资产，target:https://test.com  
  
这是一个内部盲ssrf漏洞，该bug  
允许扫描https://test.com上的内部端口，服务器将对关闭的发出不同的响应。  
  
废话少说~直接看操作![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/2_02.png "")  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/2_02.png "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkm7iaHnLsYE7aJoaK1ibEYMshN2TaEndaic0nqibMt8yOcylxlz60gdqhYgxyPjyazp4dj0jWYT17Lewg/640?wx_fmt=png&from=appmsg "")  
  
访问https://test.com，目标有个额搜索功能，当我添加一个127.0.0.1：21进行搜索，使用代理拦截数据包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkm7iaHnLsYE7aJoaK1ibEYMshLafyxyTuia8Lb17n9mW5eU8ndJZxwicNJrdGpickJicRcxFVKdye3ZyqNw/640?wx_fmt=png&from=appmsg "")  
  
发送给intuder去遍历端口，可以通过响应来分析是否开放端口  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkm7iaHnLsYE7aJoaK1ibEYMshlFnezuckwlDwFfg1hLwuES9ib87XKQxicF9ian3dhlF2DNMm02CJLjicKg/640?wx_fmt=png&from=appmsg "")  
  
扫描端口结果如下，  
证明开放端口提供大于 3000 长度的响应  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/SEVwkT7gYkm7iaHnLsYE7aJoaK1ibEYMshCQ0EwtX2v8tiaiboIw6GTw2OSiaCwnDFIac6RNXJJQ7vVDKwibzWKfyPAg/640?wx_fmt=png&from=appmsg "")  
  
**https://127.0.0.1:22****Open**  
  
**https://127.0.0.1:21****close**  
  
**https://127.0.0.1:86****Open**  
  
**https://127.0.0.1:88****Open**  
  
**https://127.0.0.1:87****close**  
  
此漏洞可用于侦测。攻击者可以枚举服务并对其发起攻击
示例：通过来自服务器的不同响应进行端口扫描  
  
盲SSRF（Server-Side Request Forgery，服务器端请求伪造）是一种计算机安全漏洞，攻击者利用该漏洞滥用服务器的功能，使其访问或操作服务器范围内的信息，而这些信息本来对攻击者来说是无法直接访问的。  
  
**SSRF的影响**  
  
成功的SSRF攻击通常会导致未经授权的操作或访问组织内的数据。  
这可能发生在受漏洞影响的应用程序内部，或者与应用程序可以通信的其他后端系统上。  
在某些情况下，SSRF漏洞可能允许攻击者执行任意命令。  
  
**SSRF的常见攻击方式**  
  
SSRF攻  
击通常利用信任关系来升级攻击并执行未经授权的操作。  
这些信任关系可能存在于与服务器相关的方面，也可能存在于同一组织内的其他后端系统之间。  
  
**欢迎分享给更多热爱安全的朋友不要忘了点个关注**  
  
