#  【安全圈】Windows KDC 代理 RCE 漏洞让攻击者远程控制服务器   
 安全圈   2025-03-06 19:00  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/aBHpjnrGylgOvEXHviaXu1fO2nLov9bZ055v7s8F6w1DD1I0bx2h3zaOx0Mibd5CngBwwj2nTeEbupw7xpBsx27Q/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
**关键词**  
  
  
  
安全漏洞  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/aBHpjnrGyliaAnbWZNIdnNMnibrp5ERSAjkibSicmP72tmhzsQiaJvgjT1ibEBLceVeqxGoLzCbNKzicVBzCnZAh8npqQ/640?wx_fmt=jpeg&from=appmsg "")  
  
安全研究人员发现微软 Windows 密钥分发中心 (KDC) 代理中存在一个严重的远程代码执行漏洞，该漏洞可能允许攻击者完全控制受影响的服务器。  
  
该漏洞编号为CVE-2024-43639，是由于 KDC 代理服务中缺少对 Kerberos 响应长度的检查而导致的整数溢出。  
  
该严重安全漏洞已于 11 月修复，可使未经身份验证的远程攻击者以目标服务的权限执行任意代码，从而可能导致整个系统被攻陷。  
  
该漏洞凸显了身份验证服务中持续存在的安全挑战，并强调了在企业环境中及时修补的重要性。  
## 漏洞概述  
  
昆仑实验室的安全研究人员与 Cyber KunLun 合作发现了 Microsoft Windows KDC 代理漏洞。该漏洞具体存在于 KDC 代理服务器服务 (KDCSVC) 中，该组件通过 HTTPS 代理 Kerberos 流量，为远程工作负载提供 Kerberos 身份验证。  
  
根据安全研究人员的详细分析，该漏洞源于对 Kerberos 响应长度的不当处理，从而产生了可利用的整数溢出情况。  
  
核心问题在于缺乏对 Kerberos 响应长度的验证检查，从而允许恶意制作的响应触发内存损坏错误，并可用于代码执行。  
  
Kerberos 是 Windows 环境中的基本身份验证协议，在 Active Directory 域中起着至关重要的作用。当远程客户端需要进行身份验证但缺乏与域控制器的直接网络连接时，KDC 代理充当中介，通过 HTTPS 转发身份验证请求。  
  
此代理功能对于 RDP 网关和 DirectAccess 等服务尤其重要。易受攻击的组件实现了Kerberos KDC 代理协议(KKDCP)，该协议将 Kerberos 请求包装在发送到 /KdcProxy 端点的 HTTP POST 请求中。  
## 漏洞技术分析  
  
攻击过程涉及一系列复杂的事件，这些事件针对的是 KDC 代理如何处理 Kerberos 响应。攻击者首先指示 KDC 代理将 Kerberos 请求转发到他们控制的服务器，然后该服务器返回带有操纵长度值的特制 Kerberos 响应。  
  
该漏洞源于 kpssvc.dll 文件中的 KpsSocketRecvDataIoCompletion() 函数，该函数在处理传入的 Kerberos 响应之前未能正确验证其长度。  
  
在处理响应时，KDC 代理读取前四个字节来确定消息长度，然后尝试读取相应数量的字节。  
  
但是，系统没有正确验证这些长度值，从而允许攻击者指定触发整数溢出的极大尺寸。  
  
当系统尝试分配或重新分配不足以满足指定消息大小的内存缓冲区时，这些内存损坏就会发生在 ASN.1 编码过程中。  
```
KDC-PROXY-MESSAGE::= SEQUENCE {
    kerb-message [0] OCTET STRING,
    target-domain [1] KERB-REALM OPTIONAL,
    dclocator-hint [2] INTEGER OPTIONAL
}
```  
  
特别令人担忧的是该漏洞如何绕过现有的验证机制。通常检查 Kerberos 响应的验证函数可以通过在响应中设置特定的字节值来绕过。这允许攻击者完全绕过安全检查并直接进入易受攻击的代码路径。  
## 影响和受影响的系统  
  
该漏洞仅影响明确配置为 KDC 代理服务器的服务器，不会影响域控制器。这在一定程度上限制了易受攻击系统的范围，因为只有积极使用 KDCSVC 服务的环境才会受到威胁。  
  
然而，对于受影响的系统，后果可能很严重，可能允许攻击者以目标服务的权限执行代码，这可能导致整个系统被入侵。  
  
使用依赖 KDC 代理的远程身份验证服务的组织尤其容易受到攻击。  
这包括使用 RDP 网关或 DirectAccess 为外部用户提供远程身份验证的环境。  
  
该攻击不需要身份验证，因此特别危险，因为攻击者只需要通过网络访问 KDC 代理服务器即可尝试利用该漏洞。  
  
虽然截至 2025 年 3 月 4 日尚未发现利用此漏洞的攻击，但详细技术信息的披露增加了未来利用此漏洞的可能性。  
## 缓解和补救措施  
  
微软在 2024 年 11 月的安全更新中通过在 KDC 代理服务器服务中实施适当的长度验证检查解决了 CVE-2024-43639 问题。具体来说，该补丁修改了易受攻击的函数，以在处理 Kerberos 响应长度之前对其进行验证。  
  
安全研究人员指出，微软解决 KDC 代理中的问题而不是修复 ASN.1 库中的底层漏洞有些不寻常，这表明在 Windows 生态系统中更广泛地使用该库方面可能会有其他考虑。  
  
对于运行 KDC 代理服务器的组织，立即修补是主要建议。Microsoft 尚未针对此漏洞提供其他缓解措施，这强调了应用 2024 年 11 月安全更新的重要性。  
  
如果无法立即修补，组织应考虑暂时禁用 KDC 代理服务，直到可以应用更新，但这可能会影响公司网络外用户的远程身份验证功能。安全团队还应实施监控，以防潜在的漏洞利用。检测指南建议监控 TCP 端口 88 流量，以查找消息长度前缀为 0x80000000（2,147,483,648）字节或更大的 Kerberos 响应，这表明可能存在与利用此漏洞有关的可疑活动。  
  
来源：https://cybersecuritynews.com/windows-kdc-proxy-rce-vulnerability/  
  
  END    
  
  
阅读推荐  
  
  
[【安全圈】最新黑产技术曝光，只需19分钟即可劫持AI大模型](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=1&sn=d8c361d857947b4f7ddd18672093ed23&scene=21#wechat_redirect)  
  
  
  
[【安全圈】全球 49,000 多个门禁管理系统存在巨大安全漏洞](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=2&sn=cfbab77073fc932a8b466a9586809efc&scene=21#wechat_redirect)  
  
  
  
[【安全圈】GitHub 大规模恶意软件行动：Redox Stealer盯上游戏玩家与盗版用户](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=3&sn=b6b1eda81cdc868cb996830336a5f909&scene=21#wechat_redirect)  
  
  
  
[【安全圈】320万用户因恶意浏览器扩展程序遭信息泄露](https://mp.weixin.qq.com/s?__biz=MzIzMzE4NDU1OQ==&mid=2652068282&idx=4&sn=101d9a5f9ab1488a2654bb7bdb7ebdf5&scene=21#wechat_redirect)  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEDQIyPYpjfp0XDaaKjeaU6YdFae1iagIvFmFb4djeiahnUy2jBnxkMbaw/640?wx_fmt=png "")  
  
**安全圈**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCEft6M27yliapIdNjlcdMaZ4UR4XxnQprGlCg8NH2Hz5Oib5aPIOiaqUicDQ/640?wx_fmt=gif "")  
  
  
←扫码关注我们  
  
**网罗圈内热点 专注网络安全**  
  
**实时资讯一手掌握！**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
**好看你就分享 有用就点个赞**  
  
**支持「****安全圈」就点个三连吧！**  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/aBHpjnrGylgeVsVlL5y1RPJfUdozNyCE3vpzhuku5s1qibibQjHnY68iciaIGB4zYw1Zbl05GQ3H4hadeLdBpQ9wEA/640?wx_fmt=gif "")  
  
  
