#  Shiro反序列化漏洞复现（文末领红包封面）   
原创 Mall0c  Cyb3rES3c   2024-02-03 11:28  
  
**0x0**  
  
声明  
  
    由于传播、利用此文所提供的信息而造成的任何直接或间接的后果和损失，均由使用者本人承担，Cyb3rES3c及文章作者不承担任何责任。如有侵权烦请告知，我们将立即删除相关内容并致歉。请遵守《中华人民共和国个人信息保护法》、《中华人民共和国网络安全法》等相关法律法规。  
  
**0****x1**  
  
漏洞原理  
  
  
    Apache Shiro 是一个强大易用的 Java 安全框架，提供了认证、授权、加密和会话管理等功能，对于任何一个应用程序，Shiro都可以提供全面的安全管理服务。Shiro-550主要是由Shiro的rememberMe内容反序列化导致的命令执行漏洞，造成的原因是默认加密密钥是硬编码在Shiro源码中，任何有权访问源代码的人都可以知道默认加密密钥，于是攻击者可以创建一个恶意对象，对其进行序列化、编码、加密，然后将其作为Cookie的rememberMe字段内容发送，Shiro将对其解码和反序列化，导致服务器运行一些恶意代码。  
  
Shiro服务器识别身份和解密处理流程：  
  
（1）客户端  
  
1、用户输入账号和密码并勾选"Remeber Me"或者"记住我"这样的选项。  
  
2、Shiro服务器先验证用户信息，用户信息校验无误后查看用户是否勾选了"Remember Me"或者"记住我"这样的选项，若勾选则将用户信息序列化，并将序列化后的内容进行AES加密，然后使用 Base64 进行编码。  
  
3、最后将处理好的内容放到Cookie的rememberMe字段中。  
  
（2）服务端  
  
1、服务器获取客户端发送的请求中的rememberMe参数的内容。  
  
2、根据加密过程，先对rememberMe参数的值进行Base64解码，然后使用AES解密，最后将解密后的内容进行反序列化得到用户信息。  
  
    由于AES加密的密钥Key被硬编码在代码中，因此可以知道payload被处理的流程：  
  
payload->序列化->AES加密->Base64编码  
  
**0x2**  
  
复现过程  
  
启动Docker  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFD8eWoV1ZabD349PvKWfvOZ48zWibDpTc2FfHY8tQcnSK9RZVatKAHiaQw/640?wx_fmt=png&from=appmsg "")  
  
访问Web服务  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDtzKsG8VHGzTicg1djoRzv1LVjs72QibnAyibRoZC1510bo5Yl2xhicRBCQ/640?wx_fmt=png&from=appmsg "")  
  
输入密码，勾选Remember me选项  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDNmcKu4ejVjb3nRRJJNCxYGFKkpp1pQqOIictacpcMsgp6CQlLEN29AA/640?wx_fmt=png&from=appmsg "")  
  
请求包中有rememberme参数，响应包的Set-Cookie字段有 rememberMe=deleteMe，从响应包中的rememberMe可以判断这是一个Shiro框架，而且有可能有Shiro反序列化漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDMGkf4A4Waeyk3WRyRKSWbZZlTNDZtibl1O7kjjdLrD2OXrHctxpJib0A/640?wx_fmt=png&from=appmsg "")  
  
删除请求包 POST 中的rememberme参数发现响应包的Set-Cookie字段仍然有rememberMe=deleteMe  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDRkPWOvBVY9BMTbLEXlKJ2VycrNnEIO7xh6InNwFmhG8WDJZLWjqcEA/640?wx_fmt=png&from=appmsg "")  
  
如果一开始POST请求中没有rememberme参数，可以在Cookie中添加一个rememberMe 参数，如果响应包中有Set-Cookie: rememberMe=deleteMe，说明存在Shiro框架。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDOjFS4jzEOC8HOuIIp4y3ZIdZZZ6urib6NoosHCKdB0usRpR0Gq1ib9zg/640?wx_fmt=png&from=appmsg "")  
  
使用Shiro反序列化利用工具检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFD3Jy5DibjpoXNSmNicqHGaNAGse2euhPwXKIEXiaEWnNMibicnsQiclIoKbiaA/640?wx_fmt=png&from=appmsg "")  
  
存在Shiro框架，并爆破出了密钥  
  
爆破利用链，Shiro反序列化有多种情况，有key有利用链，有key无利用链，还有没有key的，这里有key有利用链。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDl3ujH87mjYqrcEfmteHxibdLnSgazq702QvhVLHVdQCxpN0UGMySPYQ/640?wx_fmt=png&from=appmsg "")  
  
命令执行查看权限  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDHWqg3uqibsmHTFnutJicU8BYglEslZM62dQzATj1HJYw0WjGibu2ibLEdQ/640?wx_fmt=png&from=appmsg "")  
  
root权限，  
注入内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDWnZpxicsDpnTgQBd0SCCkB86Vgib2EOXrtgX2MicYn3Aeg5E5BHiao6QFQ/640?wx_fmt=png&from=appmsg "")  
  
哥斯拉连接内存马  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/fo3OZEF1OKrOyZ7u7117IjxWxNCY4SFDCbZuS4nNnFbbbibWa1o82y7GlHknC5g6LpiaG4gQOicmD8tGVJvCNQ6AA/640?wx_fmt=png&from=appmsg "")  
  
**0x3**  
  
关于 Shiro-721 反序列化漏洞  
  
Shiro-721的AES加密的key是系统随机生成的，并且当存在有效的用户信息时才会进入下一阶段，所以我们需要获取到登录后的rememberMe的值，才可以进行下一步利用。  
  
**0x4**  
  
致谢  
  
    感谢大家对Cyb3rES3c的关注和支持，在未来，Cyb3rES3c将继续努力，为大家带来更好的内容。  
  
    祝大家新年快乐、平安顺遂！  
  
  
