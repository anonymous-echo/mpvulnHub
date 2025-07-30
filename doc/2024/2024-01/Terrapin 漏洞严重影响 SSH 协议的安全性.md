#  Terrapin 漏洞严重影响 SSH 协议的安全性   
小王斯基  FreeBuf   2024-01-06 09:03  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
The Hacker News 网站消息，Ruhr University Bochum 的安全研究人员在 SSH 加密网络协议中发现一个新安全漏洞，威胁攻击者能够利用漏洞破坏安全通道的完整性，从而降低 SSH 连接的安全性。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38uHcVRKEwNTmvAPFAoNBqpNvavjlALbE35yncrMA1TvicmjKO6e9AotbwLASDaW52UamFWVItLW2Q/640?wx_fmt=png&from=appmsg "")  
  
  
SSH 协议依靠加密技术验证和加密设备之间的连接，这一过程主要通过握手实现。握手过程中，客户端和服务器就加密原语达成一致，并交换建立安全通道所需的密钥，从而确保传输信息的保密性、完整性和安全性。  
  
  
安全漏洞被称为 Terrapin（CVE-2023-48795，CVSS 得分：5.9），研究人员称其是有史以来第一个可实际针对 SSH 协议的前缀截断攻击。  
  
  
研究人员 Fabian Bäumer、Marcus Brinkmann 和 Jörg Schwenk 指出，当使用 SSH 扩展协商时，处于主动中间对手（AitM）位置并有能力在 TCP/IP 层拦截和修改连接流量的威胁攻击者能够降低 SSH 连接的安全性。  
  
  
威胁攻击者通过在握手过程中”精心“调整序列号，便能够在安全通道开始时删除客户端或服务器发送的任意数量的信息，整个过程客户端或服务器都不会察觉，研究人员进一步解释称，威胁攻击者还可以通过截断誊本中的扩展协商消息（RFC8308）来降低连接的安全性。（截断会使 OpenSSH 9.5 中针对击键计时攻击的特定对策失效）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38uHcVRKEwNTmvAPFAoNBqp9hQXz0kGmjC6SdoPRLlxCFialOzUgKEENQWRTI4ic65mKUkMcpg1IFMg/640?wx_fmt=png&from=appmsg "")  
  
  
从目前披露的消息来看，Terrapin 漏洞影响包括 OpenSSH、Paramiko、PuTTY、KiTTY、WinSCP、libssh、libssh2、AsyncSSH、FileZilla 和 Dropbear 等在内的许多 SSH 客户端和服务器。值得一提的是，威胁攻击者能够完成攻击活动的关键前提是被攻击目标使用易受攻击的加密模式，例如 ChaCha20-Poly1305 或 CBC with Encrypt-then-MAC 等。  
  
  
Qualys 还表示在现实世界中，威胁攻击者可以利用这一漏洞截获敏感数据，或使用管理员权限控制关键系统，对于拥有大型互联网络并提供权限数据访问的企业来说，这种风险尤为突出。  
  
  
最后，JFrog 公司安全研究部高级安全研究员 Yair Mizrahi 指出，由于 SSH 服务器，尤其是 OpenSSH 在整个基于云的企业应用环境中使用非常广泛，因此企业必须确保已采取适当措施为服务器打补丁，以避免遭受更大的网络攻击。此外，Mizrahi 特别强调，连接到修补服务器的易受攻击的客户端仍然会导致连接易受攻击。因此，企业还必须采取措施，识别其整个基础设施中的每一个易受攻击的漏洞，并立即采取缓解措施。  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=png "")  
> https://thehackernews.com/2024/01/new-terrapin-flaw-could-let-attackers.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png "")  
  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492202&idx=1&sn=2f1a84bd3e01556749aef29f924b17b6&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492186&idx=1&sn=7b90caa54b4a5e1e940295fee5b5cc50&chksm=cfb86351d083a1002f7ade50b9711b28004bcc6fec3d727c5ef7dd0073e124441c8df2d1007e&scene=21&sessionid=1704347732#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492164&idx=1&sn=180a69d74f7fc58823b91ba024a4dcb6&chksm=cf5ca40c2351683a1b4304549bfe41fb11db28b881181ca47216f00227b02b4343e83242c445&scene=21&sessionid=1704347732#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif "")  
  
