#  【漏洞预警】Java数字签名伪造漏洞   
夜影实验室  锦行科技   2022-04-25 15:04  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruCV8nvZkwfFAoxs0Vzayiaia1ZB7QyTIIzhGvyhibO21sBmDPuQicBGzfAgJKVCnPYc7zlLOaDlibLiawaw/640?wx_fmt=gif "")  
  
  
**漏洞名称：**  
  
Java 数字签名伪造漏洞  
  
**影响范围：**  
  
Oracle Java SE 7u311  
  
Oracle Java SE 11.0.14Oracle Java SE 17.0.2Oracle Java SE 18Oracle GraalVM Enterprise Edition 20.3.5Oracle GraalVM Enterprise Edition 21.3.1Oracle GraalVM Enterprise Edition 22.0.0.2  
  
**漏洞编号：**  
  
CVE-2022-21449  
  
**漏洞类型：**  
  
数字签名伪造  
  
**利用条件：**  
  
无  
  
**综合评价：**  
  
<利用难度>：低  
  
<威胁等级>：  
**高危**  
  
  
**#1**  
**漏洞描述**  
  
  
ECDSA 即椭圆曲线数字签名算法(Elliptic Curve Digital Signature Algorithm)，它是一种被广泛使用的标准，常用于应用程序和密码库。  
  
该漏洞存在于Java的ECDSA签名算法的实现中，ECDSA算法是对消息进行签名和验证内容的真实性和完整性的加密机制。攻击者利用该漏洞可以伪造签名和绕过认证过程，攻击者可以轻易地伪造SSL证书类型和握手（允许通信的拦截和修改）、签名的JWT、SAML证明或OIDC ID token、甚至WebAuthn认证消息。  
  
  
**#2 解决方案**  
  
  
Oracle 2022年四月最新补丁，请尽快使用安全版本或者及时打上安全补丁。  
  
  
**#3 参考资料**  
  
  
https://www.oracle.com/security-alerts/cpuapr2022.html   
  
https://github.com/khalednassar/CVE-2022-21449-TLS-PoC  
  
https://neilmadden.blog/2022/04/19/psychic-signatures-in-java/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruD6rSnJpSL57NHjuX79JSjjyYviaibNeS3xmGzPfoict6VdnvyuYEq6JdjQqre3WkicWWU7hjpicS2ByibQ/640?wx_fmt=gif "")  
  
**推 荐 阅 读**  
  
  
  
  
[多领域实力上榜！锦行科技入选安全牛《中国网络安全行业全景图》](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489474&idx=1&sn=bef7b914312396ac7422c4691c0a3fcb&chksm=9799ec67a0ee657178190836a5101fc51afc32dbbfe281a62d0140b541d60ecb0fc017a5b7c0&scene=21#wechat_redirect)  
  
  
  
[Java代审7-1：远程代码执行](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489424&idx=1&sn=6db2594121e743a1a29e1ce94b52678b&chksm=9799ec35a0ee6523fbb239a23918805fec0e11f9b30bd1303259bdb53f9ea377d7061980ed5f&scene=21#wechat_redirect)  
  
  
  
[从俄乌网络战中，我们可以得到什么启示？](http://mp.weixin.qq.com/s?__biz=MzIxNTQxMjQyNg==&mid=2247489342&idx=1&sn=fb9a7b5c76496e3d164ef032555ca82a&chksm=9799ec9ba0ee658d502a7c0852ac54d4313653d9fd1ec5e6d945377b8cb125a297751268fc3f&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2CRGGNuQruBy67pKAiadAicicia5vPm2xla4zAiccf9wQm5dGGTWiaic61UXVZWCtnV8Vx2RNh2p2eHFnaSTJEhZ7LRxQ/640?wx_fmt=gif "")  
  
  
