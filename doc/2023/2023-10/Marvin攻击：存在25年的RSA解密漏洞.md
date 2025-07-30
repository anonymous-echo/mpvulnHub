#  Marvin攻击：存在25年的RSA解密漏洞   
 关键基础设施安全应急响应中心   2023-10-08 15:22  
  
据悉，1998年发现的SSL服务器PKCS #1 v1.5填充相关漏洞仍然影响多个服务器。  
  
1998年，安全研究人员发现攻击者利用PKCS #1 v1.5填充的错误引发的SSL服务器的错误信息可以发起选择密文攻击，当与RSA解密同时使用时可以完全破解TLS解密的机密性；2018年，Hanno B?ck等人证明19年之后，许多互联网服务器仍然受到该攻击的变种的影响，红帽（Red Hat）研究人员发现了该攻击的多个变种，并将其命名为“Marvin Attack”。Marvin攻击可以绕过现有补丁和缓解措施，解密RSA密文、伪造签名、甚至解密有漏洞的TLS服务器的会话信息。  
  
·对于有漏洞的实现，攻击者可以解密RSA密文和伪造签名。  
  
·对于默认使用RSA加密密钥交换的TLS服务器，攻击者可以记录会话，并之后解密会话内容。  
  
·对于使用前向安全密码套件的TLS主机，攻击者必须在客户端超时重连之前执行大量的并行攻击以伪造服务器签名，虽然攻击会比较困难，但仍然存在成功的可能性。  
  
研究人员发现多个实现和修复措施仍然受到该漏洞的影响，经过测试研究人员认为大多数密码学实现在实践中都受到该漏洞的影响，包括OpenSSL、GunTLS、NSS、  
  
·pyca/cryptography、M2crypto、OpenSSL-ibmca、Go、GNU MP：  
  
·OpenSSL (TLS level)：RSA解密时间Oracle漏洞，对应CVE漏洞编号CVE-2022-4304；  
  
·GnuTLS (TLS level)：ClientKeyExchange过程中伪造的RSA密文响应时间与正确的PKCS#1 v1.5填充密文响应时间不同，对应CVE漏洞编号CVE-2023-0361；  
  
·NSS (TLS level)：改善RSA操作的恒定时间，对应CVE漏洞编号CVE-2023-4421；  
  
·pyca/cryptography：尝试缓解针对RSA解密的 Bleichenbacher 攻击，CVE-2020-25659补丁无效，需要OpenSSL层级补丁；  
  
·M2crypto：尝试缓解针对RSA解密的 Bleichenbacher 攻击，CVE-2020-25659补丁无效，需要OpenSSL层级补丁。  
  
研究人员称该漏洞并不局限于RSA，可以扩展到大多数的非对称密码算法，包括Diffie-Hellman、ECDSA等，可能引发侧信道攻击。  
  
研究人员提供了TLS服务器层面和API层面的工具来检测该问题，工具脚本参见：https://github.com/tlsfuzzer/tlsfuzzer/blob/master/scripts/test-bleichenbacher-timing-pregenerate.py  
  
**安全建议**  
  
对于受影响的用户，研究人员建议安装相关的补丁或更新。此外，研究人员建议用户停用RSA PKCS#1 v1.5加密，在TLS层面，只有启用了RSA加密的服务器受到影响，大多数客户端支持ECDH，因此禁用使用RSA加密的密码套件即可不受该漏洞的影响。对于客户单，可以使用 Finite Field Diffie Hellman。  
  
研究论文已被CCF-B类会议ESORICS录用，论文下载地址：https://eprint.iacr.org/2023/1442  
  
**参考及来源：**  
  
https://www.bleepingcomputer.com/news/security/new-marvin-attack-revives-25-year-old-decryption-flaw-in-rsa/  
  
  
  
原文来源：嘶吼专业版  
  
“投稿联系方式：孙中豪 010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaz5iaQYxGogvC8qicuLNlkT5ibJnwu1leQiabRVqFk4Sb3q1fqrDhicLBNAqVY4REuTetY1zBYuUdic0nVhZR4FHpAfg/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
