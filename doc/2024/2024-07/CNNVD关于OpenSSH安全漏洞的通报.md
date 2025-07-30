#  CNNVD关于OpenSSH安全漏洞的通报   
 金盾信安   2024-07-03 18:52  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/73LRor7IX0AqPq8iarlcdhLqVN9LiagyfCNLiam9aCMzcD7zU3lErpjtziczFKApXia9QjXGbgNAcGDgrXxnNjPREeQ/640?wx_fmt=gif&from=appmsg "")  
  
  
  
  
**漏洞情况**  
  
近日，国家信息安全漏洞库（CNNVD）收到关于OpenSSH安全漏洞(CNNVD-202407-017、CVE-2024-6387)情况的报送。攻击者可以利用该漏洞在无需认证的情况下，通过竞争条件远程执行任意代码并获得系统控制权。OpenSSH多个版本受该漏洞影响。目前，OpenSSH官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
## 一漏洞介绍  
  
  
OpenSSH是加拿大OpenBSD计划组的一套用于安全访问远程计算机的连接工具。该工具是SSH协议的开源实现，支持对所有的传输进行加密，可有效阻止窃听、连接劫持以及其他网络级的攻击。该漏洞源于信号处理程序中存在竞争条件，攻击者利用该漏洞可以在无需认证的情况下远程执行任意代码并获得系统控制权。  
  
## 二危害影响  
  
  
OpenSSH 8.5p1版本至9.8p1之前版本均受该漏洞影响。  
  
## 三修复建议  
  
  
目前，OpenSSH官方已发布新版本修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。官方更新版本下载链接：  
  
https://www.openssh.com/txt/release-9.8  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。联系方式: cnnvdvul@itsec.gov.cn  
  
来源：“CNNVD安全动态”微信公众号  
  
![](https://mmbiz.qpic.cn/mmbiz_png/73LRor7IX0AqPq8iarlcdhLqVN9LiagyfCB1icibnYmFGicTchdYRdfJs6uEgFV2HhINiaIugEyNmkkzgMaKmgccpwsg/640?wx_fmt=png&from=appmsg "")  
  
  
