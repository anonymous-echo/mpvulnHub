#  国家漏洞库CNNVD：关于OpenSSL安全漏洞的通报   
 安全内参   2022-07-06 19:01  
  
**关注我们**  
  
  
**带你读懂网络安全**  
  
  
##   近日，国家信息安全漏洞库（CNNVD）收到关于OpenSSL 安全漏洞（CNNVD-202207-242、CVE-2022-2274）情况的报送。成功利用此漏洞的攻击者，可造成目标机器内存损坏,进而在目标机器远程执行代码。OpenSSL 3.0.4版本受漏洞影响。目前，OpenSSL官方已发布新版本修复了漏洞，请用户及时确认是否受到漏洞影响，尽快采取修补措施。  
  
**一****、漏洞介绍**  
  
  OpenSSL  
是  
OpenSSL团队开发的一个开源的能够实现安全套接层（  
SSLv2/v3）和安全传输层（  
TLSv1）协议的通用加密库。该产品支持多种加密算法，包括对称密码、哈希算法、安全散列算法等。该漏洞源于计算机上具有  
2048位私钥的  
 RSA 实现不正确，并且在计算过程中会发生内存损坏  
,导致攻击者可能会在执行计算的机器上远程执行代码。  
  
**二、危害影响**  
  
  成功利用此漏洞的攻击者，可造成目标机器内存损坏  
,进而在目标机器远程执行代码。  
OpenSSL 3.0.4版本受漏洞影响。  
  
**三、修复建议**  
  
  目前，OpenSSL官方已发布新版本修复了漏洞，请用户及时  
  
确认  
是否受到漏洞影响，尽快采取修补措施。官方链接如下：  
  
https://git.openssl.org/gitweb/?p=openssl.git;a=commitdiff;h=4d8a88c134df634ba610ff8db1eb8478ac5fd345  
  
  本通报由CNNVD技术支撑单位——长春嘉诚信息技术股份有限公司、北京数字观星科技有限公司、北京华云安信息技术有限公司、内蒙古洞明科技有限公司、太极计算机股份有限公司、中瑞创信息技术（北京）有限公司、安徽华云安科技有限公司提供支持。  
  
CNNVD将继续跟踪上述漏洞的  
相关情况，及时发布相关信息。如有需要，可与  
CNNVD联系。联系方式  
: cnnvdvul@itsec.gov.cn  
  
  
  
**推荐阅读**  
- [网安智库平台长期招聘兼职研究员](http://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247499450&idx=2&sn=2da3ca2e0b4d4f9f56ea7f7579afc378&chksm=ebfab99adc8d308c3ba6e7a74bd41beadf39f1b0e38a39f7235db4c305c06caa49ff63a0cc1d&scene=21#wechat_redirect)  
  
  
- [欢迎加入“安全内参热点讨论群”](https://mp.weixin.qq.com/s?__biz=MzI4NDY2MDMwMw==&mid=2247501251&idx=1&sn=8b6ebecbe80c1c72317948494f87b489&chksm=ebfa82e3dc8d0bf595d039e75b446e14ab96bf63cf8ffc5d553b58248dde3424fb18e6947440&token=525430415&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
  
  
  
文章来源：CNNVD安全动态  
  
  
点击下方卡片关注我们，  
  
带你一起读懂网络安全 ↓  
  
  
  
