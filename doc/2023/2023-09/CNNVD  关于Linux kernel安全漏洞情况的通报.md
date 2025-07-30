#  CNNVD | 关于Linux kernel安全漏洞情况的通报   
 中国信息安全   2023-09-27 18:12  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wGBib780qFLcliaHOJ2XvyKeBHshWmLlcoUEv6Eg7kC3tpouhtITIFib1VPC9ZV8VXeT0VUljNeptpw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wGBib780qFLcliaHOJ2XvyKeBHshWmLlcoUEv6Eg7kC3tpouhtITIFib1VPC9ZV8VXeT0VUljNeptpw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/1brjUjbpg5wGBib780qFLcliaHOJ2XvyKev7zziatEtjVxg9MWGZMP5eWDd7hC6jU1ZM4GXoz7os6jicU2v1wEwx0A/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wGBib780qFLcliaHOJ2XvyKeBHshWmLlcoUEv6Eg7kC3tpouhtITIFib1VPC9ZV8VXeT0VUljNeptpw/640?wx_fmt=gif "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/1brjUjbpg5wGBib780qFLcliaHOJ2XvyKeBHshWmLlcoUEv6Eg7kC3tpouhtITIFib1VPC9ZV8VXeT0VUljNeptpw/640?wx_fmt=gif "")  
  
**扫码订阅《中国信息安全》**  
  
邮发代号 2-786  
  
征订热线：010-82341063  
  
  
近日，国家信息安全漏洞库（CNNVD）收到关于Linux kernel 安全漏洞（CNNVD-202309-2146、CVE-2023-42753）情况的报送。成功利用漏洞的攻击者可导致系统崩溃或提升本地用户权限。linux kernel 6.6、linux kernel 7.0、linux kernel 8.0、linux kernel 9.0等版本均受漏洞影响。目前，Linux官方已经发布了版本更新修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。  
  
  
**一、漏洞介绍**  
  
Linux kernel是美国Linux基金会的开源操作系统Linux所使用的内核。Linux kernel存在安全漏洞，在Linux kernel中的子系统netfilter，主要用于过滤数据包、执行网络地址转换等。该漏洞源于在netfilter中发现了一个数组索引， 丢失的宏可能会使h->nets数组偏移量计算错误，从而导致系统崩溃或权限提升。  
  
  
**二、危害影响**  
  
成功利用漏洞的攻击者可导致系统崩溃或提升本地用户权限。linux kernel 6.6、linux kernel 7.0、linux kernel 8.0、linux kernel 9.0等版本均受漏洞影响。  
  
  
**三、修复建议**  
  
目前，Linux官方已经发布了版本更新修复了该漏洞，建议用户及时确认产品版本，尽快采取修补措施。参考链接如下：  
  
https://access.redhat.com/security/cve/CVE-2023-42753  
  
本通报由CNNVD技术支撑单位——杭州迪普科技股份有限公司、南京禾盾信息科技有限公司、北京山石网科信息技术有限公司等提供支持。  
  
CNNVD将继续跟踪上述漏洞的相关情况，及时发布相关信息。如有需要，可与CNNVD联系。  
  
联系方式: cnnvdvul@itsec.gov.cn  
  
（来源：CNNVD）  
  
  
  
  
  
  
  
**《中国安全信息》杂志倾力推荐**  
  
**“企业成长计划”**  
  
  
**点击下图 了解详情**  
  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzA5MzE5MDAzOA==&mid=2664162643&idx=1&sn=fcc4f3a6047a0c2f4e4cc0181243ee18&chksm=8b5ee7aabc296ebc7c8c9b145f16e6a5cf8316143db3edce69f2a312214d50a00f65d775198d&scene=21#wechat_redirect)  
  
  
  
