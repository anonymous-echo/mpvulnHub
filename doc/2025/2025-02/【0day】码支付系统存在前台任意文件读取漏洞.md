#  【0day】码支付系统存在前台任意文件读取漏洞   
原创 Mstir  星悦安全   2025-02-08 04:53  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
**码支付是基于php开发的一套新型聚合收款、聚合支付系统，是一款专业的聚合免签收款系统,无需对接其余平台,个码就可收款,灰常的方便快捷,集成实现三网免挂功能,无需挂繁琐的监控软件就可实现回调,更便捷的监控方式,更优的产品质量.**  
  
**Fofa指纹 : 请见文末!**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6gRrE9fJ3f2B71xtNvD1yuC3r1L9FBicHGqx0FpXYH7R4bC524ppoaaxA/640?wx_fmt=png&from=appmsg "")  
  
前台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6ggDDcLAbDB5MHUwXs5Hojd7aewTRF0fFCMID9k9MDPic4xTI6zyPJibmA/640?wx_fmt=webp&from=appmsg "")  
  
后台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6gdRYzwicJdnErXFoXXBviaGVfks5qll2sShKnG6ZrnYbiaGT2Y6u37T6uQ/640?wx_fmt=webp&from=appmsg "")  
## 0x01 漏洞复现  
  
Payload:  
  
```
GET /***/*****/*****?***=/etc/passwd HTTP/1.1Host: 127.0.0.1Cache-Control: max-age=0Upgrade-Insecure-Requests: 1User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.54 Safari/537.36Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9Accept-Encoding: gzip, deflateAccept-Language: zh-CN,zh;q=0.9Connection: close
```  
```
完整POC请见文末!!!
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6gC0bghh4xqr91futwZwY1D3o4ohU98mqU17evv1MfxqgUzoKpBiaVTxw/640?wx_fmt=png&from=appmsg "")  
  
可直接组合拳读取日志文件进后台.  
## 0x02 纷传圈子  
  
  
完整Exp及源码已放在纷传圈子中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有1900+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**5，Fofa API 高级会员Key共享**  
  
**圈子目前价格为****早鸟****价，现在星球有500+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于2025.2.8日更新**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6gaqibpBEZN9r2UricBcEibNsSmlIVfnibM6SJUuNMku4FsPMO3KMrB10Diag/640?wx_fmt=png&from=appmsg "")  
  
Fofa 高级会员 Key****  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yh7LPSCjwdicjVT9I5kmk5d53XibibUmzz037tTfQx5prf7j21ed3oVTkQ/640?wx_fmt=png&from=appmsg "")  
  
超多审计资料，工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6g367ZEv3pT7cv8fl3YHMZH47sBH2IMy1J2XYeMNVXDJgLhP1yahI4pw/640?wx_fmt=png&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwYQ7XZx91DUHD6M2jFjo9jwxZEnQs2PaU9jQAvYicVxtcIiaKI2QeRxqA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
****  
**圈子内部漏********洞库(日更)**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dO3JY3ibuSzzKb6JXHOsho8GllKEjcqXnSa6OY73aptxTiaibrLiaKrw85bDlFrRjR8aUGrxZKVQBTug/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**每篇文章均有完整指纹和详细POC**  
  
****  
**一起愉快地刷分**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTp1nDJvFuhT6INWEyGaCkEEclfEo8Ld6OBOzzJ3BkTVbrfqd41XhAhicA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dPFicRheSpuSsBE8ZFeE6HwwvkuIIecPQwHta0wibQuCqoSTqsc2K1KZDpJb3enDibBiau4EEhxrTYxA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ff43kUoicsmnll86ficaMcTpt1uZwVAmW8XEscyvU51uc9sdiaHViaJKMEZyiaM4bAaQfGIPNd26u2A5w/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**上百套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通源码网VIP，已开通各大源码站VIP**  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
