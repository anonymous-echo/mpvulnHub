#  whisper多商户客服系统存在前台SQL注入漏洞   
原创 XingYue404  星悦安全   2025-04-27 05:48  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/lSQtsngIibibSOeF8DNKNAC3a6kgvhmWqvoQdibCCk028HCpd5q1pEeFjIhicyia0IcY7f2G9fpqaUm6ATDQuZZ05yw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们 并设为  
星标  
## 0x00 前言  
  
    某兄弟向我求助一站，领导要求拿到后台权限，打开一看发现是  
二开的   
whisper 多商户客服系统，搜索网络已知漏洞 发现有XSS+任意文件读取，但目标站点貌似修复了.  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhnZTLib9SBmSicCaM8D6BIBiaDOkw7BnH6bibCUwupKUsKIQkKIk17oiaHOw/640?wx_fmt=png&from=appmsg "")  
  
于是去网上找到源码 开始审计  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhsIxRgMbEjur5icCZrdMLiaSAQm9jtWkydyYknGRf5D12LIffr5QOd7oQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhzVtiafF3YbeuRCQv1o1QIPTrmg3vpYkAaXmR3Ev76aiahiaeQFfQ8gLWw/640?wx_fmt=png&from=appmsg "")  
  
框架:ThinkPHP 5.1.39 Debug:True  
## 0x01 漏洞分析&复现  
  
经过一番波折，在某处控制器模块下找到了SQL传参，且未加过滤的地方，但由于报错抑制，所以只能时间+布尔注入了  
  
Payload:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhLAicjlwbkyoFJ93QQIYMDbJT3xS4S1LMvETR9JZnwnQJlAJDmj9efEA/640?wx_fmt=png&from=appmsg "")  
  
![image.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhLl0quAgVqm8zUnzOs9zIfzzZUJIGeHdTfLldEWsJw0CV0MyGvfKB6A/640?wx_fmt=other&from=appmsg "")  
  
完整Payload及whisper源码放文末自取!  
  
如果文件读取洞还在，即可组合拳变为报错注入，需要写一个脚本，也是简单的.  
  
收工 收工  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5efdn10OrI6KuJRynyF3BIh3DpBrOqmez293luWicibXQaN8kgu3oo2O6HnzickFSmra054CgiaHvkmwA/640?wx_fmt=png&from=appmsg "")  
  
去随便测了几个站，发现注入是通杀的噢，小0day啦.  
## 0x02 知识星球  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
  
完整POC及源码已放在知识星球中，需要可自取!!!  
  
**高质量漏洞利用研究，代码审计圈子，每周至少更新三个0Day/Nday及对应漏洞的批量利用工具，团队内部POC，源码分享，星球不定时更新内外网攻防渗透技巧以及最新学习，SRC研究报告等。**  
  
**【圈子权益】**  
  
**1，一年至少999+漏洞Poc及对应漏洞批量利用工具**  
  
**2，各种漏洞利用工具及后续更新，渗透工具、文档资源分享**  
  
**3，内部漏洞库情报分享（目前已有150000+poc，会每日更新，包括部分未公开0/1day）**  
  
**4，加入内部微信群，遇到任何技术问题都可以进行快速提问、讨论交流；**  
  
**5，Fofa API 高级会员Key共享**  
  
**6,  高自动化代码审计工具共享**  
  
**圈子目前价格为已涨价至129元，现在星球有1000+位师傅相信并选择加入我们**  
  
****  
**网站源码及漏洞库已于2025.4.27日更新**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5efdn10OrI6KuJRynyF3BIhdAXFwVWOKu2WkpehPyeW6H8u2unE5Tg297xNHhicv7y4dE1rXmHGGCQ/640?wx_fmt=jpeg&from=appmsg "")  
  
Fofa 高级会员 Key****  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dJt1pKCAicLgADFELyD7N2yh7LPSCjwdicjVT9I5kmk5d53XibibUmzz037tTfQx5prf7j21ed3oVTkQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
超多审计资料，自动化审计工具  
  
![319d33192f5a9f019ec3f7a17cc25bb.png](https://mmbiz.qpic.cn/sz_mmbiz_jpg/uicic8KPZnD5fOtUasHrnibBFTUkOIJJH5Goe8FhSg3arBlw7QLWsJl3xiczb5QnWfRKiaSvcMBPHLuwFjkWuuFicDwQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dVAUWP6LibARs3usK4kNz6g367ZEv3pT7cv8fl3YHMZH47sBH2IMy1J2XYeMNVXDJgLhP1yahI4pw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
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
  
**上千套审计源码，包括各种协同办公OA**  
  
****  
**入圈之后可私信我帮你开通永久VIP，已开通各大源码站VIP**  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5ddnP3GPD4EFbjricqxLYKEMbdFQjC7ZWqVCo8nDCz3kL1UhibTicP4Nmb2fa2RmsYHtXUiacMlkYkCNg/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5dbasJicXJDEOR85icHkfIda3gg2HpaWjW2MZN9KZdGzX99Ofl7SRETFA4TicFabIO2UGibSONn6bhXQw/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**高质量代码审计社区**  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/uicic8KPZnD5eYsOmVcqiczEs2xZkicGt1u6HibInHPVngJzcM5jLf64ncdDFEN0Sfzo5jFkUspBiaCTftaSsheb5JIQ/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**标签:代码审计，0day，渗透测试，系统，通用，0day，闲鱼，转转**  
  
**PS:关注公众号，持续更新漏洞文章**  
  
  
**免责声明:****文章中涉及的程序(方法)可能带有攻击性，仅供安全研究与教学之用，读者将其信息做其他用途，由读者承担全部法律及连带责任，文章作者和本公众号不承担任何法律及连带责任，望周知！！!**  
  
