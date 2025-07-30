#  一款Spring图形化综合漏洞的利用工具   
charonlight  安全之眼SecEye   2024-05-10 20:20  
  
点击上方「蓝字」，关注我们  
  
因为公众号现在只对常读和星标的公众号才能展示大图推送，建议大家进行星标  
。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76k4fD8m0rkPrAict2lkdiaUHasZshA7Yibv0OpnNzpPKLRbGBC8ib7Fngn81sYBPpOaObsyU2iceZ4XPicQ/640?wx_fmt=png&from=appmsg "")  
  
  
01  
  
# 免责声明  
  
  
**免责声明：**  
该公众号分享的安全工具和项目均来源于网络，仅供安全研究与学习之用，如用于其他用途，由使用者承担全部法律及连带责任，与工具作者和本公众号无关。  
  
  
02  
  
# 文章正文  
  
  
### 0x01 前言  
  
工具目前支持Spring Cloud Gateway RCE(CVE-2022-22947)、Spring Cloud Function SpEL RCE (CVE-2022-22963)、Spring Framework RCE (CVE-2022-22965) 的检测以及利用，目前仅为第一个版本，后续会添加更多漏洞POC，以及更多的持久化利用方式  
### 0x02 工具使用说明  
  
**单个检测&&批量检测**  
  
工具支持单个漏洞单个目标检测，也支持多个目标检测  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1feDtI5XVkfnjv0dgnxQWMnub4oQHIkoAHO9LrC1hzcOX6YXCm2VR3BA/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1fV6oxIxwxlBuF5kcKNP2Mf2XK3mQibY180Ysz5ncTjDPQtTo0Jxu4NTQ/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1fXZYYibJIjPckMJXcCaFRGkdU1MQt24fynVroDlkjsMS2MMoq3glFvzw/640?wx_fmt=png&from=appmsg "null")  
  
**漏洞利用**  
  
Spring Cloud Gateway RCE(CVE-2022-22947) 目前支持命令执行、一键反弹shell、哥斯拉内存马注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1f6FiceRmHZnIwttoVCiaxFsseHOTPV1qCP1flJpmKhqmTiau3V5XlNyI5g/640?wx_fmt=png&from=appmsg "null")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1fYUwlia2xClXxyKJoKZGP7FzNBXYNJuGdCUVTchupgy0mTy5QlAL5IuA/640?wx_fmt=png&from=appmsg "null")  
  
Spring Cloud Function SpEL RCE (CVE-2022-22963)目前支持一键反弹shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1fNnRHybjKlE56cdptUpHWLZSOsjTBb1NMuaJfmiaGDCJKLW1KKrFA3kg/640?wx_fmt=png&from=appmsg "null")  
  
Spring Framework RCE (CVE-2022-22965) 目前支持命令执行，通过写入webshell实现的，后续会继续实现写入ssh公钥、计划任务等利用方式  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76mjeV7g0d6S1sicfvHSojU1fMibzIgwH1xGoOMJ3icw8uz3icicZjdDNE8p3IOicMsFic2kFkBBUQ9L3iaKfA/640?wx_fmt=png&from=appmsg "null")  
  
回复关键字【  
**20240510**】领取工具  
  
  
03  
  
# 知识星球  
  
  
**【圈子简介】**  
  
**高质量漏洞利用工具、最新漏洞POC/EXP分享社区，日常更新一个0Day/Nday/1day及对应漏洞的批量利用工具，内部POC分享，星球不定时更新内外网攻防渗透技巧等。分享行业最新资讯，交流解答各类技术问题。**  
  
**【圈子服务】**  
1. **Fofa永久高级会员，助力挖洞**  
  
1. **常态化更新最新的漏洞POC/EXP**  
  
1. **常态化更新未公开、半公开漏洞POC**  
  
1. **常态化更新优质外网打点、内网渗透工具**  
  
1. **常态化更新安全资讯**  
  
1. **开放交流环境，解决成员问题**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76kefyoAP2kELVOnW1PJe79111sSF8J3BGRaglm4y5icey31Z8gU90M9Z9KVibXSjn3YAfLnYUhhmr4g/640?wx_fmt=png&from=appmsg "")  
  
  
点个「在看」，你最好看  
  
  
