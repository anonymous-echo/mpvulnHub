#  【重磅更新】Struts2全版本漏洞检测工具   
abc123info  安全之眼SecEye   2024-05-26 20:30  
  
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
  
  
### 工具简介  
  
Struts2全版本漏洞检测工具  
### 工具使用  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/FUKJN1fH76lxG04EEHSdGHfV71ISk3R81JAvoEn0noImy3iawOj5PMyiav8FY7icJbMJeIjF1JyPDG7icNibnIOzPUg/640?wx_fmt=png&from=appmsg "")  
  
1、点击“检测漏洞”，会自动检测该URL是否存在S2-001、S2-005、S2-009、S2-013、S2-016、S2-019、S2-020/021、S2-032、S2-037、DevMode、S2-045/046、S2-052、S2-048、S2-053、S2-057、S2-061、S2相关log4j2十余种漏洞。  
  
2、“批量验证”，（为防止批量geshell，此功能已经删除，并不再开发）。  
  
3、S2-020、S2-021仅提供漏洞扫描功能，因漏洞利用exp很大几率造成网站访问异常，本程序暂不提供。  
  
4、对于需要登录的页面，请勾选“设置全局Cookie值”，并填好相应的Cookie，程序每次发包都会带上Cookie。  
  
5、作者对不同的struts2漏洞测试语句做了大量修改，执行命令、上传功能已经能通用。  
  
6、支持GET、POST、UPLOAD三种请求方法，您可以自由选择。（UPLOAD为Multi-Part方式提交）  
  
7、部分漏洞测试支持UTF-8、GB2312、GBK编码转换。  
  
8、每次操作都启用一个线程，防止界面卡死。  
  
警告：该工具为漏洞自查工具，仅用来扫描及验证网站存在的Struts2漏洞，并可以协助管理员修复网站漏洞，也可用作授权的渗透测试，但严禁用于非授权的渗透测试、严禁用于攻击他人网站、严禁用于非法途径，否则后果自负。  
  
回复关键字【  
**240527**】领取工具  
  
  
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
  
  
