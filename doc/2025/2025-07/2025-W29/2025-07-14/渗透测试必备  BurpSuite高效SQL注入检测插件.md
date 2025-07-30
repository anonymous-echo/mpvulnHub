> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247495334&idx=1&sn=368a3bc195d26880d00acf104e6f6c93

#  渗透测试必备 | BurpSuite高效SQL注入检测插件  
saoshao  星落安全团队   2025-07-14 16:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/spc4mP9cfo75FXwfFhKxbGU93Z4H0tgt4O9libYH9mKfZdHgvke0CeibvXDtNcdaqamRk3dEEcRQiaWbGiacZ2waVw/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
点击上方  
蓝字  
关注我们  
  
![](https://mmbiz.qpic.cn/mmbiz_png/WN0ZdfFXY80dA2Z4y8cq7zy2dicHmWOIib5sIn8xAxRIzJibo2fwVZ3aicVBM8RnAqRPH5Libr4f02Zs5YnMLBcREnA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
现在只对常读和星标的公众号才展示大图推送，建议大家能把  
**星落安全团队**  
“  
**设为星标**  
”，  
否则可能就看不到了啦  
！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/rlSBJ0flllkXnsUODwVWmlxAHuHu4dBuwIlu707ZfPdbNTYyibYzQHA0xn0p2hTbQAiba04SOnDiadxVExZ53nfog/640?wx_fmt=other&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**工具介绍**  
  
**DetSql**  
是基于 BurpSuite Java 插件 API 开发的 SQL 注入探测插件，主要作用为快速从 http 流量中筛选出可能存在 SQL 注入的请求，在尽可能减少拦截的情况下提高 SQL 注入测试效率。  
  
注意：**DetSql**  
采用 Montoya API 进行开发，BurpSuite 版本需满足（>=2023.12.1）。  
  
**使用方法**  
  
插件装载: Extensions - Installed - Add - Select File - Next  
  
主面板（dashboard）  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkiaPPz0jSPmS5wTMoerk28FstcuE0zQBcFQAWibqBzzjkUt36XibeuyA1ZOqSf0Seryk1JiaB45p5ScQ/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
  
在Logger模块中查看扫描流量，选择Extensions类型如下  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkiaPPz0jSPmS5wTMoerk28FnIgU2mTghDEUWDa49NibaXkqctd0DOkEv0nHcZYIBgB5OrZQCpg2vkw/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
  
例子  
  
报错类型页面  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkiaPPz0jSPmS5wTMoerk28F3cMl3WMhP4oaokicEuxJmaBrQrh1CzYTrNzgtyYfyiaib7fegJv1loAOg/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
  
order类型页面  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkiaPPz0jSPmS5wTMoerk28F6PLiaOZwIKnOyQbRbjTRZA9pFbL4xXM680LRQBARZ7udq9FJQDQQdjA/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
  
数字类型页面  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkiaPPz0jSPmS5wTMoerk28FXlfvyPfd5XAnFexRsLVA8q1VJic4cPCXw2US0HN8UUS4QIicNibYJethg/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
  
字符类型页面（包含多种类型）  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0flllkiaPPz0jSPmS5wTMoerk28FYY2f5SISNkBZApqYEj52VrWSiaBmYL0ekuRlV53M1Ug2pzqjWSmvvag/640?wx_fmt=other&from=appmsg "")  
![]( "")  
![]( "")  
  
  
**双引号问题**  
  
由于双引号闭合的情况出现极少，此处仍在报错类型中保留了双引号的原因，经本人测试出现过双引号报错的情况，因此仍在报错类型保留了双引号，如想自行设置报错payload可在配置面板自行设置。  
  
  
**相关地址**  
  
**关注微信公众号后台回复“入群”，即可进入星落安全交流群！**  
  
关注微信公众号后台回复“  
20250715  
**”，即可获取项目下载地址！**  
  
****  
  
  
**圈子介绍**  
  
博主介绍  
：  
  
  
目前工作在某安全公司攻防实验室，一线攻击队选手。自2022-2024年总计参加过30+次省/市级攻防演练，擅长工具开发、免杀、代码审计、信息收集、内网渗透等安全技术。  
  
  
目前已经更新的免杀内容：  
- 部分免杀项目源代码  
  
- 一键击溃360+核晶  
  
- 一键击溃windows defender  
  
- 一键击溃火绒进程  
  
-    
CobaltStrike4.9.1Linux星落专版   
  
-    
CobaltStrike免杀加载器  
  
- 数据库直连工具免杀版  
  
- aspx文件自动上线cobaltbrike  
  
- jsp文件  
自动上线cobaltbrike  
  
- 哥斯拉免杀工具   
XlByPassGodzilla  
  
- 冰蝎免杀工具 XlByPassBehinder  
  
- 冰蝎星落专版 xlbehinder  
  
- 正向代理工具 xleoreg  
  
- 反向代理工具xlfrc  
  
- 内网扫描工具 xlscan  
  
- CS免杀加载器 xlbpcs  
  
- Todesk/向日葵密码读取工具  
  
- 导出lsass内存工具 xlrls  
  
- 绕过WAF免杀工具 ByPassWAF  
  
- 等等...  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
目前星球已满600人，价格由208元  
调整为  
218元(  
交个朋友啦  
)，700名以后涨价至268元！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_jpg/rlSBJ0fllllyt22dcoYBLwGzF4lN7RDVpQyt07UVL9ibZzBftqV0loVG5gEs45D6q4ecA73IdEddwIGo7ZiaDnaA/640?wx_fmt=jpeg&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/MuoJjD4x9x3siaaGcOb598S56dSGAkNBwpF7IKjfj1vFmfagbF6iaiceKY4RGibdwBzJyeLS59NlowRF39EPwSCbeQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
     
往期推荐  
     
  
  
1.   
[学不会全额退款 | 星落免杀第一期，助你打造专属免杀武器库](https://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247494072&idx=1&sn=e46a6d176a8fad2aa4b4c055de3607da&scene=21#wechat_redirect)  
  
  
  
2.   
[【干货】你不得不学习的内网渗透手法](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489483&idx=1&sn=0cbeb449e56db1ae48abfb924ffd0b43&chksm=c0e2bc74f79535622f39166c8ed17d5fe5a2bbc3f622d20491033b6aa61d26d789e59bab5b79&scene=21#wechat_redirect)  
  
  
  
3.   
[【免杀】CobaltStrike4.9.1二开 | 自破解 免杀 修复BUG](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247488486&idx=1&sn=683083d38a58de4a95750673d9cb725d&chksm=c0e2b859f795314f3b7bc980a5d4114508ee2c286bc683cdfd25eefa4fb59f26adfe5483690b&scene=21#wechat_redirect)  
[！](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247486966&idx=1&sn=3f144d5936d5cdc11178004549384ace&chksm=c0e2a649f7952f5f7557dde6e9cca53ecee7b5e2f7ff23395250e8fe47acb102902d9727185d&scene=21#wechat_redirect)  
  
  
  
4.   
[【免杀】原来SQL注入也可以绕过杀软执行shellcode上CoblatStrike](http://mp.weixin.qq.com/s?__biz=MzkwNjczOTQwOA==&mid=2247489950&idx=1&sn=a54e05e31a2970950ad47800606c80ff&chksm=c0e2b221f7953b37b5d7b1a8e259a440c1ee7127d535b2c24a5c6c2f2e773ac2a4df43a55696&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/DWntM1sE7icZvkNdicBYEs6uicWp0yXACpt25KZIiciaY7ceKVwuzibYLSoup8ib3Aghm4KviaLyknWsYwTHv3euItxyCQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
【  
声明  
】本文所涉及的技术、思路和工具仅用于安全测试和防御研究，切勿将其用于非法入侵或攻击他人系统以及盈利等目的，一切后果由操作者自行承担！！！  
  
