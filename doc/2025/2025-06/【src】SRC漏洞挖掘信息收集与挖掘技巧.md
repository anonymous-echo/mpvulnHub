#  【src】SRC漏洞挖掘信息收集与挖掘技巧   
rggb  神农Sec   2025-06-04 01:02  
  
扫码加圈子  
  
获内部资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，EDUSRC证书站挖掘、红蓝攻防、渗透测试等优质文章，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。加内部圈子，文末有彩蛋（知识星球优惠卷）。  
#   
  
文章作者：rggb  
  
文章来源：  
https://www.freebuf.com/articles/web/237876.html  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**SRC漏洞挖掘信息收集与挖掘技巧**  
  
  
子域名收集### 暴力破解  
  
本地工具，Layer的子域名挖掘机等工具。  
  
优点：能够枚举到很多通过证书查询查不到的子域名。  
  
缺点：速度慢，靠字典。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8zVLNgiarMvXQHsbVjyzlLXEuGrXW04OKrhoPBLv7A0eeia8ibXyNPIhmA/640?wx_fmt=png&from=appmsg "")  
### 搜索引擎搜索  
  
Google、百度、360、bing、搜狗等主流搜索引擎，通过搜索语法进行搜索。  
  
优点：发现域名时往往会同时发现一些敏感的页面。  
  
缺点：收录有限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8icbcuJars58FibXXuWgVKsmk8xxYCibAyRtWzhpIEoZ73W5X5vKRg4LLw/640?wx_fmt=png&from=appmsg "")  
### 证书查询  
  
常用证书查询的站点: censys.io crt.sh 等等。  
  
优点：可以发现暴力破解无法爆破出来的子域，例如：test-xxxxx-xxxx.baidu.com  
  
缺点：收录有限。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8O0k24yLZ8VmPU8Pmwszia0mYOqiatLKUTBMpa2ksEregSVZgYMERHvRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8qziaTqVwFtz7IuxPkBeprQebmvtjDbHptxvpFaPvTS2fkichtCUpn9nQ/640?wx_fmt=png&from=appmsg "")  
### 利用IP进行反查域名  
  
常用的站点:ip138、微步在线 VIRUSTOTAL等等  
  
优点：能够发现很多通过搜索引擎、证书查询、暴力破解都无法发现的子域名。  
  
缺点：微步需要积分进行查询，其他平台相对微步数据不是那么全面。  
  
VIRUSTOTAL查询写了一个小脚本 供大家参考。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8c1hnzABJv11LNzd7qxpcBsMYfml7QepRwAEWUQFBxrvo0VHVcEQXLQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8dkAhRKreOIianglbSe5piaBibOKa8QBlgUgWNFqHvzlPUlDZtkIibfuLyQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8l679Cutt2BaMrbRvjTt8QezaGNVjw25D6YxkCWKodxYDrxBOMZfMUg/640?wx_fmt=png&from=appmsg "")  
### IP地址块收集  
  
常用的站点: CNNIC  
  
收集IP地址块对IP地址进行反查域名能够发现很多资产。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8r58jgkWcZDTWRsKpnswib38OTpyAia14Wicy8zwiaMaSO7rA5xG42gC2MQ/640?wx_fmt=png&from=appmsg "")  
### 主机端口探测  
  
常用的工具有:nmap、masscan等等  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8ic6FMASNKVM4DpuanpUAexYLBiahBxxmIia8vU3H6nmfCshNU5laGiaLTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8R4jkNQXQf7cpE8iaZ6oRzGZToCd3UUvmybUnArP8KJUAJrK5dA13WkA/640?wx_fmt=png&from=appmsg "")  
### 微信公众号、小程序  
  
微信是日常生活中用的最多的软件之一，通过微信公众号、小程序可以获得部分域名或ip地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8l36SaFKZkFTkRDXF4xgJTlcoG9CD6Z6xvQHZaEkvAruKyS1wPVA1zg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8USnLj2V84icYAmm31PIpQjrlKGmsP4wMmyibzy4vARZ9YW26LfRkomKw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8ggdQ8QmuZpFYodgZgXuhia0yyC2mRMryh8gVu9rnU2pVLTdx93yIzCg/640?wx_fmt=png&from=appmsg "")  
### APP收集  
  
通过对APP流量的抓取也可以获取到部分子域名或者ip。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8U3ucmiaxBDtHe5bcHModzRiahNj701wEgaxsrqMYyMmZiaxEtYNroicKPA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8m2dTIfkG9N7Dy5kXCgXxQQxqfN5lxkScLbGtibZIAwEgn5UoicLl9qSw/640?wx_fmt=png&from=appmsg "")  
### 其他方面信息收集  
  
通过百家号、微博、抖音、快手、哔哩哔哩等媒体公众号，可以收集到员工的账号。或是不小心泄露出来的一些web服务。当收集到qq群这种信息时还可以"潜伏"到qq群，qq群文件可能会包含一些敏感的信息。这方面的信息收集能够帮助我们在漏洞利用时构造一些参数值或是进行暴力破解等等。  
## 漏洞挖掘小技巧  
### F12、查看源文件大法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8VpsOYzzvr5ic04XhBvbB8uFKkoMiaYpj3909hDFxVlgM3gYx8zlgLiaTg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8FlibZRUg63kkhicQesbFY4GGoPv7DVd0aar7Xue6xtxhbZl7FssulKZg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8907StWfWtEqqbIlI43SI19xPSZCqskWIHP4eDMcPN449V3jD9HJE1Q/640?wx_fmt=png&from=appmsg "")  
  
在漏洞挖掘时可以多多查看“源文件”，越来越多的站点使用webpack进行打包会导致接口暴露等信息暴露，看似比较乱的js通过js格式化就能很好的进行阅读发现问题。  
  
F12大法可以发现页面在打开时有没有请求一些接口，访问接口路径构造敏感页面进行漏洞探测。  
  
例如：添加swagger-ui.html 可以访问到swagger服务。如果服务端对swagger-ui.html这个页面进行了限制可以通过/v2/api-docs 来获取API  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8JQfJ6rvFvdAo8V52jzOxHLibbmn6iaobZsjXk1ra3PdiaUIQX6oKLFGWA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8lia3UtibD8D6UT1Lib9ZWhvibALkdmEBImvTFiaTXTgze6QQwiaM2fDRAyTw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0Jo3WicChuBKOsyicHRR2X8Ex16jSPStT7Xoj9J4gKHTuUO55hZcuG3dcQzD6ibnoQdwoXC3b9Z8EQ/640?wx_fmt=png&from=appmsg "")  
## 总结  
> 1.挖掘SRC漏洞时，对于子域名的收集至关重要，子域名的多少决定了漏洞的产出。  
> 2.在进行信息收集时尽可能的做到全面，这样能最大限度上获取到子域名。  
> 3.进行漏洞挖掘时要细心，JS中蕴藏着宝藏。  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**内部圈子详情介绍**  
  
我们是  
神农安全  
，点赞 + 在看  
 铁铁们点起来，最后祝大家都能心想事成、发大财、行大运。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/mngWTkJEOYJDOsevNTXW8ERI6DU2dZSH3Wd1AqGpw29ibCuYsmdMhUraS4MsYwyjuoB8eIFIicvoVuazwCV79t8A/640?wx_fmt=png&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap086iau0Y0jfCXicYKq3CCX9qSib3Xlb2CWzYLOn4icaWruKmYMvqSgk1I0Aw/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
**内部圈子介绍**  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0F0PmZricIVE4aZnhtO9Ap08Z60FsVfKEBeQVmcSg1YS1uop1o9V1uibicy1tXCD6tMvzTjeGt34qr3g/640?wx_fmt=gif&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
  
**圈子专注于更新src/红蓝攻防相关：**  
  
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
  
  
  
  
**内部圈子**  
**专栏介绍**  
  
知识星球内部共享资料截屏详情如下  
  
（只要没有特殊情况，每天都保持更新）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibRSekfPpgmzg6Pn4yH440wEZhQZaJaxJds7olZp5H8Ma4PicQFclzGbQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWYcoLuuFqXztiaw8CzfxpMibgpeLSDuggy2U7TJWF3h7Af8JibBG0jA5fIyaYNUa2ODeG1r5DoOibAXA/640?wx_fmt=png&from=appmsg "")  
  
  
**知识星球——**  
**神农安全**  
  
星球现价   
￥45元  
  
如果你觉得应该加入，就不要犹豫，价格只会上涨，不会下跌  
  
星球人数少于800人 45元/年  
  
星球人数少于1000人 60元/年  
  
（新人优惠卷20，扫码或者私信我即可领取）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJHePfxfpEBEibsuTPjTxtvvTaS1M05C10sGweR6sKjhnt9amVS3aPicGQ/640?wx_fmt=png&from=appmsg "")  
  
欢迎加入星球一起交流，券后价仅45元！！！ 即将满800人涨价  
  
长期  
更新，更多的0day/1day漏洞POC/EXP  
  
  
  
**内部知识库--**  
**（持续更新中）**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFu12KTxgSfI69k7BChztff43VObUMsvvLyqsCRYoQnRKg1ibD7A0U3bQ/640?wx_fmt=png&from=appmsg "")  
  
  
**知识库部分大纲目录如下：**  
  
知识库跟  
知识星球联动，基本上每天保持  
更新，满足圈友的需求  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFhXF33IuCNWh4QOXjMyjshticibyeTV3ZmhJeGias5J14egV36UGXvwGSA/640?wx_fmt=png&from=appmsg "")  
  
  
知识库和知识星球有师傅们关注的  
EDUSRC  
和  
CNVD相关内容（内部资料）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFKDNucibvibBty5UMNwpjeq1ToHpicPxpNwvRNj3JzWlz4QT1kbFqEdnaA/640?wx_fmt=png&from=appmsg "")  
  
  
还有网上流出来的各种  
SRC/CTF等课程视频  
  
量大管饱，扫描下面的知识星球二维码加入即可  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUw2r3biacicUOicXUZHWj2FgFxYMxoc1ViciafayxiaK0Z26g1kfbVDybCO8R88lqYQvOiaFgQ8fjOJEjxA/640?wx_fmt=png&from=appmsg "")  
  
  
  
不会挖CNVD？不会挖EDURC？不会挖企业SRC？不会打nday和通杀漏洞？  
  
直接加入我们小圈子：  
知识星球+内部圈子交流群+知识库  
  
快来吧！！  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJ5wUOL9GnsxoXibKezHTjL6Yvuw6y8nm5ibyL388DdDFvuAtGypahRevg/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWUMULI8zm64NrH1pNBpf6yJO0FHgdr6ach2iaibDRwicrB3Ct1WWhg9PA0fPw2J1icGjQgKENYDozpVJg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
内部小圈子——  
圈友反馈  
（  
良心价格  
）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8Hviaqs0Uv6F4NTNkTKDictgOV445RLkia2rFg6s6eYTSaDunVaRF41qBibY1A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWW0s5638ehXF2YQEqibt8HviaRhLXFayW3gyfu2eQDCicyctmplJfuMicVibquicNB3Bjdt0Ukhp8ib1G5aQ/640?wx_fmt=png&from=appmsg "")  
  
  
****  
**神农安全公开交流群**  
  
有需要的师傅们直接扫描文章二维码加入，然后要是后面群聊二维码扫描加入不了的师傅们，直接扫描文章开头的二维码加我（备注加群）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWV3tDTbzdQK4qCdxgHkSbgibaLP4ChjjO3BIeMgdTz3YelibqGvekSLXV3s1JpWkncKqYgbfZvOLENg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
    
```
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/b7iaH1LtiaKWW8vxK39q53Q3oictKW3VAXz4Qht144X0wjJcOMqPwhnh3ptlbTtxDvNMF8NJA6XbDcljZBsibalsVQ/640?wx_fmt=gif "")  
  
  
  
