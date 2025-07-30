#  实战 | 记一次1000美金的TikTok盲打XSS的漏洞挖掘   
 Z2O安全攻防   2024-09-29 21:14  
  
大家好，  
在本文中，我将分享我在  
2个TikTok资产发现的XSS漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VM2D9bOcbv6oXJtq8SXia05Z0ZoNcnPdUMRKsBXWBfqMjPUEmkpLQd0QQ/640?wx_fmt=jpeg "")  
  
当我决定在TikTok 程序中寻找漏洞 时，我花了1个月的时间寻找这个XSS。  
  
当我在TikTok 卖家账户( https://seller-id.tiktok.com/ )上创建产品时，这个 XSS 发现开始了  
  
我在卖家账户的产品名称中插入了 XSS payload。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VMPPbK2hRhaRSvVHyiakz1s6ESg22fsoAYmv8Vl73jCtb64rW1uialswxQ/640?wx_fmt=jpeg "")  
  
结果是我得到的https://seller-id.tiktok.com/上没有 XSS 。我决定不再在那里寻找 XSS。  
  
第二天，当我继续测试TikTok Android Apps 资产时，我发现了我的产品的功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VM0Dvjryf7tiaVWCfscdMuPfFWsgwhYVw9WRKGOiaOFmR2zxKILY7jjTPA/640?wx_fmt=png "")  
  
我试图从上面的**Share**功能中查看产品 URL 位置。  
  
我得到一个表单的 URL：  
  
https://oec-api.tiktokv.com/view/product/1231414124124124  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VM3KOxIkbc9RiaCEasu9ib9b164pwkEDMrjfWH1jbaZtlVppx6ypJsWctA/640?wx_fmt=jpeg "")  
  
结果是一样的，这里没有XSS :(  
  
我沉默了片刻，试图查看页面的视图源。  
  
显然我在那里发现了一个易受攻击的 XSS片段，其形式如下：  
```
<meta name='keywords' content='[ "><img src=x onerror=alert()>] , TikTok, TokTok Shop' />
```  
  
这就是让我放弃的原因，但在我知道回复的片段后，我试图从TikTok 卖家账户（https://seller-id.tiktok.com/）中更改我的产品名称。  
  
现在我使用带有单引号 ( ' )前缀的 XSS payload：  
```
'><img src=x onerror=alert()>
```  
  
最后出现一个弹出窗口:)  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VMoRiakCrppoRdNuvy7evcZRGE4Ls3o1hfBicU9xicNWTCyLmjCdyt57y2w/640?wx_fmt=jpeg "")  
  
让我们看看来自视图源的响应：  
```
<meta name='keywords' content='[ '><img src=x onerror=alert()>] , TikTok, TokTok Shop' />
```  
  
是的，'>前缀用于关闭META TAG中的输入值。我在这里存储了 XSS Blind。  
  
我喜出望外，立即向TikTok团队汇报。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VMvlYnDa6xe9O0q2b7z9mgtKR1XsAXhrQVDEehRHgYViajgQrOaUXPsSg/640?wx_fmt=gif "")  
  
报告完问题后，我继续测试，结果发现在我最初的发现中发现了受 XSS 影响的其他TikTok资产的 URL。  
  
受影响的资产是https://shop.tiktok.com/  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/Uq8QfeuvouicwvjzwFcnsMq0Z32qAQ4VMwiaHmCoTGC1RMCMRIrs3f4HWjGqP9zX4mIcwUOoomF7LXM6NpqPwHDA/640?wx_fmt=jpeg "")  
  
我还向TikTok团队报告了这一发现，最后获得了1000美金的赏金。  
# 报告详情  
  
https://hackerone.com/reports/1554048  
  
受影响的资产：  
  
https://oec-api.tiktokv.com/  
  
https://shop.tiktok.com/  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
# 技术交流  
  
  
### SRC专项漏洞知识库  
  
  
建立了一个  
src专项圈子，内容包含**src漏洞知识库**、**src挖掘技巧**、**src视频教程**等，一起学习赚赏金技巧，以及专属微信群一起挖洞  
  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、小群一起挖洞
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCOPMibnJIeBT6Yv0RwBJT9AFHKEbo3BxYkLnE00jVuoLicSOBCIzMiaJKQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKubLTHiahoUQXk6w3ZygUmba5pbYMnHdozaib1EDaiaUtZuGxqVAqY5KjSibtfcM5TXiaYtCPVq0bc3dprg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKuZDDDv3NsbJDuSicLzBbwVDCPFgbmiaJ4ibf4LRgafQDdYodOgakdpbU1H6XfFQCL81VTudGBv2WniaDA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "null")  
  
图片  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIx3z6YtXqmOkmp18nLD3bpyy8w4daHlAWQn4HiauibfBAk0mrh2qNlY8A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
图片![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugI5tZcaxhZn1icWvbgupXzkwybR5pCzxge4SKxSM5z4s9kwOmvuI3cIkQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
图片  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKub5zKpgA0HmT6klBJg9IugIstia27YLJFBtC5icJO6gHLLgzRDqib6upI3BsVFfLL02w6Q8jIRRp0NJA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**app****" 获取  app渗透和app抓包教程**  
  
**回复“**  
**渗透字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档**  
