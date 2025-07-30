#  挖洞日记 | 记一次不断FUZZ拿下高危越权漏洞   
原创 zkaq-腾风起  掌控安全EDU   2025-05-11 04:02  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  腾风起 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
## 前言  
  
一个迎新系统，和师傅们一起提升一下权限  
## 敏感信息泄露 1  
  
进去系统，先挨个功能点瞅瞅，没发现上传点，找到了有敏感信息泄露的点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqas0PNGVzWkoibvJONKNchKL52AC71KaBaTv4LCuf3j4Ddw179d7tW3vdQ/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到只有七十条，太少  
## 敏感信息泄露 2  
  
继续走其他的功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasibE9XYw431J7ibHlw5y04fe8NeN05mbec9s0fg4IfjBxKqia5ECdD5Gow/640?wx_fmt=png&from=appmsg "")  
  
  
可以看到这里有更加详细的每个人的信息  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasCnFg4uuibzeQ79VA6qHI1zWZLQ3PjmTcoJ1ruKsfG4sYzlSkGIjsCKQ/640?wx_fmt=png&from=appmsg "null")  
  
  
到这儿肯定是都没必要交，继续往下点功能点  
## 敏感信息泄露 3  
  
在增加权限这里，泄露了全校 18 万+的学号和老师工号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasa1gOcTG1Oy7wEPKFqbRcHrAd4LWK0dwzGNPcfvsblAZviahCskk6mcw/640?wx_fmt=png&from=appmsg "")  
  
## 越权  
  
点击新增一个用户，看看报文  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasf0MKeGicCUTX3QJEV3SvP3lOo0Iur5Dd6e23Xf8Jv4cgCPlLRcS3sRw/640?wx_fmt=png&from=appmsg "")  
  
  
好的，只能看懂一个 ZGH 是职工号，DYBJ 是班级代码，没关系，这时候翻一下 http 历史包  
  
在这个报文知道了每一个参数的含义  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasW6rtKlDNx7y2ic13QnKMCJmkOhnGibL3vtKzicWBvibhUOrPibGHKhrJD8g/640?wx_fmt=png&from=appmsg "")  
  
  
这里我并不知道别的职工号的密码，所以增加权限这里我改成了我用的这个号的 id，别的先暂时置空看看情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqastmktDz24S7peS26e72KTmicgcAktdmVZU1uZ8jjYmU9azZ9pLicyqicCw/640?wx_fmt=png&from=appmsg "")  
  
  
呀授权用户增加了。嗯？奇怪啊，返回去看之前的敏感数据的点都没有增加还是 70 个，但是好像自己的权限可以提升了，有时候就是这么莫名其妙  
  
![img](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqass7dropP9feibPbyLpKRR5TSVq6HkkHqlsN7PBib0ARzBJCchx2XAxplw/640?wx_fmt=png&from=appmsg "null")  
  
  
好的置空不行，就尝试去改成别的什么*，之类的。之前的敏感数据的点都没有大量增加。  
  
于是乎按照规则改一下班级，这里我添加了几个专业，不同学院的  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasQJtAHLmQ9jfSV6CmnGkjicxrVaKajqyecIP1sumiczthU0ibIQqialDIJA/640?wx_fmt=png&from=appmsg "")  
  
  
诶哟哇靠，终于变了，学生敏感数据变成了 500+  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasDCF0ByaDJugPkmGqwBKPYSbUAUs8eMgzvazthOS98icqkDPBfPMArvA/640?wx_fmt=png&from=appmsg "")  
  
  
最后又不断尝试，发现遍历代表院系的DYBM 可以直接增加这个学院所有学生的敏感数据，这里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasJac7A9wh3icOan4VUFNIf4slVEsicNRq3SqAUjCCYj9Cxms7WX179TQA/640?wx_fmt=png&from=appmsg "")  
  
#### 可以得到全校所有人的sfz以及其他敏感信息，这里只是测试所以只遍历部分DYBM的id证明危害即可  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpIpibtiaypuc5SoaCSyzibqasknm1gzVWgNGIMztciaA61SnSICZbLFQhdApkDq1GE8denAm334hlRdQ/640?wx_fmt=png&from=appmsg "")  
  
  
结束啦  
  
   
  
申明：本公众号所分享内容仅用于网络安全技术讨论，切勿用于违法途径，  
  
所有渗透都需获取授权，违者后果自行承担，与本号及作者无关，请谨记守法.  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**没看够~？欢迎关注！**  
  
  
  
**分享本文到朋友圈，可以凭截图找老师领取**  
  
上千**教程+工具+交流群+靶场账号**  
哦  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
******分享后扫码加我！**  
  
  
**回顾往期内容**  
  
[零基础学黑客，该怎么学？](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247487576&idx=1&sn=3852f2221f6d1a492b94939f5f398034&chksm=fa686929cd1fe03fcb6d14a5a9d86c2ed750b3617bd55ad73134bd6d1397cc3ccf4a1b822bd4&scene=21#wechat_redirect)  
  
  
[网络安全人员必考的几本证书！](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247520349&idx=1&sn=41b1bcd357e4178ba478e164ae531626&chksm=fa6be92ccd1c603af2d9100348600db5ed5a2284e82fd2b370e00b1138731b3cac5f83a3a542&scene=21#wechat_redirect)  
  
  
[文库｜内网神器cs4.0使用说明书](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247519540&idx=1&sn=e8246a12895a32b4fc2909a0874faac2&chksm=fa6bf445cd1c7d53a207200289fe15a8518cd1eb0cc18535222ea01ac51c3e22706f63f20251&scene=21#wechat_redirect)  
  
  
[记某地级市护网的攻防演练行动](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247543747&idx=1&sn=c7745ecb8b33401ae317c295bed41cc8&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
