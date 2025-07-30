> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247550450&idx=1&sn=839edf2b6202dbff8a1099046333886e

#  EDUSRC | 记一次某学院小程序的打包（附小白小程序搜索思路）  
原创 zkaq-badland  掌控安全EDU   2025-06-16 04:02  
  
   
  
扫码领资料  
  
获网安教程  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -  badland 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（ https://bbs.zkaq.cn）**  
  
**本文涉及的相关漏洞均已修复，文章中敏感信息均已做打码处理哦！**  
  
作为一个挖洞两月半的小白，众所周知挖 WEB 还是太吃操作了，有没有简单的上分挖洞方式呢，有点兄弟有的，那肯定是微信小程序吖  
  
这里分享一下自己的小程序搜索思路吧：  
1. 1. 首先肯定是微信搜索框，量大从优，但是毕竟只要是带校名的都能搜，你能找到别人也能找到  
  
1. 2. 然后就是官方的 ICP 备案查询，这个有个优点就是能查到一些并不带校名的小程序，这样别人就不能直接在微信搜索框搜到，找一些偏远资产，也就是说小程序的事业单位确实是某学校，但是该小程序的名称里没有该大学名字（这也是从其他师傅那里学来的）  
  
附上地址：  
  
https://beian.miit.gov.cn/#/Integrated/recordQuery  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUl9vBOW5TpNOUQegsldU93mw7ic6sATlCy6JB4LQ2OCQbWD9lXBG0S9Q/640?wx_fmt=png&from=appmsg "null")  
  
  
3.还有发现小蓝本也可以，也能查找学校，详细页里面的新媒体也能看到该学校的各种公众号服务号包括小程序，虽然量也很多，但是存在里面有一些老站点或者小程序已经关站的情况哦  
  
附上地址：  
  
https://sou.xiaolanben.com/pc  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORU5svUSMpibblZicpgIkxAph28uF5rfDptlqT83hVKzHibPnA2oUSbTcUtA/640?wx_fmt=png&from=appmsg "null")  
  
  
接下来就是小白实战辣，其实算运气好，没啥操作捏（给佬磕头）  
  
首先通过 ICP 备案查询找到的某学院服务大厅  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUG8H5I12Xot5LOOXSuIKUJ1uFic2kibBK0kAzxnOnDCkxV3gNBic1s7n2Q/640?wx_fmt=png&from=appmsg "null")  
  
  
一．任意学生用户登录（勉强算是嘿嘿）  
  
发现可直接选择学号姓名登录，只要是该校学生都可以登录  
  
——这里小思路，关于找学校的姓名学号，其实可以直接问 AI，我一般是直接问小爱同学（很方便），都会帮你直接在网上收集然后返回噢，但是注意别直接问姓名学号，我一般都换个方式问，比如搜某个学校获奖学号等，因为学号也算是敏感信息，直接问学生姓名学号不会给你说的。如果实在没有，直接抖音小红书搜学生卡，没有办法辣！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORU7r3HgLn9KmgibZRuPTf7yI9ywvqE0qxjzk6H5Vjia8BySII6lk4tibmiag/640?wx_fmt=png&from=appmsg "null")  
  
  
此处用姓名学号成功登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUV37PpVELRssMTM6PdWzHZ1AwhqTVXbdibOZ8EJeXIuTfJFu0ZrATTmA/640?wx_fmt=png&from=appmsg "null")  
  
  
二．信息泄露（点击就送）  
  
点击办事大厅——学生学籍变更申请表，包括其他几个审核功能点，注意burp历史都泄露了审核老师的敏感信息（包括姓名，身份证号，电话，邮箱）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUDZ7MCLj4RN2D5HqLQc5aG8uBfojBuLoIAosuYdOc9rqX69VPlVAO9g/640?wx_fmt=png&from=appmsg "null")  
  
  
继续点击添加审核人  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUojLxDPuZGab1RCcjwg1ee4xGR2S9TeicIeiagOo7qEudbQjoW4zhQFrQ/640?wx_fmt=png&from=appmsg "null")  
  
  
输入任意数字直接暴露大量人员敏感信息（一看就没有鉴权），此处只输入2（平时看到带参数的可以试试数字/null/放空等）  
  
按理可直接暴露全校人员敏感信息并进行登录，这里估计限制了返回长度  
  
然后也可以重放修改name参数，也可将IdentityId改为1，换个数字又是另一批泄露  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUnWbIoBI4hfckAgG77OabzCAxeiaWS9ZbblqDlIicjTyQk7gM3unbLzibg/640?wx_fmt=png&from=appmsg "null")  
  
  
三. 管理审核人员任意登录  
  
因为前面功能点泄露了党委书记的工号和姓名和电话  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUSfh1jMFr8HSJichj8WRjEHo33gwClLgx6VZkIJ7YianibmFYeRKz8WsNQ/640?wx_fmt=png&from=appmsg "null")  
  
  
退出小程序，开启拦截重新进入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUUpiaGIccanWLbz06rZZOuG9qBzxK1G3IkJONOba3icZynMdclnbzhzCw/640?wx_fmt=png&from=appmsg "null")  
  
  
此参数直接修改  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUYT877ibvfD1A4Fz5OxG9Eta3iaQh3A8ibvFEnEpjHrJGDq9jx7tkTwe9A/640?wx_fmt=png&from=appmsg "null")  
  
  
放行请求包，关闭拦截，成功登录党委书记账号  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUHTxWk0V4gZFs5QOx5XFFIibJowafp7z2kkFO7DmWvMbNj03Xv56eibEw/640?wx_fmt=png&from=appmsg "null")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUMKen23lUf36aS3pxiauGyiaNuUxJjUESG5OEiajfKiaQWPjpPWYmeiafXYg/640?wx_fmt=png&from=appmsg "null")  
  
  
同理根据泄露信息重新登录其他管理人员的账号（全校都可）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcpENic7SH45B2vUPCnUFuORUr0afCCY7yrLkKRJzhOVuW2eCdq4m0qxVwGwywicdusZYh3EFzUP4kTg/640?wx_fmt=png&from=appmsg "null")  
  
  
最后感谢师傅们赏脸！  
  
   
  
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
  
  
[重生HW之感谢客服小姐姐带我进入内网遨游](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247549901&idx=1&sn=f7c9c17858ce86edf5679149cce9ae9a&scene=21#wechat_redirect)  
  
  
[手把手教你CNVD漏洞挖掘 + 资产收集](https://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247542576&idx=1&sn=d9f419d7a632390d52591ec0a5f4ba01&token=74838194&lang=zh_CN&scene=21#wechat_redirect)  
  
  
[【精选】SRC快速入门+上分小秘籍+实战指南](http://mp.weixin.qq.com/s?__biz=MzUyODkwNDIyMg==&mid=2247512593&idx=1&sn=24c8e51745added4f81aa1e337fc8a1a&chksm=fa6bcb60cd1c4276d9d21ebaa7cb4c0c8c562e54fe8742c87e62343c00a1283c9eb3ea1c67dc&scene=21#wechat_redirect)  
  
##     代理池工具撰写 | 只有无尽的跳转，没有封禁的IP！  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/BwqHlJ29vcqJvF3Qicdr3GR5xnNYic4wHWaCD3pqD9SSJ3YMhuahjm3anU6mlEJaepA8qOwm3C4GVIETQZT6uHGQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
点赞+在看支持一下吧~感谢看官老爷~   
  
你的点赞是我更新的动力  
  
  
  
  
