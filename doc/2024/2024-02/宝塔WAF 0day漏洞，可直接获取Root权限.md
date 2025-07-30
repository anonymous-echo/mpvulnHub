#  宝塔WAF 0day漏洞，可直接获取Root权限   
爱的主打歌  刨洞安全团队   2024-02-17 17:05  
  
最近开源社区好像特别流行 WAF，到处都能看到宝塔云 WAF、雷池 WAF 社区版、南墙 WAF 的各种宣传。  
  
我也是宝塔面板的四五年的老用户了，几个月前看到宝塔出了独立的 WAF 就迅速给我的小站上了一套，结果没几天发现服务器被人放了挖矿木马。  
  
这段时间除了安装 WAF，服务器我基本没动过，我第一反应是不是宝塔被黑了，不过我之前用了好几年的宝塔面板，好像也没啥问题，抱着试一试的态度，把宝塔扔进了 IDA，果然找到了一个 RCE，可以通过宝塔 WAF 直接拿到 root 权限，漏洞细节如下：  
  
第一步：打开宝塔 WAF 以后，随便创建一个防护网站，这个很简单，不赘述。  
  
第二步：进入 "网站加速" 功能，打开刚刚创建的网站的加速状态，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaO3S2tLJSQuc5WkUy0YdvwT608vaxXo9VD2bia7iaop3nTODFWaElrzuZA/640?wx_fmt=jpeg&from=appmsg "")  
  
第三步：点击 "配置缓存"，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOSwIVJ2Giclmibhic7TADwIo4ZGP0OvAENfN6Q0GXaTCafVuWW3mne6Epw/640?wx_fmt=jpeg&from=appmsg "")  
  
第四步：点击 "清除所有缓存"，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOQ8XEag56kNAiaibF2UtEMAJ85axibWMTqdiaok4oickDTqfuYygEMxd1Sibg/640?wx_fmt=jpeg&from=appmsg "")  
  
漏洞就出在这个地方，注意了，在刚刚点击 "清除所有缓存" 时，看到浏览器发了两个包出去，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOPGERDiaKjXa2HdIueRL3XD49GgLKMtKzaYRs2CsYicLYPx9IWGdmhN6A/640?wx_fmt=jpeg&from=appmsg "")  
  
第一个包请求了一个叫 "clear_cache"  
 的 API  
，其中包含了一个叫 "site_id"  
 的参数，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOQ8GG9eFxY58QYibwhOsLEC8V1PhncbaQZ9ibcqwowZpzaicy1DA3cwQVw/640?wx_fmt=jpeg&from=appmsg "")  
  
这个参数没做校验直接带入了系统命令之中，参考 IDA  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaO2DOGoKNiaia9Pmu1nuoetxYicY9ReEL4E6hVQ55U3ZQDXiaYiaXrvyytjDQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOtP41HicoiciaYIdcb8MVmqBLKwjbicfunySFZ8RBxet7W2TrCRKDGfygxA/640?wx_fmt=jpeg&from=appmsg "")  
  
第五步，尝试修改 "site_id"  
 参数进行命令注入，加一个分号以后就可以随便写 bash  
 命令了，这里我写了一个 "touch /tmp/hack"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOsKdRhajl9ib4z1icHUupGljlxFYPSK4BciaLa9PlXshbk9k8Uofe6DLwQ/640?wx_fmt=jpeg&from=appmsg "")  
  
请求提交以后看看服务器，/tmp/hack  
 文件果然被创建成功，如图：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/iaHPCQdRh2mDJssa2Qwq62miaeI2mNMoaOpNz5lXUvDMGG3GxpIVKm4ZXIgI7ibXvfFwWkz461xjs3jgsHY0rt4ibQ/640?wx_fmt=jpeg&from=appmsg "")  
  
至此漏洞利用完成，touch /tmp/hack  
 仅作为演示，实际可以通过宝塔 WAF  
 拿到 root  
 权限，进而控制整个服务器。  
  
截至发文时间，最新版测试已经修复！  
  
```
本文作者：爱的主打歌
原文地址：https://www.freebuf.com/vuls/390723.html
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/HWREJselCribXKZnW4g6I2gicDlib73KLnWBMib7xPga814txqfxcPWBtkYhkXX3BVdG42szWtx3eib5YmzeeuoibE1Q/640?wx_fmt=png "")  
  
关注公众号后台回复 0001  
 领取域渗透思维导图，0002  
 领取VMware 17永久激活码，0003  
 获取SGK地址，0004  
 获取在线ChatGPT地址，0005  
 获取 Windows10渗透集成环境  
，0006  
 获取 CobaltStrike 4.9.1破解版  
  
  
  
  
  
加我微信好友，邀请你进交流群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iaHPCQdRh2mD7k15P3gvI6IxzUohyGZicOqn7LDO0yXmtSuZtNh9gWULo1m2N435YwLmtlMFQibzTAuB4d4dMbjMw/640?wx_fmt=png "")  
  
  
往期推荐  
  
  
  
[GitLab 任意用户密码重置漏洞复现（CVE-2023-7028）](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247495659&idx=1&sn=3f865a224ea12c0d1d8c25259a4f067b&chksm=c35ba8c8f42c21de7c8595a95178508eedd1db308cf714f5c18886b54e6f5a1c01a647a88ffe&scene=21#wechat_redirect)  
  
  
[机圈大地震！](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247495558&idx=1&sn=0b8f4852351bc91caf1e983941b0639e&chksm=c35ba8a5f42c21b3b1ea071e303aeda4ea70f87189bdfaf39879be493fc295d8357ccf7ae51a&scene=21#wechat_redirect)  
  
  
[JS逆向实战：RPC + Mitmproxy](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247495529&idx=1&sn=c1bb8e5a0c61dd8d920ca645979a784f&chksm=c35ba84af42c215cc2c0292a84cf427e3b0c9595fe27c2ed39782c17d547434d29e414fcdac4&scene=21#wechat_redirect)  
  
  
[记一次CMS系统通杀0day审计](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247495442&idx=1&sn=2f865aee7608d229b203cc031ee17200&chksm=c35ba831f42c212734b73f26955f0d598e07dc354c39762f8092ad25ba2b7b10b2fcc0f565ea&scene=21#wechat_redirect)  
  
  
[BeanShell注入内存马](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247495495&idx=1&sn=c0255e497c6ce24c816ddca4d4bf0086&chksm=c35ba864f42c2172f667aa12f159554f0554833557e9cc30a200b2d862389a898618e05b252b&scene=21#wechat_redirect)  
  
  
[银狐处置及分析](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494772&idx=1&sn=9fa27f2e02c059d50057b9fa851e2783&chksm=c35bab57f42c2241443abb74da20f3090962183495df25977fa05098bfbe2bf4245fafdd4e6a&scene=21#wechat_redirect)  
  
  
[浅谈安全方向的学习方法](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494738&idx=1&sn=0e270bce7be21979fa2b3847674d556f&chksm=c35bab71f42c2267e4bf49d6e4a20c38554eb5f64fea01d529643fc2824c492e30724bccc339&scene=21#wechat_redirect)  
  
  
[记一次校内的XX系统渗透](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494728&idx=1&sn=c3e4b55f576385069ba57b55392d5a20&chksm=c35bab6bf42c227d67a3f674737b2402426e0d8567932b90835c51c220a582de24ecca9185be&scene=21#wechat_redirect)  
  
  
[极端容器场景下的远程文件下载思路](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494701&idx=1&sn=a30da467d93802a56bc99bd004126d3b&chksm=c35bab0ef42c2218fef4e86b341ad518f62669948af7177e313040d780e108afa42b9a05d0f6&scene=21#wechat_redirect)  
  
  
[实战下的内网中继攻击问题](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494631&idx=1&sn=30d9052e54a2dc09ca61a92a194f4736&chksm=c35bacc4f42c25d21fe0f1abfe8459bacfe50c3d8eaa18dae9517535ed8816aa19faf69aec44&scene=21#wechat_redirect)  
  
  
[对某菠菜的渗透测试笔记](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494532&idx=1&sn=b1bc16139196a5591f22b6cad3e34067&chksm=c35baca7f42c25b1167f00918db0b658548831589c54504fc1961661175059445619254a1b95&scene=21#wechat_redirect)  
  
  
[绕过AV进行UserAdd的方法总结及实现](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494480&idx=1&sn=dff2441e010dcb3b33f4177fcaef075c&chksm=c35bac73f42c25655afba88059b09cdb52955985788177b439a07ec53c56ef69fa66f51a8ccc&scene=21#wechat_redirect)  
  
  
[某次近源攻击到内网漫游拿下域控以及Vcenter](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494443&idx=1&sn=2d444d77af4e9d1475e167a7573a330e&chksm=c35bac08f42c251e4402fd5f4d4663fc07c15bbd1c20a3d4ef071ce63ce4658265618ce973b6&scene=21#wechat_redirect)  
  
  
[某次以目的为导向的内网渗透-取开发源码](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494369&idx=1&sn=87e69e70f762e3732070017a5e9781f2&chksm=c35badc2f42c24d44b41093edb3de25a37765445628a63ed66046d2bbe2a6dea0e530ac68841&scene=21#wechat_redirect)  
  
  
[APT29利用CVE-2023-38831攻击大使馆](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494338&idx=1&sn=b425692ca7b18245c110ed26b6e02068&chksm=c35bade1f42c24f71ed1c1bcdbee707bd93412118c87b99854c94bd6b726253f6d828977fd69&scene=21#wechat_redirect)  
  
  
[微信PC客户端存在@全体逻辑错误](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494323&idx=1&sn=7690ea917516f60b4d90e5125aee8381&chksm=c35bad90f42c2486d4bbfa08b2bae156e68d73408d2716354f772563e3f6d6f7abf4c84cdc2a&scene=21#wechat_redirect)  
  
  
[对某app的加密定位与hook](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494276&idx=1&sn=7c30b7c939342b7558acd6c1f68c9317&chksm=c35bada7f42c24b1d8c8880f7e2a976c05d6f10d15c0daf4c962cdf7e06d9318da61e70cd948&scene=21#wechat_redirect)  
  
  
[《永结无间》客户端RCE漏洞](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494255&idx=1&sn=dbbdeccd9e967f493ce60e130c5d2125&chksm=c35bad4cf42c245a49d6781b030858440e35d856757b2c8977f6fce1a41f9b0b5e5f0bce5b23&scene=21#wechat_redirect)  
  
  
[发现新恶意团伙"紫狐"！针对finalshell的供应链事件](https://mp.weixin.qq.com/s?__biz=Mzk0OTM5MTk0OA==&mid=2247494120&idx=1&sn=b2c1282cfe6982ab6b7b321f43efde71&chksm=c35baecbf42c27ddcb2610a5a4960ed3ef768d8444040fc4efe5c4e0cb1f94ccb3a941a1ff5b&scene=21#wechat_redirect)  
  
  
备用号，欢迎关注  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/MfTd6rd9CyvNRMW8I9cvI1CK5gKiaYqg2veTn9t9dAe1GxYic7pAvgvRIKNFickConFyX8AvW2reAq8GchJI6aBpA/640?wx_fmt=gif "")  
  
  
  
