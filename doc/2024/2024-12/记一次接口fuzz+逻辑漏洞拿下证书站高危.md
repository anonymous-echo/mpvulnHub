#  记一次接口fuzz+逻辑漏洞拿下证书站高危   
 扫地僧的茶饭日常   2024-12-12 01:00  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcrpvQG1VKMy1AQ1oVvUSeZYhLRYCeiaa3KSFkibg5xRjLlkwfIe7loMVfGuINInDQTVa4BibicW0iaTsKw/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
# 本文由掌控安全学院 -   kpc 投稿  
  
**来****Track安全社区投稿~**  
  
**千元稿费！还有保底奖励~（https://bbs.zkaq.cn）**  
## 一、站点选择  
  
依旧是按照可注册进站的思路搜索资产，因为是打证书站所以只需要按照域名搜索即可，关键字中加上注册，后台等即可，具体语法在Track社区的其他文章已经给出，有兴趣的大佬可以去看看。  
  
一番搜索后，确定了某管理系统：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcp03XcbOjpSlOnrymcCGgxQF17USDyqHzAWfeNZK9XdxNS9eFOqvV5lUEvQoHPkTYxhn3AJLAzo0w/640?wx_fmt=png&from=appmsg "")  
  
img  
  
由图也有注册功能，而且是用sfz注册的，我们直接用burp插件生成一个虚拟的注册即可。  
## 二、逻辑漏洞  
  
进入后，光秃秃的一片，一个功能点也没有，仅有右上角的修改密码功能：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcp03XcbOjpSlOnrymcCGgxQIrxPAPKMpD4XFmfmHnLKI0kkls6licn6yXwuJIW8LbHBibibyyrZCGU0w/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
相信大家看到这里已经发现了，修改密码不需要原密码，这就很有可能产生越权，我们抓包测试，发现删除token依旧可以修改成功，所以鉴权就靠的是账号也就是sfz：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcp03XcbOjpSlOnrymcCGgxQ7S8qzbNtdOgsb0dTRKpkZFG6Lpj1GqRicyVsTNnto4b3Z5M9ocvEURw/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
注意图中没有任何token，cookie等，也可以说是未授权修改密码。  
  
到这里肯定是不够高的，说不定连中都不到，因为修改密码靠的是sfz了，这个sfz我们也是不容易搞到的，所以危害并不大，这就像有的系统鉴权靠的是一串不能遍历的数字（有一定的规律再加上时间戳生成的），虽然可以创建两个号证明存在越权，但是并不能产生实质性的危害。  
## 三、接口fuzz  
  
本来到这里我已经准备放弃了，后来注意到上面修改密码的接口是xxuser/changepassword，一看到user这个敏感词，我就想到了接口fuzz，一般的开发都会把查询用户的接口设计成/user/list，/user/info，、/user/query，/user/page等这样类似的接口，于是我突发奇想，把chagepassword改成了list，结果直接出现了所有用户的信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcp03XcbOjpSlOnrymcCGgxQC8oib0vn23FmhtlcPkzT4GRIa7daYSSMS2zJibibIrqQLibdbJGlhmncGA/640?wx_fmt=png&from=appmsg "null")  
img  
  
又因为该系统注册靠的是sfz，所以username就是sfz，不仅获取了大量sfz还能将上面的修改密码接口加以利用，间接造成所有用户账号密码修改，最后修改了一名用户的账号密码证明确实存在：  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/BwqHlJ29vcp03XcbOjpSlOnrymcCGgxQBo53QKe9w0CRc7894UTdQXr07uCjVA7ibPiaEQFoQIDxN4LChFvTVZ2w/640?wx_fmt=png&from=appmsg "null")  
  
img  
  
最终提交漏洞至平台，高危10rank拿下  
```
```  
  
  
