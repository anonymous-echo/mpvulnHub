#  从302到RCE，拿shell就像喝水一样简单   
 不秃头的安全   2025-01-16 07:35  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fVNCXqrL9k0r2icauIbCEBEls8X0kfM78frUZBL3ZSZKZlICQlev704WAdTLlWPZ0taFhvEm1mr3Lg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
从302到RCE，拿shell就像喝水一样简单****  
  
  
  
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。  
  
还在学怎么挖通用漏洞和src吗？快来加入星球  
-考证请加联系vx咨询  
  
由  
于微信公众号推送机制改变了，快来  
星标  
不再迷路，谢谢大家！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVxjFlrnQicRmicGwibBuICVdO06eKkicatCKSODHZaL3OdQKYuHKsBhDD9SejOkehWibbR9BoS4LZSFGA/640?wx_fmt=other&from=appmsg "")  
  
1  
  
Start  
  
    从前两天《[从404到RCE](http://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247484218&idx=1&sn=744a1df0c116bf5257da1d5001de1172&chksm=c2be2c16f5c9a500ddc9068cfc8e039c77d79e8dbc88b3324a30f5870cf1517678643619fd82&scene=21#wechat_redirect)  
》的文章反馈来看，大家很喜欢看这个系列嘛（还没看过的铁汁可以点击链接查阅哦），刚好最近项目上又碰到一个比较有意思的网站，顺手也给记录了下来。  
  
2  
  
Action  
  
    故事的开始总是那么的普通，老生常谈的开局一个登录框。什么？还有人不会测试登录框？快去参考参考斯叔之前的文章：[抛开day不谈，为什么同样一个站你挖不到洞，别人却能咔咔上分？](http://mp.weixin.qq.com/s?__biz=MzkzNDI5NjEzMQ==&mid=2247483975&idx=1&sn=25603630eb190bc7b66f5769003861f1&chksm=c2be2d6bf5c9a47de40a142e20d145be38ee90d4a148f44bd32d0ac1600916da892e34aaaaf8&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8Me21EaeV5xzs3FqzmekDANE9YSibfkWxGGUic6Tibn9h8UuJQL8kqrVuPg/640?wx_fmt=png&from=appmsg "")  
  
    简单识别了一下指纹情况，只有shiro，但是没跑出来key，刚燃起来的火焰又被浇灭了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8Mtt8EPt8ibBUtrPhHZZlNjEF42o7Al7iaLyEbvb20NZia5R04IcTVFeniaQ/640?wx_fmt=png&from=appmsg "")  
  
    试了弱口令也无果，JS里面也没翻到什么有价值的内容。偶然瞥到了url栏里面的/xxx/admin/login（/xxx指代一级目录），你说会不会存在未授权的后台页面呢？试了一下访问/xxx/admin/home，emmm不行，302跳转回了登录框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MIczYlCVCcQffiabFO0VCicGPefW1reticicbdsaesiaGc0zCjzTG38E49Hg/640?wx_fmt=png&from=appmsg "")  
  
    看似走头无路，但是汇总一下目前已知的一些信息来看。。。首先网站是用了shiro的……嗯？shiro？谁说shiro只有爆key反序列化漏洞？还有权限绕过诶，试了一下权限绕过的poc：/xxx/;/admin/home，成了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MAP6l2ch0tKcaNvj2ribAMwlSIvYvQfKAYZWyAticGibXbsvXoxFqRibvXA/640?wx_fmt=png&from=appmsg "")  
  
    但是光是这个漏洞还不够呀，不得行啊，不能辅助rce这就是个垃圾洞，看看还能不能继续深入。翻了一下home页面加载的js文件，没啥能利用的接口呀，那咋办？没啥好办法，只能使用  
fuzz  
大法了，burp导入密码本，开扫！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MeJPVbicALI9D9K1KdYVY2tVaZOMgibVicc60Ud7BjRiaqKhj53xxvrQ4qQ/640?wx_fmt=png&from=appmsg "")  
  
    功夫不负有心人，还真让我扫到了一个目录/xxx/;/admin/content，有数据！感觉有戏。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MicDJo9nZ1tkibGS7SluhQWQBRycECrISicLjkGZ0ZZjPQFhY2Olvue1SQ/640?wx_fmt=png&from=appmsg "")  
  
    不过目前都是在burp里面访问这些资源，如何在浏览器里面自动的让url添加/;/呢？我们只需要在burp的代理模块里面按照下图的步骤添加一个规则，这时候经过burp的代理流量就会自动将匹配到一级目录/xxx/后面添加;/实现自动的shiro权限绕过了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8Ml3JvicrnduZs1PQ8DmCm0PWhUTpM4iblfErpmpyjmOtxvxkBtSOzDJEA/640?wx_fmt=png&from=appmsg "")  
  
    随机点了一个标题的查看功能点  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MgHEZexyOHKPEbrwic39bHcP8oMibjKfcyvTAUjfntE0U5h2n4EKCjjJA/640?wx_fmt=png&from=appmsg "")  
  
    有上传点![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/newemoji/Yellowdog.png "")  
！稳一半了  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MItuc7LEp2KLUUqqHdwZ2IPlYHYoNWnNialRicmbIiataLeg880mTPB1WA/640?wx_fmt=png&from=appmsg "")  
  
    经过测试，共有三个上传的接口，分别是/uploadImage，/uploadPicture以及/uploadVideo，其中前两个是白名单校验，不能上传非图片后缀的文件，最后一个能上传jsp（提示上传成功），但是不返回文件路径。  
  
  
  
    得盲猜文件路径了啊，有点难搞。不过当我回头分析  
/uploadImage接口的时候发现了一件事情，它是返回路径的，它告诉我文件保存在了/xxx/xx/res/images目录下面的  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MG0cNfYguWh3U0khcyECx4lL4zM24anWw4pAIkFibicib0dv9slyc9oIQw/640?wx_fmt=png&from=appmsg "")  
  
    有没有一种可能，，  
/uploadVideo也是在/res目录下的？  
为了防止资源目录下可能不解析  
webshell  
文件，我特地在文件名处增加../跳跃到上一级目录，这样webshell的地址就在/xxx/xx/res/1.jsp了，上传成功  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8MMRKiavl6OBPHEnRNibiaOTKvib0ldUYSWSy4yrGtF94cTp4QqcGYncxibWg/640?wx_fmt=png&from=appmsg "")  
  
    访问一下  
/xxx/xx/res  
/  
1.  
jsp，成了！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24UaOw6lthMj8PPTGzibQzvSVv0oMAibC50CYcNYyoMw2mvKL0f5XmPSpaJhagntSdr6YxBvOVlDL4AFQ/640?wx_fmt=png&from=appmsg "")  
  
    上传的马子是无害的自删除马子，访问后自动把自己删除掉  
```
<%out.print("f7098ef4b298e771722e3935f309eb6e");new java.io.File(application.getRealPath(request.getServletPath())).delete();%>
```  
  
    一不小心又shell了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/pKCicPnn24Ubia8oiavG1E6r9CuRsniaEib8M9nPTJ167CUuvjfLUqoXJVk0HoYxlkNoBjEzjr6YVich3vPDTfLeN14w/640?wx_fmt=png&from=appmsg "")  
  
  
3  
  
End  
  
      
如果你也对网络安全感兴趣，不妨添加主页斯叔微信，大家一起互相交流学习。如果你愿意倾诉当前的学习苦恼，斯叔也会免费给铁汁做一个符合现状的职业规划。  
  
    文章编辑不易，麻烦各位老铁动动发财的小手转发转发，点点赞，点点广告  
![](https://res.wx.qq.com/t/wx_fed/we-emoji/res/v1.3.10/assets/Expression/Expression_64@2x.png "")  
  
～～  
  
  
往期推荐：  
  
[aws key利用，云资产管理工具不能下载文件怎么办？](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488259&idx=1&sn=1f16c990da00d4eacbc2ce73bf1d0809&scene=21#wechat_redirect)  
  
  
[RongIOC 一款全自动APT威胁情报拓线工具(APT Automated Tool )（使用教程+实战对比效果）](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488180&idx=1&sn=c4b629fb40aa2f54c1bb0410d3a93ba5&scene=21#wechat_redirect)  
  
  
[APT拓线分析指南（自研工具RongIOC实战）](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488177&idx=1&sn=eb603f7aedc2b41a928b076d03bb2543&scene=21#wechat_redirect)  
  
  
[黑盒乱锤某专属SRC到0day代码分析](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488175&idx=1&sn=1c921a987a68886965f42dd89bd995bd&scene=21#wechat_redirect)  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/5XMBWuTy1YdnTAAczP5ENGmlT9xMEAsJuTqV6jib7IyxImNprOeHxrbPLFkKfEPfh2U829KgfaTYB6NLOmx9Ykg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
  
**关注福利：**  
  
回复“  
google工具  
" 获取 google语法生成工具  
  
回复“  
小程序渗透工具  
" 获取 小程序渗透工具  
  
回复“  
暴力破解字典  
" 获取 各种常用密码字典打包  
  
回复“  
typora激活  
" 获取 最新typora激活程序  
  
回复“  
蓝队工具箱  
”即可获取一款专业级应急响应的集成多种工具的工具集  
  
  
**知识星球**  
  
星球里有什么？  
  
CNVD、EDU及SRC赏金，攻防演练资源分享(免杀，溯源，钓鱼等)，各种新鲜好用工具，最新poc定期更新，  
以及一些好东西  
（  
还在学怎么挖通用漏洞吗快来加入  
），16个专栏会持续更新~  
**提前续费有优惠，好用不贵很实惠**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fWrow7Lich50u81LLP4zJibgPAraQqDXp7unGFQ4kARpmX2yicpt7hworr5QptZTtCGKsXzicAr24Fy9A/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**交流群**  
  
加我联系方式拉交流群~  
  
****  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icjIKcQsgZ0q8U9MOMKkIGEGjAcDMjOXuW6eYDOur79SYFak4z5Pu5v6liaPDvuaAVGKSibvBnKiaRFiaHvBDYwsfAQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**安全考证**  
  
需要考以下各类安全证书的可以联系我，  
绝对低价绝对优惠、组团更便宜，报名成功先送星球一年，  
CISP  
、PTE、PTS、DSG、IRE、IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理......  
巨优惠  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fVicVKjibDEuQ9Kib0ia6TibrVmoFRWyXqReDwUhDas8kOqD29OfTA4XzqZjgw1pn8OYibtFfQxvPJq4kNg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
