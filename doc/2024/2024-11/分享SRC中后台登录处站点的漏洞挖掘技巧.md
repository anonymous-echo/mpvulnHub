#  分享SRC中后台登录处站点的漏洞挖掘技巧   
原创 神农Sec  神农Sec   2024-11-17 05:12  
  
扫码领资料  
  
获网安教程  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b7iaH1LtiaKWXLicr9MthUBGib1nvDibDT4r6iaK4cQvn56iako5nUwJ9MGiaXFdhNMurGdFLqbD9Rs3QxGrHTAsWKmc1w/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/b96CibCt70iaaJcib7FH02wTKvoHALAMw4fchVnBLMw4kTQ7B9oUy0RGfiacu34QEZgDpfia0sVmWrHcDZCV1Na5wDQ/640?wx_fmt=png&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
  
#   
  
网络安全领域各种资源，学习文档，以及工具分享、前沿信息分享、POC、EXP分享。  
不定期分享各种好玩的项目及好用的工具，欢迎关注。  
#   
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x1 前言**  
  
  
这次给师傅们分享下SRC漏洞挖掘中的在后台登录处可以进行测试的相关漏洞的一个汇总，也算是给刚入门src或者不太能挖src的师傅们一个小福利吧。然后下面会从我们常见的一个登录后台界面给师傅们分享下几个能进行测试的功能点，主要是给师傅们分享下有注册功能点的登录口和没有注册点的登录空的一个测试的不一样的手法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPRm5SgfUj5I0bjRgeGV7GIOMYe11wvIvWwcUibph6ddvf3rafcvI0VEA/640?wx_fmt=png "")  
  
             
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x2 登录口网站的漏洞挖掘**  
##   
### 一、浅谈  
  
这里呢主要是给师傅们分享就是没有注册功能点的登录页面，然后给师傅们分享下可以进行怎么样的一个渗透测试，对该登录口可以进行一个怎么样的漏洞挖掘，这里主要是给师傅们分享下我在挖掘企业src、渗透测试、众测项目中的一些案例和测试的功能点，因为比如说一些师傅经常问我说，怎么EDUsrc不收的漏洞，众测和渗透测试之类的项目中却收了呢，那么下面主要不是讲EDU漏洞的收录标准了哈。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPyhcVeJmuL4Td0ZyZ3rT4QQicSPrNNQXgtuVcvq8ApPnvDzCvXfcSp5w/640?wx_fmt=png "")  
  
### 二、短信轰炸  
#### 浅谈  
  
本人在挖掘漏洞的过程中，遇到的逻辑漏洞还是比较多的，其中就有不少短信轰炸漏洞。今天就以我挖掘到的一些短信轰炸漏洞为例子，主要是分享一些思路，还请大佬们多多包涵。由于实际到真实厂商，对一些敏感信息进行了打码，大家伙看看思路即可。  
#### 短信轰炸简介  
  
短信轰炸漏洞，顾名思义就是可以无限制地发送短信，原理由于短信业务逻辑设计缺陷，没对短信发送次数做限制，导致可以大量重复发送短信验证码。该漏洞会对其他用户造成骚扰或使厂商的运营商短信费用的增加，造成损失。  
  
此类漏洞还是比较好入手，而且出现频率还是较高的，挖一挖交到盒子上还是不错的，在一些演习甚至能归类到中危。而且对于新手师傅们在众测的时候去测试这样的短信轰炸的漏洞还是蛮不错的，我开始小白的时候靠挖众测的短信轰炸也是有好几百的奖金。  
  
### 三、短信轰炸案例分享  
#### 众测的一个小翻车事件分享  
  
下面这个短信轰炸的案例就是前段时间某市的一个小众测项目，然后也是在项目开始的时候进行漏洞挖掘，最先开始的就是进行登录口的对抗了，找登录口然后看那个是否存在短信轰炸、验证码可爆破漏洞。  
  
然后去挖掘最简单的漏洞，其实在开始的过程中，我挖掘到了好几个短信轰炸的漏洞，但是最后跟那边确认漏洞，发现交了5个短信轰炸，1个重复，2两个资产不归属（这里我要声明下，其实不是不归是，那个证书都是他们那边的，但是就是不收，说什么域名不在资产表格里面，这里我必须得吐槽一下）给我的吃了好几个漏洞，白花花的银子又没了。  
###     
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPPm42ShHbQGdlPnibiaxViabgH0J7xQCPDoibteDDccsKFac1arDkSa3X8Q/640?wx_fmt=png "")  
  
#### 真实众测案例分享    
  
像这样的登录接口，可以使用手机号进行登录，且需要我们获取验证码的功能点，那么我们就可以进行短信轰炸测试      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPIHN41SLpTFsoJXUlDdibPEuxnqY3WIAAQ3o1Nutv8hepCRNicNtCWd8A/640?wx_fmt=png "")  
  
  
一般像这种没有验证码的，一般是绕过js抓包重放即可，在BurpSuite设置代理，抓取发送短信的数据包到重放器中，重复点击发送，可以一直发送数据包，则说明短信轰炸漏洞存在      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPqdAvLnppA31wrAOLtIetjoicqAcgvGb1peGancNBU0LXDUKdeXML70w/640?wx_fmt=png "")  
  
  
然后这里使用bp的并发插件进行短信验证码批量发送，以此来进行一个短信轰炸的操作      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPm2rtXwuFKwoibvF4MaB1w7ow9nkic9LjQfa5aPKY09Vhnq89D2CXjqgw/640?wx_fmt=png "")  
  
手机短时间内收到了大量短信      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPNiaHPfbma0vMN3lKTR0ekgI3ZD2f1FdsibR9icrZHwrRASzqib7ZSiczCPg/640?wx_fmt=png "")  
  
             
#### 绕过短信轰炸限制的思路     
  
1、利用空格绕过短信&邮箱轰炸限制  
  
2、利用调用接口绕过短信&邮箱轰炸限制  
  
3、修改Cookie值绕过短信&邮箱轰炸限制  
  
4、修改IP绕过短信&邮箱轰炸限制  
  
5、多次叠加参数绕过            叠加多个参数，发送多条短信验证码  
  
mobile=130xxxxxxxxx&mobile=130xxxxxxxx&mobile=130xxxxxxxxmobile=130xxxxxxxx  
            
  
  
### 四、任意用户枚举  
#### 漏洞简介  
  
在应用系统登录过程中，当输入错误的用户名信息时，应用程序将反馈相应的诸如“用户不存在”的错误提示，攻击者可通过该提示为依据进行对用户名的枚举，猜解出已存在于应用系统的用户名信息，最终攻击者可进行一步发起对已有用户的密码猜解。  
#### 漏洞案例分享  
  
这个案例也是在众测的时候收的，然后也是低危80￥，是在这个站点的登录后台，然后在忘记密码的地方，进行的任意用户名枚举漏洞测试。  
  
忘记密码页面发现随便输入一个数字提示手机号未注册  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPDicFoZ7n0Vag69QUqvbeugEKMjC3gSHTsHOj98fv4CUBibh7UiavAALMQ/640?wx_fmt=png "")  
  
             
  
使用Burp Suite软件的intruder攻击页面进行用户枚举，发现没有注册的用户都会提示”手机号未注册不能重置密码”      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPtOXdBkwxSibkhgVETs2OvrvEENhgoxWzGyjApUu6GH8Dky1k0eZibjOQ/640?wx_fmt=png "")  
  
  
有一个手机号没有提示未注册说明可以进行用户枚举      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPAXujxibzlzibGbX8BnfZpj62JPqRtS6aIAHKuZ83ibNonpaszQicWIsQibw/640?wx_fmt=png "")  
  
由于验证码是四位数的所以能够通过Burp Suite暴力破解验证码来达到修改密码的目的  
  
#### 修复建议     
  
1、 添加验证码，避免被探测工具批量枚举用户名。  
  
2、 实施强密码策略，确保用户使用强密码来增加用户账户的安全性。  
  
3、 对接口登录页面的判断回显提示信息修改为一致：账户或密码错误(模糊提示)。  
  
4、 设置用户登录次数，如果用户登录次数达到设置的阙值，则锁定账户(有恶意登录锁定账户的风险)。      
  
5、 对用户输入的内容进行强加密  
  
### 五、session会话固定  
###   
#### 漏洞简介  
  
会话标识未更新漏洞，在用户进入登录页面，但还未登录时，就已经产生了一个session，用户输入信息，登录以后，session的id不会改变，也就是说没有建立新session，原来的session也没有被销毁）, 可能会窃取或操纵客户会话和cookie，它们可能用于模仿合法用户，从而使黑客能够以该用户身份查看或变更用户记录以及执行事务。  
#### 真实漏洞案例分享  
  
开始是这样的一个登录页面，然后这里是使用弱口令admin888进去的登录后台  
###   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPero2Ka1v14sGoSJpYcKzMBicez6v4PAaTsC8N0gvSGAJazMGLkERBYw/640?wx_fmt=png "")  
  
  
登录成功的cookie值，下面我们修改下密码，然后再登录看看cookie有没有改变  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANP0UlusrCAexZP4lHTFMtgNv4AHSD3zriaV0CicNhLajAxgGricjpLPjAQQ/640?wx_fmt=png "")  
  
  
修改密码为admin666，但是可以通过对比下发现cookie值并没有发生改变  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPfACv439a5ZPgLW5OWWU6BpuOESFXZibX45nn9QUicVtbTbOC1Ixm3Cvw/640?wx_fmt=png "")  
  
  
那session会话固定不过期的话，那么我们就可以把里面某个功能点的数据包保存，就算是学校把该密码改了，我们还是可以进行数据修改，或者保留密码修改的数据包，因为cookie值是一直不变的。  
  
就比如下面的这个，我是改密码前（admin888）的时候保存的数据包，现在照样可以使用，因为这个cookie值一直不变      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPENQ0ict9qpVyBJRIicGfoibGWf3K3z2cmCqywxZOX2u5QBibCMUcMDadsg/640?wx_fmt=png "")  
  
### 六、图片验证码相关逻辑漏洞  
### 1、图片验证码直接显示在返回包里面     
  
下面的这个预约系统的可以看到下面的这个点击发送验证码，然后可以在那个返回包中可以看到直接返回了验证码字段，可以直接提交漏洞了。      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPbFvBXyFmJFeWwp24yf9eH5h5ctSsaWBwtjMakntxSPuicSvSNAf9vxw/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPiazuCbNOYficqT5KUtBxf8zuic3gVyw7x16dibCOzNYYgOYCic0cnesyrqw/640?wx_fmt=png "")  
  
#### 2、图片验证码永久不失效    
  
图片验证码不失效，可进行爆破：该案例中第一次将图片验证码填写正确后，输入任意账户密码，点击登录进行抓包，报文中的code字段为图片验证码，直接爆破即可，此处图片验证码可无限复用      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANP4ym13UibYdt2J4HfwWq7UcOu1dhx940NPrniaDFpWa4fVjP1icVONdbQg/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPCNKrDsy3ILoQjPlFHufOTEwZd4OssKJlCRr9jq31P4Inb8FdIDzelA/640?wx_fmt=png "")  
  
             
#### 3、图片验证码拒绝服务漏洞（验证码dos）  
  
**漏洞原理：**  
  
开发者在网站开发过程中为了图片验证码能够适应网站在显示过程中的大小，从而加入了隐藏参数，当这个参数被攻击者猜测出以后攻击者就可以修改图片验证码、二维码的大小，让服务端返回的验证码无限放大，最终导致服务端生成的图片超级大然后网站停止服务。  
  
**如何测试：**  
- 1、点击图片验证码进行抓包  
  
- 2、在请求后面拼接隐藏参数：height、width、size、mergin、h、w等实战过程中以h、w、height、width居多  
  
- 3、逐步增加大小例如：第一次:height=111 第二次:height=222，看burp会不会延时，或者直接看burp响应中的Render模块图片有没有变形  
  
  
### 七、sourcemap 文件泄露漏洞      
#### 漏洞原理  
  
在日常测试时，经常会遇到以js.map为后缀的文件这是jQuery中的一个新功能，支持Source Map非常多Webpack打包的站点都会存在js.map文件通过sourcemap可还原前端代码找到API，间接性获取未授权访问漏洞  
#### 什么是Source map？  
  
简单说，Source map就是一个信息文件，里面储存着位置信息。转换后的代码的每一个位置，所对应的转换前的位置。有了它，出错的时候，除错工具将直接显示原始代码，而不是转换后的代码,这无疑给开发者带来了很大方便。  
#### shuji工具还原前端代码  
  
使用nmp安装  
```
npm install --global shuji
```  
  
shuji命令执行  
```
shuji app.js.map -o desfile
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPQK9Xkwu2obgxScLtxWiaTJibyNRBBuYnTsXBTeL3cgiatE8cgNTkayW7g/640?wx_fmt=png&from=appmsg "")  
  
     
  
还原之前的js文件：      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPdwcLGyib3FmzGzQ4Df2l3UCkfMLSicDIlITYdQEC0snKaz9YTyP4z4Uw/640?wx_fmt=png "")  
  
  
还原后的文件如下：  
  
那么后面我们就可以分析js代码，然后找找有没有什么js接口泄露，然后导致敏感信息泄露的漏洞，那么我们不就可以提交src或者众测了嘛  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPIDsFLsgPrZf4ZYEq2OK5ALUoxD8icd6oHg41BknebJLDzicqmXMyofPg/640?wx_fmt=png "")  
   
####   
#### 油猴sourcemap-searcher脚本  
  
功能：自动搜索网页有无sourcemap文件泄露  
  
油猴脚本：F12控制台输入sms()，如果存在会提示，然后打开看能否下载下来，能下载下来的话可以使用我们上面的shuji工具或者使用nodejs进行反编译，然后可以分析里面js接口去找别的漏洞，但是这个sourcemap文件泄露漏洞也是可以直接提交的。  
  
油猴sourcemap-searcher脚本安装位置如下：  
  
https://greasyfork.org/zh-CN/scripts/447335-sourcemap-searcher  
####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPiaSjE0tLiacGQ47axNZM5lPnZCwhshUUlNAzhWIt9zTBBo11unGM5aOQ/640?wx_fmt=png "")  
  
  
这样就是按照该脚本成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPjVJCbALPX3bicsGicGPlX72AFdHsSwGdQ9n6CchibfD3VKP3YrHMxWQrw/640?wx_fmt=png "")  
  
  
下面是我之前在挖src的时候，挖到的sourcemap的js.map文件泄露的漏洞  
  
然后就可以使用  
nodejs  
进行反编译了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPebDvrOaKExWLW3WwSdS9YhN7EhTOPfUwsYc4WbzMplIvzMImrE6zVA/640?wx_fmt=png "")  
  
#### src漏洞报告编写  
1. **漏洞危害：**Source map就是一个信息文件，里面存着位置信息。转换后的代码的每一个位置，所对应的转换前的位置。有了它，出错的时候，除错工具将直接显示原始代码，而不是转换后的代码，这无疑给开发者带来了很大方便。Webpack打包的站点会存在js.map文件,通过sourcemap可还原前端代码找到API，间接性获取未授权访问洞。  
  
1. **漏洞复现：**按照刚才的案例每一步都写好，怎么下载、怎么反编译、反编译出来的东西有啥敏感的都写清楚  
  
1. **修复建议：**删除web站点保存的.js.map后缀的文件。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x3 可注册网站的漏洞挖掘**  
  
##   
### 一、浅谈  
  
漏洞多的资产一般都是叫XX管理平台、XX后台、XX企业，操作系统特征如下，登录口可以用手机号或邮箱直接注册      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPNNZqaesAEaNhDewCuibleUsyI8BX5EiaIlibhePicbN82HzvShib48Krj3w/640?wx_fmt=png "")  
  
  
然后可以使用一些空间引擎进行语法检索，找到自己需要资产  
  
资产寻找：  
  
●fofa：domain="edu.cn" && (title="管理" ‖ title="注册" ‖ title="后台" ‖ title="平台")  
  
●鹰图：domain.suffix="edu.cn" AND (web.title="后台" OR web.title="平台" OR web.title="管理")  
  
●鹰图：(domain="”edu.cn”"&&web.body="”注册”")&&(web.title="”系统”" or web.title="”平台”" or web.title="”管理”" or web.title="”后台”")      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPVI6PpY8cMaaMyIP1mwP57BRgqbxhh8vjARJsicXUHibX9zYxRvrztr9Q/640?wx_fmt=png "")  
  
             
### 二、未授权访问漏洞  
#### 浅谈  
  
下面给师傅们分享下之前众测挖的两个未授权漏洞，一个是druid未授权还有一个是nacos未授权访问漏洞，这两个未授权都给了400￥，主要是当时众测挖的这两个未授权当时使用灯塔ARL扫出来的，虽然是未授权但是里面的数据泄露的不是很敏感，没有能够进一步利用，所以都是给的中危。像你比如说nacos未授权要是能够进去，可以进行nacos工具打rce之类的，能够提升到严重的级别，但是那个利用不了。  
  
未授权访问，顾名思义不进行请求授权的情况下对需要权限的功能进行访问执行。通常是由于认证页面存在缺陷，无认证，安全配置不当导致。常见于服务端口，接口无限制开放，网页功能通过链接无限制用户访问，低权限用户越权访问高权限功能。  
#### 某站点未授权创建普通用户  
  
这个也是通过弱口令进入管理员权限的登录后台，然后在创建用户的功能点进行未授权测试  
  
####   
#### 某站点未授权创建普通用户  
  
这个也是通过弱口令进入管理员权限的登录后台，然后在创建用户的功能点进行未授权测试  
####   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPVj9NvicAO577XbmnD656q1KGYBrG4cjsTVZynPSPcczmGS19Jp55AGw/640?wx_fmt=png "")  
  
  
下面我们直接拿bp抓包，抓这个admin管理员创建用户的数据包，那么我们要是测试未授权，就可以尝试把这个token删掉，然后看看还能不能创建用户了      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPoYhuUDZPicic6POHbbnxgYuCo2E2v17uSaSfgibBgfuKbfptS0fTrPg2Q/640?wx_fmt=png "")  
  
  
可以看到把token删掉了，但是还是可以创建用户成功，这样未授权就成功了  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPvIFugGHqCVFeiaJmf4MDp8VGubscLGH5MibPAucZUdicjdweRNbk6E0hQ/640?wx_fmt=png "")  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPdAo2nVngye8NNzhXt4N9t2XPOryecfzvFVGXhQ3P6kHFJFr8Gq83fg/640?wx_fmt=png "")  
  
             
#### Druid未授权  
  
如果网站无需登录，则可利用未授权访问漏洞，直接访问下面的springboot常见报错界面404直接拼接**常见路径(可构造未授权拼接尝试):**  
```
```  
  
         
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANP0gibMoia4PHJPWOmFTPf74tVmULAC1DH6icTWxNp4dzlgGibl3tkpCajVQ/640?wx_fmt=png "")  
  
  
  
其实像对于Druid框架熟悉的话别的功能点的信息泄露没什么利用的价值，主要就是开头讲的URI**监控、Session监控、Spring监控**这三个功能点  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPT6hzl2vhibK6FDLkFk4iaWiaH4gUIDR5vCT88Sd9DpmQGFRuHSmo8AM7g/640?wx_fmt=png "")  
  
             
  
             
  
                 
  
             
### 三、水平/垂直越权漏洞  
#### 越权简介  
  
什么是越权？举个例子假设有一栋公寓中每个人都租住在自己的屋子里有人在你不知道的情况下进入了你的屋子这就叫做越权。把他放在SRC漏洞挖掘中就是说，你能干原来你自己干不了的事就是越权。  
  
越权常出现的点：增删改查任何地方，任何功能、任何场景都有可能存在越权。  
#### 越权分类  
  
越权访问漏洞主要分为水平越权、垂直越权。  
1. 水平越权：指攻击者尝试访问与他拥有相同权限的用户资源。例如，用户A和用户B属于同一角色，拥有相同的权限等级，他们能获取自己的私有数据（数据A和数据B），但如果系统只验证了能访问数据的角色，而没有对数据做细分或者校验，导致用户A能访问到用户B的数据（数据B），那么用户A访问数据B的这种行为就叫做水平越权访问。  
  
1. 垂直越权：由于后台应用没有做权限控制，或仅仅在菜单、按钮上做了权限控制，导致恶意用户只要猜测其他管理页面的URL或者敏感的参数信息，就可以访问或控制其他角色拥有的数据或页面，达到权限提升的目的。  
  
#### 常见的鉴权字段  
```
比较常见的：
Cookie
Authorization

Token


比较少见的：
X-API-Key
Api-Key
X-Auth-Token
X-Session-ID
```  
#### 简单的测试思路  
  
这里给师傅们提供一个简单的测试思路，因为Cookie代表着一个用户的身份，不论他是否使用session，都和Cookie有关，所以我们就可以利用这一点进行一个越权的简单测试，也是最为常见的一个越权漏洞的测试了。简单的测试步骤如下：  
1. 两个浏览器，一个截包工具。  
  
1. 登录A帐号记录下Cookie值到文本文件。  
  
1. 登录B帐号开始操作。  
  
1. 每次操作截断，修改为A的Cookie值进行发包。  
  
1. 检查，如发现A帐号中的信息成为了B帐号的信息，则越权成功。  
  
#### 越权测试小技巧  
  
1、添加参数  
- user/info  
  
- user/info?id=123  
  
2、hpp 参数污染  
- user/info?id=1  
  
- user/info?id=2&id=1  
  
- user/info?id=2,2&id=1,1  
  
3、添加.json（如果它是用 ruby 构建的）  
- user/id/1  
  
- user/id/1.json  
  
4、测试过时的api的版本  
- /v3/user/123  
  
- /v2/user/123  
  
5、用json对象包装ID  
- {"id":{"id":1}}  
  
6、大小写替换  
- /admin/info -> 401未授权  
  
- /ADMIN/info -> 200 ok  
  
7、常见的测试手法  
- 可以使用通配符(*)，而不是id  
  
- 如果有相同的web应用程序，可以测试下app的api端点  
  
- 如果端点的名称类似/api/users/info,可以修改为/api/admin/info  
  
- 用GET/POST/PUT替换请求方法  
  
                 
### 四、CSRF漏洞  
#### CSRF漏洞产生的原因  
  
1、http协议使用session在服务端保存用户的个人信息,客户端浏览器用cookie标识用户身份；  
  
2、cookie的认证只能确保是某个用户发送的请求,但是不能保证这个请求是否是"用户自愿的行为"；  
  
3、这时,用户登录了某个web站点,同时点击了包含CSRF恶意代码的URL,就会触发CSRF。  
#### 漏洞利用的条件  
  
1、用户必须登录A网站,生成了cookie；  
  
2、登录的同时访问了恶意URL(包含CSRF恶意代码的URL)。  
  
下面拿Pikachu靶场给师傅们演示下这个过程  
  
首先我们登录打开这个pikachu靶场，登录lili这个账号，可以看到下面的这个信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPnjn0bXS7sBFMrXdj3d6L4jcdw7JbXdo273vvVp2eq2Qb6PuNK6BHeg/640?wx_fmt=png "")  
      
  
然后进去之后点击修改个人信息，修改里面的信息，然后再使用bp进行抓包  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPv9t5VlQQZ2vQoYZ4Yv2yXYcA8k5icUYSjCVLg6YbsrgVJn1hNBeAl2A/640?wx_fmt=png "")  
  
  
然后使用bp的插件，保存到桌面的一个html文件      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPKOwBQVH08Nraxw5icbnd1WmwFSheYWrqTnUKUaHw08u3kXgsAfKlveA/640?wx_fmt=png "")  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPloUMjIkpVtgbkkeYjhRrwKW0MosKfMdWmYsVDic8IoBgCCsAXfTRYdw/640?wx_fmt=png "")  
  
  
然后点击，就会发现我们的信息发生了修改      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPvRvuLBNEeKX0pUOI2oWbPsoJkwkGcavEMUZG3LnzmLuylbUSI8dJrA/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWUaicOLF2KdXt4UAkUPWgANPRibibaeIMxhuAmusQ82EA3icXm8lcZHCsVTpHabXYdMCOicicNBouka89mw/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/iabIwdjuHp2VkevXU9Iiad0pl0dnkk6GmAQNiaqmb1kKX2NGKhaGF7m8UicdyCp9agykgzj7pNN1oEw4b3QLvFbibzQ/640?wx_fmt=png&from=appmsg&wxfrom=13&wx_lazy=1&wx_co=1&tp=wxpic "")  
  
****  
**0x4 总结**  
  
  
这篇文章主要是以我们常见的登录后台界面的一个src漏洞挖掘分享，然后后面以能进行注册登录后台进行一个测试的功能点，然后进行一个src漏洞测试的分享多个案例。开始是给师傅们分享以短信轰炸、任意用户名枚举这些众测、渗透测试常去测试的一些简单的漏洞来给师傅们做一个分享，后面主要是以我们能够进去站点后台，然后去测试一些TOP10之类的漏洞，然后用一些真实的案例给师傅们分享了下。  
  
好了师傅们，这篇文章就给师傅们分享到这里了，祝愿师傅们多挖洞，多出洞！  
##   
  
  
**文章中涉及的敏感信息均已做打码处理，文章仅做经验分享用途，切勿当真，未授权的攻击属于非法行为！文章中敏感信息均已做多层打码处理。传播、利用本文章所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任，一旦造成后果请自行承担。**  
  
****  
圈子专注于更新src相关：  
  
```
1、维护更新src专项漏洞知识库，包含原理、挖掘技巧、实战案例
2、分享src优质视频课程
3、分享src挖掘技巧tips
4、微信小群一起挖洞
5、不定期有众测、渗透测试项目
```  
  
  
  
  
  
  
```
```  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b7iaH1LtiaKWWgocP2PwIwb1Ozu2wjXvd2f8kcHv04SXvbE3V43NKaC3MZ0KFatpZSpw4NZlf8srbO3rWy4DT9Dw/640?wx_fmt=png&from=appmsg "")  
  
  
**欢迎加入星球一起交流，券后价仅40元！！！ 即将满100人涨价**  
  
**长期更新，更多的0day/1day漏洞POC/EXP**  
  
             
  
