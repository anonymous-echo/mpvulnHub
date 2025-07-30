> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486564&idx=1&sn=3c6d11aaa73f5a56d9dc96c0b1c03c73

#  代码审计-ASP.NET项目-文件上传漏洞  
原创 小黑子安全666  小黑子安全   2025-07-18 04:21  
  
代码审计必备知识点：  
  
1  
、  
代码审计开始前准备：  
  
环境搭建使用，工具插件安装使用，掌握各种漏洞原理及利用  
,  
代码开发类知识点。  
  
2、代码审计前信息收集：  
  
审计目标的程序名，版本，当前环境(系统,中间件,脚本语言等信息),各种插件等。  
  
3、代码审计挖掘漏洞根本：  
  
可控变量及特定函数，不存在过滤或过滤不严谨可以绕过导致的安全漏洞。  
  
4、代码审计展开计划：  
  
审计项目漏洞原理->审计思路->完整源码->应用框架->验证并利用漏洞。  
  
代码审计两种方法  
：  
  
功能点或关键字分析可能存在  
的  
漏洞  
  
-  
抓包或搜索关键字找到代码出处及对应文件  
。  
  
-  
追踪过滤或接收的数据函数，寻找触发此函数或代码的地方进行触发测试。  
  
  
-常规或部分M  
VC  
模型源码可以采用关键字的搜索挖掘思路。  
  
  
-框架  
  
MV  
C   
墨香源码一般会采用功能点分析抓包追踪挖掘思路。  
  
1.  
搜索关键字找敏感函数  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCYEwz6P0TOt7ep6Ys8tgPr8cLJ3Udc4mHiclRROb5ricE1YiaFRS2cIicYQ/640?wx_fmt=png&from=appmsg "")  
  
2.  
根据目标功能点判断可能存在的漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCrruViafRH38poSzo4pDY9lfe5Dp516ok91AvRDd7LBB88sN3C8ws0gA/640?wx_fmt=png&from=appmsg "")  
  
常见漏洞关键字：  
  
SQL注入：  
  
select insert update mysql_query mysqli等  
  
文件上传：  
  
$_FILES，type="file"，上传，move_uploaded_file()等   
  
XSS跨站：  
  
print print_r echo sprintf die var_dump var_export等  
  
文件包含：  
  
include include_once require require_once等  
  
代码执行：  
  
evalassert preg_replace   
  
call_user_func   
  
call_user_func_array等  
  
命令执行：  
  
systemexec shell_exec   
  
`  
  
` passthru pcntl_exec popen proc_open等  
  
变量覆盖：  
  
extract()parse_str() import  
_  
request  
_  
variables() $$ 等  
  
反序列化：  
  
serialize()unserialize()  
  
 __construct  
  
   
  
__destruct等  
  
文件读取：  
  
fopen f  
ile_get_contents  
  
fread  
  
fgets  
  
fgetss  
  
file  
    
fpassthru  
  
parse_ini_file  
  
readfile等  
  
文件删除：  
  
unlink()remove()等  
  
文件下载：  
  
download()  
  
download_file()  
等  
  
通用关键字：  
  
$_GET,$_POST,$_REQUEST,$_FILES,$_SERVER等  
  
案例：  
.NET  
项目  
审计  
-  
微厦在线学习云服务平台  
-  
文件上传漏洞  
  
.NET  
项目审计介绍  
  
  
asp.net可以用C# ，VB.NET ，Jscript.net等等来开发，但是通常首选都是C#和VB.NET  
  
审计asp.net的时候，首先得弄明白他的结构，他并不像php那么单纯。  
  
一般来说，在asp.net应用中，需要进行观察的文件有：.aspx，.cs，.ashx，dll文件  
  
1、.aspx是页面后的代码，aspx负责显示，服务器端的动作就是在.cs定义的。  
  
2、.cs是类文件，公共类神马的就是这个了。  
  
3、.ashx是一般处理程序，主要用于写webhandler  
,  
可以理解成不会显示的aspx页面。  
  
4、.dll就是cs文件编译之后的程序集。  
  
ASP.NET  
中  
Inherits、CodeFile、CodeBehind  
  
三个属性  
指向解析：  
  
Inherits  
  
msdn解释：定义供页继承的代码隐藏类。 它可以是从 Page 类派生的任何类。 此特性与 CodeFile 特性一起使用，后者包含指向代码隐藏类的源文件的路径。Inherits 特性在使用 C# 作为页面语言时区分大小写，而在使用 Visual Basic 作为页面语言时不区分大小写。  
  
CodeFile  
  
msdn解释：指定指向页引用的代码隐藏文件的路径。 此特性与 Inherits 特性一起使用，用于将代码隐藏源文件与网页相关联。 此特性仅对编译的页有效。  
  
Codebehind  
  
msdn解释：指定包含与页关联的类的已编译文件的名称。 该特性不能在运行时使用。此特性用于 Web 应用程序项目。  
  
开始审计：  
  
1.  
下载好源码，使用  
V  
isual Sdudio Code  
打开  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC61H0MWvcibiakdBp0ibWKNkEJhBbibk0LYpekTvZ0YUNMeG5abLEj2Vwnw/640?wx_fmt=png&from=appmsg "")  
  
2.  
搜索  
.  
net  
项目的文件上传关键字：  
SaveAs   
。只搜索到一个符合结果，发现是  
kindeditor  
编辑器的上传功能，网上搜索  
kindeditor  
编辑器的上传漏洞发现没有。直接  
gg  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC0IoRS8btQTlAKtNNNxb5yQKGibdMk4YG09A4mWX8cmZKiazntEPcdNdA/640?wx_fmt=png&from=appmsg "")  
  
3.  
但是  
bin  
目录下还有许多被编译的类文件也就是  
dll  
文件，需要反编译才能查看，所以应该先将  
dll  
文件反编译后在进行关键字或函数搜索进行审计。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCYhbFcibLnLyZeNicpsx8rzwpIjRoTjcck96pPa1Y77FD6tCHABcqiazdw/640?wx_fmt=png&from=appmsg "")  
  
4.  
但是  
dll  
文件这么多应该反编译哪一个呢？可以打开核心功能的文件，查看引用的是谁。这里引用的是  
song.site  
，所以对  
song.site.dll  
进行反编译。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC6IElnXZCMkTIyne4j7Ksmmic4FuYAMsPRdrqQTxkpxIdnyMmEtSToWQ/640?wx_fmt=png&from=appmsg "")  
  
5.  
选择  
bin  
目录下的  
song.site.dll  
，使用  
ILSpy  
工具打开  
song.site.dll  
进行反编译。  
  
ILS  
py  
下载：https://github.com/icsharpcode/ILSpy/releases  
  
打开  
dll  
文件反编译成功后，右键选择保存代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC62uMMU4pu7Pp11QbQGmlc92EtfQR91abwYVRgiat7a5W5qu4bnlyiblA/640?wx_fmt=png&from=appmsg "")  
  
回刚刚的  
bin  
目录中创建一个  
dll  
文件夹将反编译的代码保存，回到  
V  
isual Sdudio Code  
之后就可以在  
dll  
目录查看到  
bin  
目录下  
song.site.dll  
的代码内容了。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC2e1cicjveWm7dmg4qOtSpbA5CUYN90tpz7lFG55tygWicunMcaHTAjKg/640?wx_fmt=png&from=appmsg "")  
  
6.  
再次进行关键字搜索：  
S  
aveAs  
    
。成功在  
List_Edit.cs  
文件中找到一个上传功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCClOicNXhnHHY8ReKSBBSPOSWNTgAmPRquLSXsnlqkRbmjvTq3NER3A2A/640?wx_fmt=png&from=appmsg "")  
  
7.  
在当前代码中没有发现过滤，审计发现调用了WeiSha.WebControl，查看WeiSha.WebControl  
.dll  
反编译后的代码，  
  
成功找到过滤代码。发现是检测  
fileallow  
的值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCqPqeymSmsERiaaKG8zR272uQQicL6qYZ73PPxWLx0F4cUx18sbpufVNw/640?wx_fmt=png&from=appmsg "")  
  
8.  
接下来需要找到此功能的网站页面访问路径，全局搜索：  
CodeBehind="List_Edit  
    
。成功找到上传功能访问路径：  
M  
anage/Template/List_Edit.aspx  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC2EbWm6ibnSlVIamgyz1lElr9AU1ib033GsGMtD773yFiabSDBywpy1hkA/640?wx_fmt=png&from=appmsg "")  
  
9.  
来到上传功能页面，审查元素发现  
fileallow  
的值是通过前端  
js  
传递的，直接修改前端代码成功绕过过滤，实现任意文件上传。  
  
推荐一下作者最新研发的yakit被动漏洞检测插件，可挖掘企业src漏洞。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavtzDPaxIm6PXM8IuzuAB6ViceOVwpEMvHH403GNQp59nju2Q49TvqOpg/640?wx_fmt=png&from=appmsg&watermark=1&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
以上漏洞都是不需要任何技巧的，作者只是开启插件在目标网站用鼠标“点点点点”就挖掘出这么多漏洞，完全  
  
“零基础”“  
  
零成本”挖洞  
  
目前一共开发了四个插件：  
  
被动  
sql  
注入检测  
  
被动  
xss  
扫描优化版  
  
被动目录扫描好人版  
  
被动  
ssrf  
及  
log4j  
检测  
  
插件使用效果：[记一次企业src漏洞挖掘连爆七个漏洞！](https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486552&idx=1&sn=41c4e4a40fd104f53e22f5a7143c88ad&scene=21#wechat_redirect)  
  
  
插件使用教程：  
[新一代SQL注入检测技术，小白也能轻松挖到漏洞！](https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486516&idx=1&sn=8ce41df1c1c32eddb5762dc6c362a85b&poc_token=HEcld2ij2mPrmNUdYokG5LVG3B9lMQFCmGocR1XA&scene=21#wechat_redirect)  
  
  
知识星球——小黑子安全圈  
[  
精华版  
]  
    
开业大吉！  
  
每一个插件都是非常实用的，有没有用作者也已经通过  
  
企业  
src   
漏洞的挖掘来证明了，并且只需要开启插件  
  
点击鼠标就可以全自动挖掘漏洞。  
  
需要获取插件的小伙伴可以扫描下方二维码加入我的知识星球，星球  
 99  
元  
/  
年  
  
，前  
50  
个加入的  
 77  
元  
/  
年。  
  
加入知识星球的同学会提供  
  
yakit  
  
安装  
  
和  
  
插件  
  
使用教程。  
  
![图片](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImmI8E9Zf6JqGRia9JWljiaavyafDg4ZciajrrTwTH4VWgO5MnmzRk1FMbiaZT2mQxbjb1JJicMDQLXDlw/640?wx_fmt=jpeg&from=appmsg&watermark=1&wxfrom=5&wx_lazy=1&tp=webp "")  
  
本星球只提供精华内容，没有烂大街的东西。会持续更新  
yakit  
插件和各种漏洞漏洞探针和利用工具，哪怕你是什么都不懂的小白用了插件点点鼠标就能挖到漏洞。  
  
注！！！红包返现！！！拉新活动！！！  
  
星球接受使用插件挖到漏洞的投稿，我审核通过会返  
30  
红包，直接微信转，文章我会发公众号  
(  
每人仅限一次  
)  
。  
  
拉新人加入星球待满三天也会返  
20  
红包  
(  
微信直接转  
)  
。插件会一直优化和上新，欢迎大家加入星球。  
  
  
  
