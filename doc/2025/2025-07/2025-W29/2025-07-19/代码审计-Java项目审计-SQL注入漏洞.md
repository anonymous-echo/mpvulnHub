> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NDg4MzYzNQ==&mid=2247486568&idx=1&sn=38979e7c71e92a748fe6c50d174e5ed3

#  代码审计-Java项目审计-SQL注入漏洞  
原创 xiaoheizi  小黑子安全   2025-07-19 05:47  
  
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
  
在Java中SQL语句写法一般有以下几种方式：  
  
一  
.  
JDBC 注入分析  
  
安全写法： "select * from user where id = ?";  
  
不安全写法： "select * from user where id ="+req.getParameter("id");  
  
二  
.  
Mybatis 注入分析  
  
#号会对语句进行预编译  
  
${ } 只是进行string 替换，动态解析SQL的时候会进行变量替换  
  
安全写法：select *  from user where name = #{name}  
  
不安全写法：select *  from user where name = ${name}              
  
三  
.  
Hibernate 注入分析  
  
安全写法：参数绑定预编译  
  
Query<User>.query=session.createNativeQuery("select * from user  where name=:name");  
  
query.setParameter("name",parameter) ;  
  
不安全写法：  
  
Query<User>.query=session.createNativeQuery("select * from user  where name="+req.getParameter("id"));  
  
java  
项目  
sql  
注入产生原理总结：  
  
1、预编译使用不当：  
  
sql="select * from user where id = ?";  
  
sql+="and username ="+req.getParameter("username");  
  
2、直接动态拼接：  
  
 "select * from user where id ="+req.getParameter("id");  
  
3、order by&like&in查询：  
  
由于这三种关键字不能预编译  
(  
预编译失效  
)  
，所以需要过滤器或自定义过滤  
  
防御：  
  
能预编译的情况都做预编译，一些特殊无法做预编译的，则过滤用户可控的参数。  
  
案例：  
Javaweb-代码审计SQL注入-INXEDU在线网校  
  
环境：  
MYSQL：5.X  
     
TomCat：8.X  
     
JDK：1.8  
     
IntelliJ IDEA  
  
1.  
将源码导入到  
IntelliJ IDEA   
，部署好环境，启动服务器  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC8hzLJO1ZkyJ0PLicO1any4mpoDyc2VGicd6JBeMiaSKXf9xK75AcicrN7w/640?wx_fmt=png&from=appmsg "")  
  
2.  
搜索关键字：  
jdbc  
    
m  
ybatis  
—  
>$  
   
hibernate  
，判断源码使用的是哪种方式写的  
sql  
语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCZy6ujDZnITLl76dQZl9gO0IpuYTOMm9jriaBlc1khdbdu2m5bEDFPmQ/640?wx_fmt=png&from=appmsg "")  
  
3.  
判断出源码使用的是  
m  
ybatis  
方式写  
sql  
语句，我们就可以查找  
  
如：  
${}   
这样的不安全写法。  
  
可以看到下图的  
 IN(${value})   
不但使用了  
$()  
不安全写法，还使用了  
in  
关键字使预编译失效，极大概率会产生  
SQL  
注入漏洞。所以要知道是谁调用执行了这条  
SQL  
语句。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCaxDM8o4wjtsDmOibCu3xOibn7CzpAiaqZicTXOBqoAHTWUibdem4g5sbd0A/640?wx_fmt=png&from=appmsg "")  
  
4.  
复制  
deleteArticleByIds  
  
进行全局搜索  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCWP16DDQuj2HEfoaPqGdK1FfC3ibmhR6ibpnZRYmPPhV2iaMLRu72IpTPQ/640?wx_fmt=png&from=appmsg "")  
  
5.  
成功找到方法，选中——导航——调用层次结构，成功获取完整调用链  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCRc9MUMialVZowDN7LlY0PlZZ6IIEicqVM9xvIXdkzq31LQ9BYovGPOiaQ/640?wx_fmt=png&from=appmsg "")  
  
6.  
分析调用链，获取到路由地址：  
/admin/article/delete  
    
，以  
post  
方式为  
articelId  
参数传递参数值  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCC2s1W4zlOfPXQTjC5zY12FhjjqPx7gDjmRxOIHHDzL410Y39xaEicZ1g/640?wx_fmt=png&from=appmsg "")  
  
7.  
访问路由地址并且抓包，将数据包更改为  
post  
请求，增加  
post  
传参：  
articelId=1*  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCNooVzSNibFiafwBFvf2cPR4HTRyW6PJuut5TcovrAk4s9ZJkDTI5r4Bw/640?wx_fmt=png&from=appmsg "")  
  
8.  
将数据包保存为  
1.  
txt  
，使用  
sqlmap  
检测  
sql  
注入。  
  
cmd  
执行：  
python sqlmap.py -r 1.txt --dbs  
  
成功获取数据库信息：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIlnNxeT7FCVA8Hp7B3HBpCCZyUO4NEOHbQS0AMyibGpVkLIuQQiaZ0wldZdjZdlWD29piauH9RicpjDVw/640?wx_fmt=png&from=appmsg "")  
  
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
  
拉新人加入星球待满三天也会返  
20  
红包  
(  
微信直接转  
)  
。插件会一直优化和上新，欢迎大家加入星球。  
  
  
  
  
