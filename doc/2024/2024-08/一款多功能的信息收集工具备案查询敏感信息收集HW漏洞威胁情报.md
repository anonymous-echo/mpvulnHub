#  一款多功能的信息收集工具|备案查询|敏感信息收集|HW漏洞威胁情报   
kkbo8005  黑客白帽子   2024-08-15 17:31  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
##   
0x01 工具介绍   
对  
于学习网络安全的小白来说，在渗透实战过程中容易没有方向，密探借鉴FindSomeThing、SuperSearchPlus ，御剑文件扫描、dirsearch、JSFinder、fofaviewer等工具，开发这款“密探”渗透测试工具，希望能够为大家提供帮助，并向上述工具的开发者致敬！！  
  
0x02 功能简介  
**密探-主要包含资产信息收集**  
- IP端口查询  
  
- 备案信息查询  
  
- 子域名爆破支持多级递归搜索引擎语法自动生成  
  
- FOFA,Hunter,Quake,  
ZoomEye  
,google,github  
  
- 资产测绘FOFA，hunter，  
Quake  
，ZoomEye 的查询及结果导出  
  
- 指纹识别、敏感信息暴露接口并可以自动探测未授权  
  
- 文件扫描（包含目录，备份文件，spring信息泄漏，自定义字典等）  
  
- 渗透技能路线备忘录，常用网络安全网站导航等功能。  
  
- 界面风格：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1b4hs57wNzj02MKU0eGf7PcFhnWyIlgVHIOoVSkric4qbMdJnchuyGFRA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1bKmdJNgGKbuRzITLHxBc6LS6CI44qVibQCwEbkK4JtYvePoDotV9uDtQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1bS5BwoVfrBko3SOAv30xFM6jvn2s5scEWGICp6RvSReCSZjS1JKN3ag/640?wx_fmt=png&from=appmsg "")  
- 资产测绘  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1bblk0CFGuoaOhONPRMics83lWBbPI4oCmia9jG925ftYvOlVkib25gWxaQ/640?wx_fmt=png&from=appmsg "")  
- 敏感信息（接口未授权）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1bJxwtPl25fl1hiamhZa6B76nDpVdF6y1H1NH9JlQkyFfvPG5c7YjMVMg/640?wx_fmt=png&from=appmsg "")  
- 备份扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1bDY7mccmM3UiaUv77AEicGJuFicFEsd9CQJHacctKbJMAUffDugoJELWog/640?wx_fmt=png&from=appmsg "")  
- 目录扫描  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1bBjcXQVRrYRsRF2iaHThMqdEcDoFWZnlKoQqO9RB7coMXcEwFRHJwNYg/640?wx_fmt=png&from=appmsg "")  
- 渗透备忘  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/PJG3jJlPv0zCSe5plHicGblicbEHuH6H1baibiagYhXyYRk2HZpKyRTB4rwE4ZGPNByHceTFfV1WS2zwpGZtib9q2SQ/640?wx_fmt=png&from=appmsg "")  
  
0x03更新说明```
2024.8.5  增加选择3套皮肤的功能，增加了资产测绘的icon hash计算，增加了jeecg,ruoyi,springblade,apipath的未授权路径扫描字典，增加渗透备忘的编辑功能，可以自定义备忘录的目录及对markdown文档的编辑和浏览，解决基本信息查询单位名称卡死的bug，敏感信息披露接口查询增加了对delete等危险接口的过滤功能，优化了敏感信息js接口抓取。
2024.7.10  所有多线程扫码模块增加线程的暂停，恢复功能，优化停止任务的退出机制，子域名爆破的title乱码问题，指纹识别模块增加高亮显示，子域名爆破泛解析和任务量不匹配的bug，信息查询和资产测绘能改有下拉选择框记录历史记录(右键可清除历史记录），资产测绘自定义每次最大的查询数量，修复了一些其他使用中发现的bug。
2024.6.18  主要增加了子域名爆破功能，子域名爆破可设置递归层级，资产测绘代理功能分拆出来独立设置，为了满足大量的查询需求，资产测绘每个测绘引擎可单独为每个测绘引擎设置每页数据条数（Zoomeye不支持)，然后是各个模块的序号列排序bug， 资产测绘增加copy标题和按标题查询，修复了指纹识别标题乱码的bug，修复子域名爆破的时候调整无法获取到title,增加了对跳转的页面获取title，同步修复子域名title乱码的问题
2024.5.31  资产测绘增加了对ZoomEye的支持，优化了导出资产的报错的bug, 信息查询增加了单位名称/IP的查询，在备案，IP反查等列表增加了“信息查询”等右键菜单。子域名增加rapiddns,alienvault聚合查询结果。修复了资产测绘联动到指纹识别，敏感信息，文件扫描等没带端口的bug。优化显示界面自适应问题。搜索语法增加一些网上搜集的搜索语法。
2024.5.19  优化指纹识别的增加任务文件中包含多个空行导致的线程假死bug，增加状态码过滤，增加指纹识别去重，优化适当调整窗口高度，解决分辨率不够,看不全的问题，优化文件扫描，敏感信息的任务初始化操作步骤。修复文件接口扫描导出因返回包太大无法导出的bug，修复了资产测绘条件语句中包含保留词无法导出的bug，增加首页重要信息的复制功能。
2024.5.15  增加了将工具里面的配置项保存到配置文件，启动加载功能，调整了资产测绘的导出方式，优化文件扫描过滤功能，优化了扫描线程BUG,优化主界面域名信息查询的正则表达式.优化quake注册会员、高级会员的domain查询字段的bug,优化了使用中的一些细节bug
2024.5.8  修正使用中各位师傅提的bug，基本信息模块新增软件著作权，子域名，IP反查域名解析记录，资产测绘增加配置Hunter的多KEY轮询查询功能，文件目录扫描增加了按域名+压缩文件后缀的组合方式。
2024.5.6  增加权重信息查询，增加资产测绘的自动加载查询，优化指纹扫描，接口扫描，文件目录扫描功能，增加密码字典功能。优化网站导航信息
2024.4.24  界面功能增加指纹识别扫描模块，支持从资产测绘联动到指纹识别，从指纹识别联动敏感信息、文件扫描模块
2024.4.20  增加资产测绘模块，调整界面布局，资产测绘支持fofa,hunter,quake3个引擎的查询，并支持右键菜单与敏感信息扫描、文件扫描模块的联动功能
2024.4.13  优化了接口未授权扫描的界面卡顿问题以及接口抓取完成自动触发接口未授权扫描计算bug
2024.4.11  将敏感信息界面重构了，增加了接口抓取及未授权接口探测功能。（正则表达式感觉还不够完美，下一版再优化一下）
2024.4.7  优化文件扫描的多线程扫描功能，增加网站导航地址
```  
  
  
0x04 使用介绍  
  
在jdk8环境下（在jdk8以上的高版本请参考常见问题1的处理方案）运行以下语句运行:  
```
java -jar mitan-jar-with-dependencies.jar
```  
  
若不想输入这么长太长语句，可以通过以下脚本的方式启动：  
1. Mac/Linux 环境下，可以通过sh文件启动，需要在控制台窗口先给予start.sh权限。  
  
```
chmod +x start.sh
```  
  
赋予权限后，每次在控制台窗口执行如下命令打开工具  
```
./start.sh
```  
1. windows系统直接双击"start.bat" 文件启动工具  
  
**常见问题**  
```
运行时错误提示: 缺少 JavaFX 运行时组件的解决方法。
JavaFX 从 Java 11 开始从 JDK中移除，JDK11以上的需要单独下载和配置javaFx。

1. 下载 JavaFX SDK
首先，从 Gluon 网站 下载对应操作系统的 JavaFX SDK。

2. 解压到目录
将下载的 JavaFX SDK 解压到一个目录中（例如 C:\javafx-sdk-21）。

3. 运行 JAR 文件时指定 JavaFX 模块路径
在运行你的 JAR 文件时，需要指定 JavaFX 模块的路径。假设你的 JavaFX SDK 解压在 C:\javafx-sdk-21，你可以使用以下命令来运行你的 JAR 文件：

java --module-path "C:\javafx-sdk-21\lib" --add-modules javafx.controls,javafx.fxml -jar mitan-jar-with-dependencies.jar
在这个命令中：

--module-path "C:\javafx-sdk-21\lib" 指定了 JavaFX 模块的路径。

--add-modules javafx.controls,javafx.fxml 添加了所需的 JavaFX 模块，根据你的应用程序可能需要添加其他模块。

感谢 p1at0x ，s0nd9r师傅在Issues中提出的解决方案，可自行根据操作系统修改start.bat或start.sh脚本文件，解决快速启动。

若遇到界面乱码问题，建议指定编码方式进行启动。
java "-Dfile.encoding=UTF-8" -jar mitan-jar-with-dependencies.jar
可自行根据操作系统修改start.bat或start.sh脚本文件，解决快速启动。
```  
  
  
0x05 近日HW漏洞情报大部分POC已在星球公开持续更新中，漏洞在星球获取(每日更新)中成科信票务管理平台TicketManager存在SQL注入漏洞中成科信票务管理平台SeatMapHandler存在SQL注入漏洞Dedecms sys_verifies存在任意文件读取漏洞章管家updatePwd存在任意账号密码重置漏洞润申信息科技 ERP commentstandardhandler sql注入漏洞用友crm客户关系管理help.php存在任意文件读取漏洞Apache Tomcat存在信息泄露漏洞( CVE-2024-21733)大华DSS 视频管理系统group_saveGroup存在SQL注入漏洞章管家listUploadIntelligent接口存在sql注入漏洞赛蓝企业管理系统GetImportDetailJson存在SQL注入漏洞润申企业标准化管理系统DefaultHandler存在SQL注入漏洞用友U8 Cloud BusinessRefAction 存在SQL注入漏洞用友-U8-CRM-attrlist存在SQL注入漏洞用友-U8-CRM-emailitemedit存在任意文件上传漏洞章管家updatePwd.htm存在任意账号密码重置漏洞H3C iMC智能管理中心 autoDeploy.xhtml 远程代码执行漏洞安美数字酒店宽带运营系统 weather.php 任意文件读取漏洞金斗云 HKMP 智慧商业软件 queryPrintTemplate 存在 SQL 注入漏洞WookTeam接口searchinfo存在SQL用友U8-CRM help存在任意文件读取漏洞喰星云·数字化餐饮服务系统shelflife存在SQL注入漏洞喰星云·数字化餐饮服务系统stock存在SQL注入漏洞方天云ERP系统setImg存在任意文件上传漏洞智慧校园(安校易)管理系统FileUpAd任意文件上传漏洞锐捷乐享智能运维管理平台getToken存在SQL注入漏洞致远 M1移动端存在未授权访问漏洞ZoneMinder存在SQL注入漏洞通天星CMSV6车载视频监控平台SESSION伪造漏洞章管家-listUploadIntelligent-sql注入漏洞方天云智慧平台系统setImg.ashx存在文件上传漏洞WookTeam接口searchinfo存在SQL注入漏洞Dedecms接口sys_verifies.php存在任意文件读取漏洞乐享智能运维管理平台getToken存在SQL注入漏洞润申企业标准化管理系统CommentStandardHandler存在SQL注入漏洞酒店宽带运营系统weather存在任意文件读取漏洞喰星云·数字化餐饮服务系统not_finish存在SQL注入漏洞智慧校园安校易管理系统FileUpAd任意文件上传漏洞...  
  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**0815****】获取网盘**  
**下载链接**  
  
**二个月前资源汇总**  
  
https://kdocs.cn/l/cq  
EYzWfs0kUS  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
