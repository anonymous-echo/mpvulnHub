#  多功能BurpSuite漏洞探测插件—TsojanScan   
 黑伞安全   2025-05-16 09:00  
  
#   
#   
# TsojanScan  
  
一个集成的BurpSuite漏洞探测插件  
## First  
  
  本着市面上各大漏洞探测插件的功能比较单一，因此与  
TsojanSecTeam  
成员决定在已有框架的基础上修改并增加常用的漏洞探测POC，它会以最少的数据包请求来准确检测各漏洞存在与否，你只需要这一个足矣。  
#   
### Usage  
#### 1、加载插件  
  
********  
####   
#### 2、功能介绍  
#### （1）面板        
####   
  
自定义黑名单，插件不扫描黑名单的url列表，进行Reg匹配优先级第一。  
****  
####   
#### （2）主动探测     
####     
  
**比如探测非根目录/，目录下面需要加/**  
****  
  
****  
####   
#### 3、fastjson >=1.2.80探测  
#### （1）本地环境         
####   
#### 2）预查询DNSlog接口  
####   
  
****  
####   
#### （3）扫描  
####   
  
****####   
#### （4）判断准确版本  
  
1.2.80版本探测如果收到了两个dns请求，则证明使用了1.2.83版本，如果收到了一个 dns 请求，则证明使用了1.2.80版本。****  
####   
#### 4、DNSLog查询漏报  
####   
  
****  
  
****  
  
****  
  
**注意⚠️：扫描结束后才会在BurpSuite的Target、Dashboard模块显示高危漏洞，进程扫描中无法进行同步，但可以在插件中查看（涉及到DoPassive方法问题）。**  
  
****###   
###   
### Update  
#### 更新说明 - v1.4.1  
1. 修复dnslog平台，更换api接口。  
  
1. 版本号未修改，下次更新上传。  
  
#### 更新说明 - v1.4  
1. 增加 laravel 漏洞扫描、增加 laravel 主动扫描。  
  
1. Issue 首字母大写（强迫症福音）。  
  
1. 增加自定义每个请求之间延时的功能。  
  
1. 增加SQL注入扫描、增加SQL注入主动扫描（MySQL报错，时间盲注SQL全系列）。  
  
1. 修复Text4shell某些头部不扫描的问题。  
  
1. 修复主动扫描时已存在的漏洞不会重复添加的问题。  
  
1. 修复dnslog平台，更换api接口为dnslog.rest。  
  
#### 更新说明 - v1.3  
1. 增加thinkphp多语言rce漏洞扫描。  
  
1. 优化thinkphp多语言rce探测数据包，减少发包数量。  
  
#### 更新说明 - v1.2  
1. 增加Fastjson参数扫描，并增加Fastjson主动扫描。  
  
1. 修改引入的fastjson库版本为1.2.83，防止被反制。  
  
1. 删除自己添加的bp api，改为maven库导入模式。  
  
1. 增加axis服务接口扫描。  
  
#### 更新说明 - v1.1  
1. 增加Domain黑名单设置，可手动添加域名让插件对该域名进行判断是否为黑名单，从而不对其进行漏洞探测，来减少多余的探测进程影响渗透过程。。  
  
1. 黑名单模式添加方式：google.com或者google，127.0.0.1或者127.0.0.1:8080；之前的扫描进程不会中断，下一个域名或者ip开始进行判断。  
  
1. Reset表示恢复默认黑名单状态，也就是当前初始化状态。  
  
1. apply表示当你启用BlackList功能时，需要apply加载。  
  
#### 更新说明 - v1.0  
1. 增加druid未授权扫描。  
  
1. 修复log4j只扫描 已有头部与容易出现问题头部取交集 的问题。  
  
1. 修复SpringBoot Env、swagger、druid在同一文件中导致的发现druid则不再探测其他漏洞的问题。  
  
1. 修改dnslog请求次数，改为仅在插件开启时请求一次，方便查询dnslog结果。  
  
1. 不扫描dnslog平台（某个家伙Yyy连dnslog都自己扫了）。  
  
1. 增加了spring cloud gateway扫描，但没加漏洞检测。  
  
1. 修复了spring cloud SPEL漏洞不报的问题，增加/functionRouter接口扫描。  
  
1. 修复只取host不取port导致同一域名不同端口会跳过扫描的问题。  
  
1. 修复fastjson扫描无法通过dnslog获取结果的问题。  
  
1. 修复匹配URL后缀时使用包含的方式，改为以xx后缀结尾。  
  
1. 修改log4j和text4shell为不扫描.asp/.php/.aspx等后缀。  
  
1. 增加ThinkPHP主动自定义目录扫描  
  
   
  
 ○ 比如：想扫描/Think5/目录的话，Repeater请使用GET /Think5/ HTTP/1.1；  
  
    
  
○ 缺点：如果想主动扫描根目录或public目录的话，Repeater请使用根目录GET / HTTP/1.1。  
  
1. 修改结果窗口的请求和响应分割线，将其保持在中间的位置。  
  
1. 增加Weblogic主动扫描（这个也有类似ThinkPHP的自定义目录扫描）。  
  
#### 更新说明 - v0.1  
1. 修改dnslog部分，将ceye删除，创建了testmail.buzz（已修复）。  
  
1. 增加Text4shell漏洞探测。  
  
1. 增加springboot信息泄露扫描记录，防止扫描重复路径。  
  
1. 增加配置窗口，替代config.json文件。  
  
### ToDo  
<table><colgroup><col width="72" style="width:54.00pt;"/><col width="622" style="width:466.50pt;"/></colgroup><tbody><tr height="20" style="height:15.00pt;"><td height="15" width="12" x:str="" style="word-break: break-all;">√</td><td width="519" x:str="" style="">增加swagger-resource的扫描与匹配规则。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">修复路径中包含.js即跳过扫描的问题。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加druid的扫描配置。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加springboot扫描绕过部分（后跟.json后缀、增加/绕过方式）。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加log4j扫描的头部字段。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加spring漏洞扫描（core没加）。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加log4j的404路径扫描，未测试，没找到测试环境。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加fastjson扫描规则。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加ThinkPHP Scan。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">修改sql注入扫描<span style="mso-spacerun:yes;"> </span>-<span style="mso-spacerun:yes;"> </span>后续慢慢来，工程量太大。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加weblogic检测poc。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">删除Level Make功能。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">修改scannedURL，改为每个POC都有自己的scannedURL并单独检测。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">增加fastjson检测（参数中的）。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="word-break: break-all;" width="12"><br/></td><td width="519" x:str="" style="">增加shiro扫描key - 比较占用时间，决定不加。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="word-break: break-all;" width="12"><br/></td><td width="519" x:str="" style="">增加log4j、Text4shell、fastjson的延迟检测 - 决定不加，手动探测吧。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">修改bp的interface，改为2022的interface，目前issue无法同步到dashboard那里。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">设置ThinkPHP扫描每个目标仅扫一次。</td></tr><tr height="20" style="height:15.00pt;"><td height="15" x:str="" style="" width="12">√</td><td width="519" x:str="" style="">设置weblogic扫描每个目标仅扫描一次。</td></tr></tbody></table>-   
### Thanks  
  
部分代码参考来源：  
  
https://github.com/pmiaowu/BurpShiroPassiveScan  
  
https://github.com/pmiaowu/BurpFastJsonScan  
  
https://github.com/l1ubai/GyScan  
  
https://github.com/whwlsfb/Log4j2Scan  
### END  
  
 欢迎各位师傅提Issue。。。  
###   
  
****###   
  
