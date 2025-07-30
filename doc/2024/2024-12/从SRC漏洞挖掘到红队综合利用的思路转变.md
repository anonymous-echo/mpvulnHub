#  从SRC漏洞挖掘到红队综合利用的思路转变   
原创 487DonkeySec  487Donkey Sec   2024-12-26 09:15  
  
红队第一期的培训已经结束，跟学员了解到一些情况，做渗透测试、挖SRC都能频频出漏洞，但并不了解如何去将漏洞深入的  
综合  
利用。  
  
在日常的渗透测试与漏洞挖掘过程中，安全研究人员往往会尽量做到点到为止，仅仅证明漏洞的存在即可。然而，在实际的攻击场景中，漏洞挖掘仅仅是第一步，后续如何通过综合漏洞利用获取到目标服务器权限才是实现攻击的关键。  
  
在实战中，  
发现漏洞存在后还需要懂得利用漏洞的特性综合利用从而达到目的。  
许多被忽视的小漏洞往往能在关键时刻发挥出意想不到的效果。  
这些小漏洞包括  
内网IP泄漏  
、  
绝对路径泄露、默认安装路径  
等。以下是几个简单例子：  
  
1. 内网IP泄漏导致的内网漫游  
  
目标站点服务器本地的内网地址会因为开发人员的疏忽或者安全意识不到位从而写到项目的静态文件中，从而泄漏内网IP地址，这种小漏洞往往会被忽视，但当可以满足一些前置条件的情况下也可以称为综合利用当中的一环。  
  
示例分析：在一个目标站点属于库分离架构并且不出网的环境下，存在mssql数据库的注入能够执行系统命令的  
环境，想对其进行内网横向移动扩大战果该怎么办呢？  
  
难点  
：  
不出网  
无法直接上线远控  
、  
无法远程下载程序、sql语句  
写  
文件  
有  
限制...  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wd3JaJGKlfueayzcBJlWoOUxcpAibTgIpa3KolUBLQaArRicr9ta0icgPL6ApaEVQmLFCKw3bWaJQpHYdnc48RVVw/640?wx_fmt=png&from=appmsg "")  
  
利用前期信息收集时发现的目标站点内网IP地址，找到任意文件上传功能点，可以获取到对应的文件落地URL地址，即可通过Web服务器作为中间文件服务器下载横向移动所需的工具（  
PS:后缀不重要将exe文件以png格式上传也不影响  
），再利用SQL注入实现命令执行，通过内网地址下载文件到数据库服务器上，反之 也可以通过数据库服务器将内网文件通过目标站上传，再在互联网下载到攻击者本地。  
以  
目标为载体对目标  
内网  
通讯，直接“  
隔山  
打牛”  
对内网进行横向。  
  
2.  
从绝对路径泄漏到任意文件上传  
  
   
绝对路径泄露是在错误提示或日志中显示了文件系统的绝对路径  
  
示例分析：全站都是访问路由，  
遇到任意文件读取/下载  
漏  
洞，低权限  
  
难点  
：无法知道Web应用的文件名、读取不了系统历史命令...  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wd3JaJGKlfueayzcBJlWoOUxcpAibTgIpJ6rKvDmicicX36SAO9QDicSvcliaNjrqIc2Pv92icZJxSTcvwsmCyOpYc4Q/640?wx_fmt=png&from=appmsg "")  
  
任意文件读取结合绝对路径泄漏扩大攻击面，通过泄露的绝对路径去查找中间件日志，根据访问日志获取到更多接口路径甚至一些后端的未授权接口来进行进一步的渗透。直到获取到主机权限。  
  
3.  
从默认安装路径到权限获取  
  
这里说的默认安装路径是指一些项目或者厂商部署服务时存在默认路径。  
  
示例分析：存在文件上传漏洞路径可控，上传落地的附件目录不在Web根目录  
  
难点：  
存在文件上传漏洞，但是响应中不回显文件落地后的路径或者URL链接。及时成功文件上传也无法访问WebShell。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/wd3JaJGKlfueayzcBJlWoOUxcpAibTgIpEqdv6ibWdc4IhkJRZ6fqiacM5bw69t1oEtFPlgibPRmEZKue8xOIdWMAw/640?wx_fmt=png&from=appmsg "")  
  
参考HiKVISION 综合安防管理平台report任意文件上传漏洞的利用。  
```
POST /svm/api/external/report HTTP/1.1
Host: 
Content-Type: multipart/form-data; boundary=----WebKitFormBoundary9PggsiM755PLa54a
------WebKitFormBoundary9PggsiM755PLa54a
Content-Disposition: form-data; name="file"; filename="../../../../../../../../../../../opt/hikvision/web/components/tomcat85linux64.1/webapps/eportal/new.jsp"
Content-Type: application/zip
<%out.print("test");%>
------WebKitFormBoundary9PggsiM755PLa54a--
```  
  
通过部署目标站点的相同系统或者互联网检索获取到Web应用默认安装的安装路径，在上传时使用../跨目录的方式将webshell传到Web根目录...  
  
PS：以上案例均来自实战，手法跟思路区别于常规的渗透测试方法，但正是这样的组合拳才可以在攻防演练中打开更多的突破点。综合渗透的任何一个小细节都可能是打穿目标单位的最后一根稻草！！！  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
