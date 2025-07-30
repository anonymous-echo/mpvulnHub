#  【神兵利器】Spring-Boot漏洞利用工具   
wh1t3zer  七芒星实验室   2024-11-25 23:00  
  
**项目介绍**  
  
SpringBootVul-GUI是  
一个半自动化springboot打点工具，内置目前springboot所有漏洞  
  
**文件结构**  
```
├──SpringbootVul-GUI
  ├── META-INF/
  ├── resources/    # 存放资源文件、字典和exp的跨文件
  ├── HPFile/        # 存放下载的heapdump
  ├── src/          # 工程代码
  ├── image/        
  ├── libs/          # 所需依赖
```  
  
**支持功能**  
- 配置不正当导致的泄露  
  
-  脱敏密码明文(1)  
  
-  增加漏洞利用选择模块，可以选择单一或多个漏洞进行检测  
  
-  命令执行漏洞式支持交互式执行命令  
  
-  Spring Gateway RCE  
  
-  heapdump文件下载导致敏感信息泄露  
  
-  druid数据连接池  
  
-  脱敏密码明文(2)  
  
-  脱敏密码明文(3)  
  
-  eureka中xstream基于反序列化的RCE  
  
-  spring.datasource.data 基于h2数据库的RCE  
  
-  基于SpEL注入的RCE  
  
-  spring.main.source的groovyRCE  
  
-  logging.config的groovyRCE  
  
-  H2数据库设置query属性的RCE  
  
-  logging.config的logback基于JNDI的RCE  
  
-  CVE-2021-21234任意文件读取  
  
-  h2数据库的控制台基于JNDI注入的RCE  
  
-  SpringCloud的SnakeYaml的RCE  
  
-  jolokia中logback基于JNDI注入的RCE  
  
-   
**使用演示**  
  
**(1) 密码脱敏**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusDicOr0tNibTC2Ouju5F5CudHI59MiayKhLHlfBbebIHs0sgdcN956onicw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusnZTrVETTII7dia2rPE7pibWoJge6qEFwlA4vscnAOkO4kT0zLbaLDSiaA/640?wx_fmt=png&from=appmsg "")  
  
得到Authorization字段的数据用base64解码即可，有时间再优化下能直接显示到文本框里****  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusqKTmHocVKAVsIGN65kCLkqA92bE3swMkPeI0P7ib2xzDVXianMrBKODg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusnrHJUkcKU1flj7tO78b8pVLwHm6OE6USH49YRV6gx5yTWggkw1GeWQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusd6bbgWU0ylicTATgk3pLfSlhNm8ZzLRCtmkDc89ibvYriaoUcS4WY3DuQ/640?wx_fmt=png&from=appmsg "")  
  
**(2)  Spring Cloud Gateway 交互式命令**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusOTs0Agf1JIRnw9mfShz2qVT5WlnVGbLjwsNNOTalhd8eO0BibaBj6LQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusaTVReousJ9fukswaFurONz3buy31ibUyTxibX00AibbSRca3icS4ibJ15TQ/640?wx_fmt=png&from=appmsg "")  
  
**痕迹清除：**  
  
默认清除poctest、pwnshell和expvul路由，其他路由自行判断  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusIlHJ3tr1ibsHHHcJy5f9gm7eVugicpI5JTrjib6dt5Kdq7IM7CJdibn43A/640?wx_fmt=png&from=appmsg "")  
  
(3)   
E  
ureka 反序列化RCE（慎用）  
  
直接点击getshell反弹，单纯poc测试的没写，python文件放同一目录下了，需要在vps启用2个端口，一个是你python服务器的端口，一个是反弹端口，写在python文件中，反弹端口默认是9000，注意这两个端口区别，输入框的端口是托管服务器端口  
```
nc -lvk 9000 # mac
nc -lvp 9000 # linux
python -m http.server 80
```  
  
备注：  
该数据包发送后会驻留到目标Eureka会不断请求，若造成服务器出错时，可能会导致无法访问网站的路由  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusLWA7Tia7enafmWbW9DfH5hPtCCWiaDrdYr9EtEUibsWt3cZVECvn0XLHg/640?wx_fmt=png&from=appmsg "")  
  
**(4) H2DatabaseSource RCE（慎用）**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusz94yLbYBmAWsHdMINrHfXjBnyD1TfkwTJFLfSSrRBuPQffueagVqZg/640?wx_fmt=png&from=appmsg "")  
  
目前已经基本完成一键getshell，理论上只要在不关闭的情况下可以无限弹，因为目前的payload是从T5开始的，如果遇到网站被测试过时，那大概率会报错而导致对方服务宕机，因为这是不回显RCE，无法判断到底有没有被测试过。现为随机生成3位数字，没有关闭工具的情况下默认递增。  
  
监听端口默认是8881  
  
输入框中填写你开启服务器的端口，目前为了能无限弹的机制，暂时只能设置在该项目的resources文件夹开启  
```
nc -lvk 8881 # mac
nc -lvp 8881 # linux
python -m http.server 80
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusib3X5q3yRbq1yocWEDr4XGibZXCCT3vRicyS7MH2KuS4KCnA2IdYXZBAA/640?wx_fmt=png&from=appmsg "")  
  
**（5） SpEL注入导致的RCE**  
  
可以同时检测多个参数值，要在参数值上打上一个单引号'作为标记'  
  
http://127.0.0.1:9091/article?id=1'&b=2'  
  
getshell功能可以直接弹shell，getshell模块直接输入地址+路由+参数，无需加=和后面的值  
```
nc -lvk port # mac
nc -lvp port # linux
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceuseSyiaRYCJ1qm6OjBLyaUSxLj5oMIDWicobGIZpMia4haiaGwJsyDVSfnKA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceus81AYqp2CxonSCQysrShdqiczVk3yljNp8wdlkLRvt7ej1UiaqjCEWBLA/640?wx_fmt=png&from=appmsg "")  
  
**(6) MainSourceGroovyRCE**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceuscxw6gShcuAlyphKb84ooI2vlwB5txyXdVAtB9UkSy3csWdSUHwSicDg/640?wx_fmt=png&from=appmsg "")  
  
一键getshell监听的端口是托管groovy文件的端口，反弹端口默认为7777，输入框中填写你开启服务器的端口，目前为了更好弹shell，最好设置在该项目的resources文件夹开启  
  
备注：“HTTP 服务器如果返回含有畸形 groovy 语法内容的文件，会导致程序异常退出”  
  
所以师傅有需要修改代码或者其他用途的时候，修改代码的时候不要改错groovy内容并且文件内容也不要随意修改，以防万一  
```
nc -lvk 7777 # mac
nc -lvp 7777 # linux
python -m http.server 80
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusUy4iaJxZWEJZlH1S5AVcraYdLMRx502h7GbgIbGIjtBQQdbDH5ibChCA/640?wx_fmt=png&from=appmsg "")  
  
(7)   
LoggingConfigGroovyRCE  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJcQz9vmUicmVJibU4Odib6wGXdE8b9ceusGKy3jxTiayV7icAfGjOj3EpTedZSvuGZjtCwZU2EYiayBTMDKUkFtepRA/640?wx_fmt=png&from=appmsg "")  
  
**下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【**  
**241126****】获取**  
**下载链接**  
  
****  
**·推 荐 阅 读·**  
  
# 最新后渗透免杀工具  
# 【护网必备】高危漏洞综合利用工具  
#    【护网必备】Shiro反序列化漏洞综合利用工具增强版  
# 【护网必备】外网打点必备-WeblogicTool  
# 【护网必备】最新Struts2全版本漏洞检测工具  
# Nacos漏洞综合利用工具  
# 重点OA系统漏洞利用综合工具箱    
# 【护网必备】海康威视RCE批量检测利用工具  
# 【护网必备】浏览器用户密码|Cookie|书签|下载记录导出工具  
  
  
横向移动之RDP&Desktop Session Hija  
  
