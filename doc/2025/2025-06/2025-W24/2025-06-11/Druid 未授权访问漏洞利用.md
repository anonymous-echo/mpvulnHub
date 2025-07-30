#  Druid 未授权访问漏洞利用  
徐志洋  玄武盾网络技术实验室   2025-06-11 02:19  
  
## 免责声明：本文仅供安全研究与学习之用，严禁用于非法用途，违者后果自负。  
## 0x00 前言  
  
在近期的渗透测试实践中，发现某目标系统存在 Druid 监控平台的未授权访问漏洞。基于漏洞利用的常规思路，尝试通过获取有效会话凭证（Session）实现后台访问，并进一步探索系统命令执行权限的可能性。以下是漏洞发现与实战过程的技术复盘  
## 0x01 Druid背景介绍  
  
Druid 作为阿里巴巴数据库团队研发的专业数据库连接池组件，其核心定位是兼具高性能与全方位监控能力。该组件内置的监控体系可实现对 SQL 执行耗时的精准统计、Web URI 请求的全链路追踪以及 Session 状态的实时监测。从技术架构层面而言，Druid 本身具备较为完善的安全设计，其漏洞风险通常源于开发者在实际部署过程中产生的配置缺陷，典型场景如未正确设置访问认证机制、未限制敏感监控接口的访问范围等，此类配置不当会直接导致未授权访问风险的产生。  
## 0x02 漏洞详情  
  
在网络安全攻防场景或 SRC 漏洞报送体系中，**Druid 监控平台的未授权访问漏洞通常被划分为低危风险**  
。然而，通过深度挖掘漏洞的链式利用潜力，可将其转化为获取高价值目标权限的关键入口。  
  
在利用时该漏洞时，可能需要用到两个界面的信息，分别是/druid/weburi.html  
和/druid/websession.html  
。/druid/weburi.html  
界面会保存系统中存在的目录和接口信息，/druid/websession.html  
界面会保存所有的Session  
信息，包括创建时间、最后访问时间、访问IP  
地址等信息。  
  
注意：Druid  
未授权访问路径，并不都是位于网站根目录下，有的会在二级目录下，在利用时，需要根据  
真实环境进行路径拼接，常用Druid未授权访问路径：  
```
/druid/index.html                                    #首页/druid/datasource.html                                #数据源/druid/sql.html                                        #SQL监控/druid/wall.html                                    #SQL防火墙/druid/webapp.html                                    #Web应用/druid/weburi.html                                    #URI监控/druid/websession.html                                #Session监控/druid/spring.html                                    #spring监控/druid/api.html                                        #JSON API
```  
## 0x03 漏洞实战操作  
### 3.1 制作session字典  
  
（1）访问/druid/websession.html  
界面，可以看到存在很多Session  
，直接选中页面中全部的内容，复制下来。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87WzoEwSLOAcpxaar3am2yxqgVTQ0FpRwkZjofkO2micib9SWYQoWJTDjMOA/640?wx_fmt=png&from=appmsg "")  
  
（2）将复制的内容到Excel  
中进行粘贴，直接拉到Excel  
最底部，选择今天日期的全部Session  
进行复制。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87WzcqYRF60gn5p2icYZ9MgVLcDyXeeLGOk5V2ZBqstehYUyTWeHQWPUcPQ/640?wx_fmt=png&from=appmsg "")  
  
（3）将复制的Session  
粘贴到txt  
中，作为字典使用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87WzjePGHxPmMKQXMGuFgEWOLQric791IchibFLapKWpy6NxI7ul7ibtYj0GQ/640?wx_fmt=png&from=appmsg "")  
### 3.2 确定一个后台目录  
  
访问/druid/weburi.html  
界面时，页面中展示有大量目录信息。需注意的是，并非所有目录均可正常访问，且其中未必包含后台管理目录，因此需进行多次尝试验证。经过反复测试，最终确认index  
目录为目标系统的后台管理入口。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87WzGtkh4SmxwwUHMEhmWGzOElcia8kWib5zt7Q2ZNanGqWTIxNMRriat5uoA/640?wx_fmt=png&from=appmsg "")  
### 3.3 使用burp进行爆破session  
  
（1）  
访问index  
界面，使用burp工具抓取数据包，然后对Session  
进行暴力破解，在爆破结果中只存在一条为200的状态码  
，其余全为302  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87Wz4asia0Yw2bTj8GHPWQ6U7Hf1qIiajuAUMSyQjN3FIUw7DoQXJFdamuJw/640?wx_fmt=png&from=appmsg "")  
  
（2）  
使用浏览器调试工具（如 EditThisCookie 插件）捕获状态码为 200（表示请求成功）的有效会话凭证（Session）。将捕获的会话数据替换目标系统原有 Cookie 信息，保存后在 URL 路径中追加后台管理目录（如 /admin、/manage 等），即可完成会话劫持操作  
。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87WzasG6kPEczPR8VEjjdsJtnSwxo1bATFtjg35PGM0q92pWoSWYdvicwMg/640?wx_fmt=png&from=appmsg "")  
  
（3）**通过界面刷新操作，成功实现后台管理系统的访问登录**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0nVR3SzhOzmgeuwsjzh87WzXOR7s2HYZYcbSFKSK7rANcd7yQVT2T5d6JSEsGeqOwqib1icZm09zwbA/640?wx_fmt=png&from=appmsg "")  
## 0x04 总结  
  
该漏洞的利用方式虽不复杂，但实际操作过程中，运气成分往往起到关键作用。只有在目标用户处于在线状态时，攻击者才能获取有效的会话凭证（Session）并加以利用；反之，若仅持有过期或无效的会话数据，则攻击失败。在选择攻击时机方面，建议优先选择业务高峰期（如工作日上班时段）进行尝试。此时系统中活跃用户数量显著增加，成功获取有效会话的概率也将大幅提升。  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/UM0M1icqlo0knIjq7rj7rsX0r4Rf2CDQylx0IjMfpPM93icE9AGx28bqwDRau5EkcWpK6WBAG5zGDS41wkfcvJiaA/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
声明：  
技术文章均收集于互联网，仅作为本人学习、记录使用。  
侵权删  
！  
！  
！  
  
  
