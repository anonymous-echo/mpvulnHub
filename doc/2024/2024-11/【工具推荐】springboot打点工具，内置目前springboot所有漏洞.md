#  【工具推荐】springboot打点工具，内置目前springboot所有漏洞   
wh1t3zer  Z2O安全攻防   2024-11-28 13:28  
  
点击上方[蓝字]，关注我们  
  
  
**建议大家把公众号“Z2O安全攻防”设为星标，否则可能就看不到啦！**  
因为公众号现在只对常读和星标的公众号才能展示大图推送。操作方法：点击右上角的【...】，然后点击【设为星标】即可。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuao3T9EnGbUIqxgDhEVicCV8NbH4FiaZ3YIbpXNEr6qFicGkAelnQHKGHsVlfapMGgO3DHA68iaiac0n4Q/640?wx_fmt=png "")  
  
  
# 免责声明  
  
  
本文仅用于技术讨论与学习，利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者及本公众号团队不为此承担任何责任。  
  
# 文章正文  
  
  
一个半自动化springboot打点工具，内置目前springboot所有漏洞  
- • 配置不正当导致的泄露  
  
- • 脱敏密码明文(1)  
  
- • 增加漏洞利用选择模块，可以选择单一或多个漏洞进行检测  
  
- • 命令执行漏洞式支持交互式执行命令  
  
- • Spring Gateway RCE  
  
- • heapdump文件下载导致敏感信息泄露  
  
- • druid数据连接池  
  
- • 脱敏密码明文(2)  
  
- • 脱敏密码明文(3)  
  
- • eureka中xstream基于反序列化的RCE  
  
- • spring.datasource.data 基于h2数据库的RCE  
  
- • 基于SpEL注入的RCE  
  
- • spring.main.source的groovyRCE  
  
- • logging.config的groovyRCE  
  
- • H2数据库设置query属性的RCE  
  
- • logging.config的logback基于JNDI的RCE  
  
- • CVE-2021-21234任意文件读取  
  
- • h2数据库的控制台基于JNDI注入的RCE  
  
- • SpringCloud的SnakeYaml的RCE  
  
- • jolokia中logback基于JNDI注入的RCE  
  
- • jolokia中realm基于JNDI注入的RCE  
  
- • mysql中jdbc基于反序列化的RCE(暂不写，需配合痕迹清除一起用，不然造成对方数据库业务异常)(需ysoserial工具)  
  
## 项目演示  
### #1 密码脱敏  
  
脱敏（1）  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJA49IezZaZTOMys1kXUicsEHaQibK7UwibOtZYYXTE1XibzwibByRtweQRBQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJDzxO8zodceYLXjAiauOPLwZiaC7NgjuM4QhOkqD5euCREwb7HzW9kpTw/640?wx_fmt=png&from=appmsg "")  
  
  
脱敏（2）  
  
得到Authorization字段的数据，用base64解码即可，有时间再优化下能直接显示到文本框里  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJ3gxrpGwxZ6LRNQosgubc0bOJq9qVAegFRvmz4RL7swKj1xEEA6V5Xw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJvq3KZQIGsOOGX160kd8yiab5XkSyDlJZc0glb2YDreCibw57Gx6OGKHQ/640?wx_fmt=png&from=appmsg "")  
  
### #2 Spring Cloud Gateway 交互式命令  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJRFYvb1XQXBeKbibjhLGvpztBkka53MgEWRxINcDO5lrKrYzZLR3dd5Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJiaIPib02XibEiamxWwt65LIsHZgAW6d1o8RDAedyWQVJV0ETpjmoDBMNMw/640?wx_fmt=png&from=appmsg "")  
  
  
**痕迹清除**  
  
默认清除poctest、pwnshell和expvul路由，其他路由自行判断  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJ8XCE6fjFI3YGHWhapzmiaNB6adAHqZaXBaicZicicN0lldSkkK1g7UjE7Q/640?wx_fmt=png&from=appmsg "")  
  
### #10 CVE-2021-21234任意文件读取  
  
(仅做poc测试，后续加入输入文件名)  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJib1YxtiaAX9McH7kZpu6ibu9ZCtLDZ0QSoje7TR41nFV2YwhyY0ybGOlA/640?wx_fmt=png&from=appmsg "")  
  
  
### #12 SnakeYamlRCE  
  
POC  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJKnLicRICOeJz67cccMtpuiauDpqQ46nTOvbjianYof13ZqWRoy9kviblgA/640?wx_fmt=png&from=appmsg "")  
  
  
### #15 一键上马  
  
密钥默认为hackfunny  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJBO6VpoVbibcBb6RINK5oRlqj0FbDCngoQY0wYTBMeFEZYEgAz9Ogxtg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubtxibIWQUw62IgIVZO7HYgJEFswyhBnJCP71CW8iceiaSjiaDpice628fjgiawuaDZb2WIGPMRRlVZxQBA/640?wx_fmt=png&from=appmsg "")  
  
img  
  
  
**后台回复"241128"获取工具地址**  
  
  
  
### 考证咨询  
  
  
最优惠报考  
各类安全证书(NISP/CISP/CISSP/PTE/PTS/PMP/IRE等....)，后台回复"  
好友位"咨询。  
  
# 技术交流  
  
  
### 知识星球  
  
  
**欢迎加入知识星球****，星球致力于红蓝对抗，实战攻防，星球不定时更新内外网攻防渗透技巧，以及最新学习研究成果等。常态化更新最新安全动态。针对网络安全成员的普遍水平，为星友提供了教程、工具、POC&EXP以及各种学习笔记等等。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmXPg6kVsggaWKZsh0ab2kh6icbbkBgOH8icuV0x2IPGGRMiaU2hNBErstcA/640?wx_fmt=png&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYl1eHu25UAxhOZEBXZpSmX8Pjria4EK9ib8PPUAxiaMaSqUZibdxNoqqmmVHqGwXkYdzziaZNDLOwCGQw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKubkRgdNbBQdOZibtbt7oibUpdUIl55vlmiaibqInxXG1Z9tfo52jF8onER5R4U2mCM5RpZia6rwEHnlMAg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/h8P1KUHOKuYItiapGtLIq3gAQYGfE5nictnkFeBicm7brKdibz4Va1hRf2dKZT0IyRRXYboE1lbZ6ZquDGnzqKibGGw/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/h8P1KUHOKub0WpCibOMMSdictvo8OHh6dticYAz6QYzXibSpQD5ohWB1ambKv8Tamf7H6RjyVjVXxibKorFAeDeILOg/640?wx_fmt=other&tp=webp&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 交流群  
  
  
关注公众号回复“**加群**”，添加Z2OBot好友，自动拉你加入**Z2O安全攻防交流群(微信群)**分享更多好东西。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/h8P1KUHOKuYMO5aHRB3TbIy3xezlTAkbFzqIRfZNnicxSC23h1UmemDu9Jq38xrleA6NyoWBu1nAj0nmE6YXEHg/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
### 关注我们  
  
  
  
**关注福利：**  
  
**回复“**  
**书籍****" 获取  网络安全书籍PDF教程**  
  
**回复“**  
**字典****" 获取 针对一些字典重新划分处理，收集了几个密码管理字典生成器用来扩展更多字典的仓库。**  
  
**回复“漏洞库" 获取 最新漏洞POC库(**  
**1.2W+****)******  
  
**回复“资料" 获取 网络安全、渗透测试相关资料文档合集**  
  
****  
点个【 在看 】，你最好看  
  
  
