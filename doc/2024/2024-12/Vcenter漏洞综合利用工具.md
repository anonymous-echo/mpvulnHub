#  Vcenter漏洞综合利用工具   
 SecHub网络安全社区   2024-12-27 02:08  
  
****  
****  
****  
**点击蓝字 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**免责声明**  
  
本文发布的工具和脚本，仅用作测试和学习研究，禁止用于商业用途，不能保证其合法性，准确性，完整性和有效性，请根据情况自行判断。  
  
如果任何单位或个人认为该项目的脚本可能涉嫌侵犯其权利，则应及时通知并提供身份证明，所有权证明，我们将在收到认证文件后删除相关内容。  
  
文中所涉及的技术、思路及工具等相关知识仅供安全为目的的学习使用，任何人不得将其应用于非法用途及盈利等目的，间接使用文章中的任何工具、思路及技术，我方对于由此引起的法律后果概不负责。  
## 🌟简介  
  
      
一款针对Vcenter的综合利用工具，包含目前最主流的CVE-2021-21972、CVE-2021-21985以及CVE-2021-22005、One Access的CVE-2022-22954、CVE-2022-22972/31656以及log4j，提供一键上传webshell，命令执行或者上传公钥使用SSH免密连接  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZqUq9q2xQ7VlWkPdM2yldwHvO3GXYGnp1Qyibrwc2IqVxZTUIDhPBCCZyQhOnycIickcn7SQoI2CUcg/640?wx_fmt=png&from=appmsg "")  
  
#### -1.注意  
  
  
在本地搭建漏洞环境的师傅，用vckiller验证log4j基本上会失败，因为在Vmware 虚拟机环境下用NAT模式的话，验证模块中的出口网卡会被判定为127.0.0.1，这样目标访问的LDAP Server地址就变成了127.0.0.1，验证就失败了😏  
  
#### 0.必读  
  
  
如果遇到bug请提issue，写这个工具单纯是为了方便，它没有什么高大上的东西  
  
#### 1.它是什么  
  
  
一款针对Vcenter的综合  
验证工具，包含目前最主流的CVE-2021-21972、CVE-2021-21985以及CVE-2021-22005，提供一键上传webshell，命令执行或者上传公钥并使用SSH连接的功能，以及针对Apache Log4j CVE-2021-44228漏洞在Vcenter上的检测以及利用，比如命令执行并获取回显（  
需要一个ldap恶意服务器），现在不需要另外启动ldap服务器了，我根据jndi-injection工具手搓了一个利用方式，Vcenter使用的中间件是Tomcat，直接使用TomcatBypass的利用链就行了。  
  
#### 2.它的定位  
  
  
一般Vcenter都放在内网，并且漏洞特征也都是烂大街，像什么fscan啦一扫就出来了，那么VcenterKiller就不是用来检测目标是否存在漏洞的，而是直接尝试利用，一般通过CS/MSF在跳板上来执行，所以去掉了其余花里胡哨的输出。  
  
为什么用GO，因为Python写起来方便但是用起来很蛋疼，各种依赖库，并且编译出来体积太大，C#没法跨平台，写到一半扔了。  
  
#### 3.使用方法  
  
```
```  
  
#### 4.免责声明  
  
  
本工具仅面向  
合法授权的企业安全建设行为，例如企业内部攻防演练、漏洞验证和复测，如您需要测试本工具的可用性，请自行搭建靶机环境。  
  
在使用本工具进行检测时，您应确保该行为符合当地的法律法规，并且已经取得了足够的授权。  
请勿对非授权目标使用。  
  
如您在使用本工具的过程中存在任何非法行为，  
您需自行承担相应后果，我们将不承担任何法律及连带责任。  
  
#### 5.更新日志  
  
```
```  
  
# 项目地址  
```
https://github.com/Schira4396/VcenterKiller
```  
  
  
  
欢迎关注SecHub网络安全社区，SecHub网络安全社区目前邀请式注册，邀请码获取见公众号菜单【邀请码】  
  
**#**  
  
  
**企业简介**  
  
  
**赛克艾威 - 网络安全解决方案提供商**  
  
****  
       北京赛克艾威科技有限公司（简称：赛克艾威），成立于2016年9月，提供全面的安全解决方案和专业的技术服务，帮助客户保护数字资产和网络环境的安全。  
  
  
安全评估|渗透测试|漏洞扫描|安全巡检  
  
代码审计|钓鱼演练|应急响应|安全运维  
  
重大时刻安保|企业安全培训  
  
![](https://mmbiz.qpic.cn/mmbiz_png/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwuh8LP87lPQLxMwiceAsv3TurmE7zZOulOhMELnQ2OulwFIJkbmB3bRg/640?wx_fmt=png "")  
  
  
**联系方式**  
  
电话｜010-86460828   
  
官网｜https://sechub.com.cn  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0FW5uwU0BZtn2lmMrLPwpibCeCVbtBFDRkbFb7n7ibhPRxg20spUo9mUIiakmRYABB88Idl81IpGuXfw/640?wx_fmt=gif "")  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/SUZ43ICubr4mWJcUARDKYbQooQjbjbmqZTerAIXqDX9CaVxXbB7pyWwnMRklrCJias9r59PhnJAxZ4e3gYjyqVQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8icWLyUKibZZrPdaxnm18Zscp6Xcu0OiaMwyhlWCYDVqK38BA5dbjKkH7icWmAew7SYRA7ao1bFibialrMvmQ9ib0TBvw/640?wx_fmt=jpeg "")  
  
  
**公众号：**sechub安全  
  
**哔哩号：**SecHub官方账号  
  
  
