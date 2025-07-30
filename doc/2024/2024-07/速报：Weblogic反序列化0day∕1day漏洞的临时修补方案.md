#  速报：Weblogic反序列化0day/1day漏洞的临时修补方案   
原创 abc123info  希潭实验室   2024-07-19 19:26  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9LbcCCMJ6Af2WYicgMPA32IwibF8mI2ibC9h8jaHkhxnZzZuqctMLRTxDudicA/640?wx_fmt=png "")  
##   
##  Part1 前言   
  
**大家好，我是ABC_123**  
。一年一度的大考就要开始了，坊间传闻weblogic中间件爆出了0day或者1day漏洞，这里ABC_123给大家提供一个临时的漏洞修补方案。  
  
##  Part2 研究过程   
  
最近几年的weblogic反序列化漏洞都与T3和IIOP协议相关，所以还是建议禁用T3和IIOP协议，但是网上很多禁用方法不对，ABC_123给大家介绍一下正确操作方法。  
  
- **禁用T3协议过程**  
  
进入weblogic的后台之后，选择“安全”—“筛选器”，在“连接筛选器规则”输入  
  
**weblogic.security.net.ConnectionFilterImpl**  
  
连接筛选器规则中输入:  
  
**127.0.0.1 * * allow t3 t3s**  
  
**0.0.0.0/0 * * deny t3 t3s**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AJmeo5U5SYiaKBJXQHcfpkjv7p0tKVpu3TRVU9decqW68wIQjyzDMbFWPtEBKTUqUR5nbfaichDo9Q/640?wx_fmt=png&from=appmsg "")  
  
  
最后重启weblogic项目。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AJmeo5U5SYiaKBJXQHcfpkjrCqhlRrI4ZrIglYyicO0F3hP49EOaod13dJsh6wC6AtQYU0ExzCrFjQ/640?wx_fmt=png&from=appmsg "")  
  
  
经过测试，10.x版本的weblogic禁用T3需要重启，否则不会生效；12.x版本不需要重启，点击“保存”即可立即生效。  
  
- **禁用IIOP协议过程**  
  
进入weblogic的后台之后，选择“base_domain”—“环境”—“服务器”，然后在对应服务器设置中选择 “协议”—“IIOP” 选项卡，**取消 “启用IIOP” 前面的勾选**  
，然后重启weblogic项目。  
##   
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AJmeo5U5SYiaKBJXQHcfpkjg5Pbta2iaomE2MKxX4yflFib0RfO59wqLexgI2EKRrpH2HVSTMn94DGA/640?wx_fmt=png&from=appmsg "")  
  
  
经过ABC_123测试，几乎所有版本的weblogic，彻底禁用IIOP协议需要重启，否则即使点击了“保存”，也不会生效。禁用T3、IIOP协议之后，红队工具检测如下，提示filter blocked Socket。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AJmeo5U5SYiaKBJXQHcfpkjCpkUeuTX6Oj3tjdeErlRW0prfGmRFWjJibcdyPIvxC7fAjKwjy7VgMg/640?wx_fmt=png&from=appmsg "")  
  
- ## 其它修复方法  
  
借助安全设备、防火墙策略屏蔽T3及IIOP协议；  
也可以在Web  
logic前面放置一个Nginx，只对HTTP协议进行转发，对T3协议及IIOP协议不进行转发，但是这种方法只能杜绝外网攻击，无法杜绝内网横向中对于Weblogic反序列化漏洞的利用。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450A5qqg2iaK6KIYYR8y6pF5Rh3JHDibOKOop204nXz618iawdRb8dABicMPtHb2PkJE8x6koJO5HyuwZJQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
****  
**公众号专注于网络安全技术，包括安全咨询、APT事件分析、红队攻防、蓝队分析、渗透测试、代码审计等，99%原创，敬请关注。**  
  
**Contact me: 0day123abc#gmail.com**  
  
**(replace # with @)**  
  
  
  
  
  
