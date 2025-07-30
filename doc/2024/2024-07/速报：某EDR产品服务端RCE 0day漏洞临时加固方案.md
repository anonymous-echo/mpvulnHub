#  速报：某EDR产品服务端RCE 0day漏洞临时加固方案   
原创 abc123info  希潭实验室   2024-07-21 22:22  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9LbcCCMJ6Af2WYicgMPA32IwibF8mI2ibC9h8jaHkhxnZzZuqctMLRTxDudicA/640?wx_fmt=png "")  
##  Part1 前言   
  
**大家好，我是ABC_123**  
。一年一度的大考即将开始了，坊间确切消息，某EDR的服务端存在RCE的0day漏洞，具体影响版本不详。这里ABC_123给大家提供一个临时的加固方案，有其他修补建议欢迎在文末给我留言。  
  
##  Part2 研究过程   
  
一般一个单位最快出局的方法就是：外网打一个点或者钓鱼邮件获取权限，内网使用0day/1day干掉集权类系统，然后  
下发命令  
或  
者直连靶标，随后该单位直接出局。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/OAz0RNU450BspxRJXqXvoHoPRibbV95Ftuf4GNyLx0UqlbphzOWlWuvAMLBvkFLss7yw9ymjbI41Rpl7icp1DVTw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
所以这种0day危害特别大，跟几个朋友讨论了一下，给出的临时加固方案如下：  
  
**1   EDR服务端所在机器异构化**  
。可以装个强杀软或者其它的EDR客户端辅助一下，当然需要提前测好兼容性，防止两个产品打架。  
  
**2   EDR服务端设置IP访问白名单**  
。只允许EDR的Agent的IP进行访问，防止从业务段Web系统的IP直接访问。  
  
**3   限制EDR服务端与靶标的文件下发和远控能力**  
。防止EDR服务端被搞下，直连靶标，导致该单位直接出局。  
  
**4   EDR服务端设置监控**  
。做好数字签名新增监控，对重点文件的增、删、改、查，命令执行监控等等，这里就不细说了。  
  
**5   限制终端EDR服务端出网**  
。增加内网代理及内网横向的难度。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450A5qqg2iaK6KIYYR8y6pF5Rh3JHDibOKOop204nXz618iawdRb8dABicMPtHb2PkJE8x6koJO5HyuwZJQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
********  
**公众号专注于网络安全技术，包括安全咨询、APT事件分析、红队攻防、蓝队分析、渗透测试、代码审计等，99%原创，敬请关注。**  
  
**Contact me: 0day123abc#gmail.com**  
  
**(replace # with @)**  
  
  
  
  
  
  
