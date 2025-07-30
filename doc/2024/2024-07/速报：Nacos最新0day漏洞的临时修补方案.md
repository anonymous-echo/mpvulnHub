#  速报：Nacos最新0day漏洞的临时修补方案   
原创 abc123info  希潭实验室   2024-07-15 19:11  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450ATcz6jUJnFNeOxRzVZ9Lbc0INLwTJTZT1GaNutZrfDn6csvjBoS2ox0efLUEexXqPEcVbYfbLo8w/640?wx_fmt=png "")  
##  Part1 前言   
  
**大家好，我是ABC_123**  
。今天下午github上有网友公布了最新的nacos远程代码执行漏洞及exp，目前官方补丁还没出来，这里ABC_123给大家提供一个临时的漏洞修补方案。  
  
##  Part2 技术研究过程   
  
首先这个nacos的0day漏洞是真实存在的，危害是很严重的，再者这是一个登录后台才能利用的漏洞，而且不出网也能利用。有网友会说，有的nacos不需要登录后台也能打，那是因为所打的nacos存在之前的匿名访问漏洞、或者鉴权漏洞。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450AQs2qljPrMOnY6iaURUpGJT8xFkj24IJuCnlkJGMianvBiawjQDz93OaJ3vCSzPZW4qTLKSGOlYBt5w/640?wx_fmt=png&from=appmsg "")  
  
  
**这里给出一个临时的修补漏洞的方法：**  
  
**1   升级nacos到最新版本**  
（原因：杜绝nacos前期出现的几个未授权访问漏洞）。  
  
**2   禁止nacos的匿名访问，开启鉴权**  
。  
  
**3   nacos的口令设置得足够复杂**  
（原因：杜绝弱口令，这个nacos的0day漏洞是需要登录后台才能利用）。  
  
**以上三条措施做好了，就可以解决修复该漏洞。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OAz0RNU450A5qqg2iaK6KIYYR8y6pF5Rh3JHDibOKOop204nXz618iawdRb8dABicMPtHb2PkJE8x6koJO5HyuwZJQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
**公众号专注于网络安全技术，包括安全咨询、APT事件分析、红队攻防、蓝队分析、渗透测试、代码审计等，99%原创，敬请关注。**  
  
**Contact me: 0day123abc#gmail.com**  
  
**(replace # with @)**  
  
  
  
  
