#  Pwn2Own大赛：黑客利用JavaScript零日漏洞攻破Firefox的技术细节   
 FreeBuf   2025-05-19 10:30  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
![Firefox安全漏洞与JavaScript攻击](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOlTs9PicI6y5kfyrMUicr6NtjunudFvxdm6MK37XZPDAiacD3eQy66de0QM6uia23zb5W9fJJz6pibCw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Mozilla已紧急修复Firefox浏览器中的两个关键零日漏洞（zero-day vulnerability），这两个漏洞均在上周柏林举行的Pwn2Own 2025黑客大赛中被成功利用。  
  
  
**Part01**  
### 漏洞利用过程  
  
  
在这场以顶尖安全研究员挑战流行软件而闻名的赛事中，Firefox浏览器通过高级JavaScript引擎漏洞被两次攻破。Mozilla在24小时内迅速响应，为Firefox和Firefox ESR（延长支持版本）发布了紧急安全更新。  
  
  
来自Palo Alto Networks的安全研究员Edouard Bochin（@le_douds）和Tao Yan（@Ga1ois）演示了如何利用涉及JavaScript Promise对象的越界写入漏洞（out-of-bounds write）攻破Firefox。该漏洞现被标记为CVE-2025-4918，可导致未授权的内存访问，进而引发代码执行或浏览器崩溃。  
  
  
![零日计划组织](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOlTs9PicI6y5kfyrMUicr6NXmKOzSnLvHv4EQFVWyuGSR0Lp3FaTMQMZsOiccs1AYxrUWV187X6IUQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
他们的研究成果为其赢得了5万美元奖金和5个"破解大师"积分——这是授予Pwn2Own杰出参与者的 prestigious 荣誉。  
  
  
**Part02**  
### 第二个高危漏洞  
  
  
知名Pwn2Own冠军Manfred Paul则利用一个严重的整数溢出漏洞（integer overflow）攻陷了Firefox的渲染器。该漏洞编号为CVE-2025-4919，根源在于JavaScript数组索引计算错误，可能导致越界读取或写入——这是权限提升和远程代码执行的经典路径。  
  
  
![零日计划组织](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibOlTs9PicI6y5kfyrMUicr6Nb1pBqrfve9RVMTCK2y05Ix2Xu5JQOjfQogbBYRDbAHAqFbUDCAGwTA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Paul凭借其创新且精确的攻击向量同样获得5万美元和5个"破解大师"积分。  
  
  
**Part03**  
### 受影响版本  
  
  
根据Mozilla公告，受影响的版本包括：  
  
- Firefox 138.0.4之前版本  
  
- Firefox ESR 128.10.1之前版本  
  
- Firefox ESR 115.23.1之前版本  
  
**Part04**  
### 紧急响应措施  
  
  
尽管趋势科技零日计划（Zero Day Initiative，ZDI）通常给予厂商90天的修复窗口，但Mozilla以超常速度完成了补丁发布——在漏洞公开演示后不到一周即推出修复方案，远快于ZDI的标准披露时间表。  
  
  
**Part05**  
### 安全建议  
  
  
这两个漏洞凸显了现代JavaScript引擎持续存在的安全风险——仅需一次内存操作不当就可能导致整个浏览器沦陷。鉴于Firefox在个人和企业环境中广泛使用，这些漏洞在熟练攻击者手中将构成切实的即时威胁。  
  
  
所有Firefox用户应立即升级至：  
  
- Firefox 138.0.4或更高版本  
  
- Firefox ESR 128.10.1或更高版本  
  
- Firefox ESR 115.23.1或更高版本  
  
用户可通过菜单→帮助→关于Firefox查看当前版本号。  
  
  
**参考来源：**  
  
Pwn2Own: Firefox Hacked with JavaScript Zero-Days – Details on the Exploits  
  
https://securityonline.info/pwn2own-firefox-hacked-with-javascript-zero-days-details-on-the-exploits/  
  
  
###   
###   
###   
### 推荐阅读  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651320917&idx=3&sn=7dc05cb9d3ab151bf6da222ec282fb34&scene=21#wechat_redirect)  
  
### 电台讨论  
  
****  
  
![图片](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
