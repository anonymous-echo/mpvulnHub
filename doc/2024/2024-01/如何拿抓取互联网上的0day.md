#  如何拿抓取互联网上的0day???   
原创 ChinaRan404  知攻善防实验室   2024-01-20 15:28  
  
关注本公众号，长期推送技术文章  
  
  
免责声明：请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息或者工具而造成的任何直接或者间接的后果及损失，均由使用者本人负责，所产生的一切不良后果与文章作者无关。该文章仅供学习用途使用！！！  
  
前言  
  
互联网上每天各种公众号都会发布一些漏洞，然而这些漏洞大概率曝光出来就是已经交完SRC的了，在交SRC之前，会通过资产搜索引擎搜集互联网资产，这些平台会短时间内多次扫描整个互联网  
  
那么，我们只需要保证我们的设备被扫描到，并且收录特征，并且记录流量特征即可。  
  
能满足这个需求的，可以使用蜜罐平台。  
  
本次实践以HFish作为演示，并且抓取数据包  
  
  
搭建教程  
  
实验环境：Ubuntu  
  
更新源  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpaOOuSL4ndbmFIhH9wEGcaFZbUpCVcWLu7cErerpaysJUpjksu3624gYNicB77Tul0SqichwQ6Ufiaw/640?wx_fmt=png&from=appmsg "")  
  
安装docker  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpaOOuSL4ndbmFIhH9wEGcatdch79xXkbXyiaAmqTj5FBVRmNDK7FDrpLhI7XpFetnqh2LIqjM3wiaw/640?wx_fmt=png&from=appmsg "")  
  
启动docker  
```
docker run -itd --name hfish \
-v /usr/share/hfish:/usr/share/hfish \
--network host \
--privileged=true \
threatbook/hfish-server:latest
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpaOOuSL4ndbmFIhH9wEGcalIvnP4gsw41ExcHzDDBicibY3WqaXpIIt92PNXN7LibibYblrb9dQYIicFw/640?wx_fmt=png&from=appmsg "")  
  
访问服务器地址  
```
https://192.168.5.138:4433/web/login
```  
  
登录用户名：admin  
  
密码：HFish2021  
  
根据自己需求部署  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35R4HXGmJic2lJfcvMxq7pDjksOXteawxA7SPc9YibibO12oMj8DY7lD4fMg/640?wx_fmt=png&from=appmsg "")  
  
部署完后找到节点管理  
  
即可看到所有的蜜罐模板  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35RicmgticYZuDsP1mTPKfUIzd7a2gfedSx6K9hibg4XPAb52qwrDJKvngLQ/640?wx_fmt=png&from=appmsg "")  
  
我们可以在服务管理-新增自定义服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35R2whKQvYk17VQZlROZcp21iahLSTXd3tdqjvuull5whxlmDl74n9xicng/640?wx_fmt=png&from=appmsg "")  
  
包名称格式应为service-xxxx.zip（不支持特殊符号）  
  
通过官方给的模板进行修改  
```
https://hfish.net/service-demo.zip
```  
  
  
抓取0day?  
  
这里方便演示，我们随机打一梭子poc,看看效果  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35RelMMML4bqqa1dBkzuKBD7utzlPuOwIIjLTQWhutJ4425ib7QZNShvww/640?wx_fmt=png&from=appmsg "")  
  
再回到蜜罐系统  
  
找到攻击列表，即可看到数据包  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35R2yRMgiaPFvWMeeGtw272YFiarChoicyDWicicibhBK6Jo5UshwCOliaCRZBtw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35RNpydqYeqTrUPhbe0ic3ibFiaqvvj1SBGLDqIRhIzCJrcnibXM9vaicU53uQ/640?wx_fmt=png&from=appmsg "")  
  
如果你仅作本地测试，可以直接下载我打包好的VM版本，直接解压，然后在Vmware打开即可。  
  
启动服务  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vrVrkVbyq60lyAMur5gs35RhHqjuibDCmTMrzKzicfyKI2tXIFOYgvDtXfwXic5UmCPmsAaibSQ9bAmicg/640?wx_fmt=png&from=appmsg "")  
  
系统密码：hfish/hfish  
  
后台回复“蜜罐”获取  
  
