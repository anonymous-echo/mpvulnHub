#  DeepSeek黑客工具箱！代码审计POC 漏洞报告输出 支持第三方API～拒绝卡顿！！   
 哈拉少安全小队   2025-02-13 01:06  
  
前言  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v8yrCQN46lGibnfXztFesYNPLQKoYfVFK8VW5TOEhXbAHKkMkLnv7iazSic32VwJqfhUss0jcGeWJY1RlqCS3xCow/640?wx_fmt=png "")  
  
  
  
文章来源为原公众号，文内ai邀请链接更改了0.0  
  
硅基流动为邀请好友注册两人都可以获得  
14余额  
  
```
注册地址：
https://cloud.siliconflow.cn/i/aiivEvzy
```  
  
  
  
更新内容：  
1. 代码审计直接出POC  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpVFTI5EWlqc6EK0dicTqPOI872gHR3ChdSd9Aia5yexr9E4gYIgBta4NjbRSTVptiakgTAO6gF6YKeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpVFTI5EWlqc6EK0dicTqPOI2orUvriadpwHd6TFOulGic4t88SGn3UrxPSJkY6o9NHPUFfaopN4mgKQ/640?wx_fmt=png&from=appmsg "")  
  
2.报告输出  
  
为了解决每次写渗透测试报告，一些漏洞描述都要现场百度，倒不如直接把功能加进去。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpVFTI5EWlqc6EK0dicTqPOIAoGhhGkL2icXgEK45XjXTz4icMn90zIK0sDlofPH8FQLjRe55LianDfUQ/640?wx_fmt=png&from=appmsg "")  
  
3.第三方API支持  
  
【省流：第三方API解决官方API卡顿问题】  
  
DeepSeek的api还在卡，对于本地性能不够的师傅，已经用不了了，所以稍微改了一下，支持了  
第三方的API，这样就可以用其他网站的api了，如果你是第一次看文章，请先点开公众号看看往期两篇文章。  
  
这里我以  
硅基流动为例子（主要是送钱，邀请好友注册两人都可以获得  
14余额，理论上左脚踩右脚直接升天。）  
```
注册地址：
https://cloud.siliconflow.cn/i/aiivEvzy
```  
  
安装完DeepSeekTools之后，你需要配置config.py文件  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpVFTI5EWlqc6EK0dicTqPOIiapJZYt4TCkbRl5xfZdbHDcpcbzQ71lruXkwcnicrkxjr5ybMTDrGpaQ/640?wx_fmt=png&from=appmsg "")  
  
如果你要用官方的api，那么就填官方api，如果用第三方的api，就用第三方的api  
  
如果你用官方的模型，就填官方的模型，如果用第三方的api就用第三方的模型  
  
如果你用官方的api就用官方的key，如果用第三方的api就用第三方的key  
  
【疑似水文章】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/H7ec9FOh7vpVFTI5EWlqc6EK0dicTqPOIp2WpZU5TBphoq3rolhzJMdeuiasUicnUibxjuLmersNyufITia27BxAtpw/640?wx_fmt=png&from=appmsg "")  
  
config文件配置  
  
API_TYPE，必须二选一，deepseek或者ollama  
  
然后在下面继续配置  
  
实在不会的，详情请看bilibili  
  
部署：https://www.bilibili.com/video/BV1yxNAenEwj/  
  
config配置：https://www.bilibili.com/video/BV1skNoeuEZu/  
  
部署教程  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v8yrCQN46lGibnfXztFesYNPLQKoYfVFK8VW5TOEhXbAHKkMkLnv7iazSic32VwJqfhUss0jcGeWJY1RlqCS3xCow/640?wx_fmt=png "")  
  
  
```
https://github.com/ChinaRan0/DeepSeekSelfTool
然后
cd DeepSeekSelfTool
pip install -r requirements.txt
配置config.py
python DeepSeekSelfTool.py
python ollamaMain.py
```  
  
  
欢迎大家留言区讨论新功能。  
  
  
  
  
  
  
  
  
  
  
