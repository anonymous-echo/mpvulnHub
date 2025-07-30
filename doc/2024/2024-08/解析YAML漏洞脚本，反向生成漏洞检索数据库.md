#  解析YAML漏洞脚本，反向生成漏洞检索数据库   
原创 chobits02  C4安全团队   2024-08-07 14:39  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/EXTCGqBpVJQGQG6ibYpsQ9hibUNQ9JogaBM4ETcLDdyuTknYvxjLbGCEQFKUEwbwpummEIZzqUcA3Mhaj6yJqd9Q/640?wx_fmt=gif&from=appmsg&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
  
  
**解析YAML******  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwFBsVylNUiavF7I8vIqHXWIIdrp7v7PIgm0ZTHPSL6e9ntdn5HgQVa7A/640?wx_fmt=png&from=appmsg "")  
  
最近有搭建漏洞检索数据库的想法，但是漏洞录入数据库是个难事。  
  
为了方便录入漏洞信息，这边就想直接用Nuclei的历史漏洞YAML脚本做成数据录进数据库中，作为数据方便全文搜索关键字。  
  
Nuclei的漏洞模板中主要读取如下几个字段：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwVc0XZtn2VFUic5R3XyP9z6jCcIqd7QTX9PYn0fXqwSn1hfqNaRibHpQA/640?wx_fmt=png&from=appmsg "")  
  
漏洞目标中会有漏洞资产检索语法，一般存在**fofa-query**或**shodan-query**字段里面  
  
然后POC解析的话可能还是有些难度的，要完全识别nuclei模板语法的话要花些时间，这里就简单解析下满足条件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwlKuqZVXyRuiaToGG7fUQzFM1VFKCnoNZSLH0hN1XhLUhYZqCsUprsiaw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwZrxELlrcDsnCBJLVO3RLibFaEicIhMpv7hdtF3b5MChBQFh0ETOtgEcw/640?wx_fmt=png&from=appmsg "")  
  
根据返回包匹配条件类型type，做以上几个不同的简单解析，然后匹配的语句还是按原文来存储。  
  
识别完成后的数据库大概是这样的：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwmJzTUq1YvqJwicKPstQFfz62KXcA5KichdAW3kHDMKT7PSxZtwI1wnTw/640?wx_fmt=png&from=appmsg "")  
  
漏洞ID是CVE的ID或是CNVD的ID，漏洞标题等其他信息按格式简单读取解析出来  
  
数据差不多就这样存好了，现在缺一个查询的交互页面。简单的方法是写一个Flask页面，通过SQL直接模糊查询漏洞信息。  
  
这里我图方便就拿老早之前的毕设改了下，因为POC等其他地方存在XSS的检测语句，渲染进前端页面会产生XSS弹窗，所以我就不对那些数据做换行符检测处理了：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwaWicyfUH7Oq7bI4qBnIMLBbqCEDpXjUFXFMdoDJoTibx5IF3uwLGtUug/640?wx_fmt=png&from=appmsg "")  
  
运行main.py，在5000端口启动网页后端  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwD1lfmamAuZN797gKGx95Xubpjz2tsCbbXvB2Qa1v9dc2dKqiclzfibmw/640?wx_fmt=png&from=appmsg "")  
  
访问之后通过网页模板渲染出漏洞信息，最上方带一个查询框  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwQMUdibNicVmK6HY35OtCbvp3iaiaqnRrAYyCGDWFvR4MficYACjCfAax8QQ/640?wx_fmt=png&from=appmsg "")  
  
测试查询CVE ID为CVE-2021-44228的漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwpPDeib2QJGXMcKquCezdaTT8mRFxHzCKUiawvPTcbZ92qujNiaoTnWNcQ/640?wx_fmt=png&from=appmsg "")  
  
还能对漏洞利用POC中的内容进行查询，查询带有/etc/passwd的漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwtaHDvdSMqM9TjCLeRPY76bEKPJkr0FzlS95ESNc9cwKkibQwnJ34PZw/640?wx_fmt=png&from=appmsg "")  
  
以上数据只包含了nuclei自带的2021年CVE漏洞信息，感兴趣的师傅可以用其他方法保存到数据库中再解析查询。  
  
漏洞信息文件我附在Freebuf的帮会中了，包含以上数据的数据库文件、Python Flask后端和前端查询页面，使用时先新建数据库然后修改python文件中的数据库连接信息即可。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EXTCGqBpVJRP8MES9kahNudmAKWrmEQwFY8lxypXmUe9SRs3ffNpJ8jUvLWo7JvgVBVpfMGDialIvfiaoBgPNwqw/640?wx_fmt=png&from=appmsg "")  
  
  
  
END  
  
  
关注Code4th安全团队  
  
了解更多安全相关内容~  
  
  
  
  
  
#   
  
  
  
  
  
