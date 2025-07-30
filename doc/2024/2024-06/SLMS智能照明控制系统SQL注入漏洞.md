#  SLMS智能照明控制系统SQL注入漏洞   
NT-V  NightmareV   2024-06-13 23:26  
  
声明：  
  
请勿使用本文档提供的相关  
操作及工具  
开展任何违法犯罪活动  
。  
本技术类文档与工具仅支持学习安全技术使用，他用造成严重后果，请自行负责！！！  
  
一、  
漏洞名称  
  
SLMS智能照明控制系统SQL注入漏洞  
  
二、  
产品介绍  
  
智能照明控制系统是利用先进电磁  
调压  
及电子感应技术，改善  
照明电路  
中不平衡负荷所带来的额外功耗，提高功率因数，降低灯具和线路的  
工作温度  
，达到优化供电目的照明控制系统。  
  
三、  
漏洞概述  
  
SLMS智能照明控制系统txtUsername参数处存在SQL注入漏洞，未经身份认证的攻击者可以通过该漏洞获取数据库敏感信息。  
  
四、  
FOFA搜索语法  
  
fid="2C3BnXz4nRk70n6wMhfrkw=="  
  
五、漏洞验证截图  
  
访问界面如下图所示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHa4Qv34cSS0l305d8HYLFc7r43sVDtj5CFmlYWxRJc29DkN27ic3rZU9g/640?wx_fmt=png&from=appmsg "")  
  
用户名和密码处任意输入，此处用户名输入  
1，密码输入123。点击登录，查看登录提示。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHaNkialq6tCSMicksfPTxUiavZlsibxwbnsGQqA7dcicVhTVZ4BpCUrsiaYNvg/640?wx_fmt=png&from=appmsg "")  
  
点击登录后，系统提示  
“用户名和密码错误”。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHagDykOV4SDmz2em9R8iaubHzpliaXyLNp19lwRvB2ibb5OtQ2zEEI4GsnQ/640?wx_fmt=png&from=appmsg "")  
  
用户名处输入单引号，点击登录，系统无任何动作提示。尝试进行闭合处理，发现当输入如下语句  
:1  
’  
and  
’  
1  
’  
=  
’  
1，密码123保持不变，此时再点击登录，页面又有了系统错误提示回显。如下图所示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHaBUic25WLHNiaeuicPKUGYCSvenfqpDA81d7Jb8OQY5MvgY0xsNXDLbK5g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHaAm8a5pt5eFFlqf78o8fIyOZ0IW0acKAXW7kmphribJMGxke2tjBMQJA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHa51dbf9DLPTXS5tDTXDFy2WJ2J4icaZyGRiaTv8sbZiarDJH4sTiaVaVVqw/640?wx_fmt=png&from=appmsg "")  
  
漏洞验证截图：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHaNTN8xn66SMXOTC656LpR1mqgA9tC8icvEibFPY0uP2nSOPBvPxicynuuQ/640?wx_fmt=png&from=appmsg "")  
  
至此，说明  
SQL注入漏洞存在。  
  
漏洞  
POC在下方知识星球内，扫描二维码，即可查看POC内容  
。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/cysMYfusftlkZRxnMLKpNulVTEic1WPHalRzQvl0T1gSVq1v9JZJYhY5XOvhWwj5UP2d26TDXorUpuoQtWatySw/640?wx_fmt=png&from=appmsg "")  
  
