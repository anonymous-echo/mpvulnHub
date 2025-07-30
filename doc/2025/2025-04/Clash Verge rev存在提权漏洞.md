#  Clash Verge rev存在提权漏洞   
JunYi  毅心安全   2025-04-26 09:35  
  
Clash Verge rev存在提权漏洞，在Mac、Linux和Windows都能进行提权，Mac和Linux下能提权到root，Windows下可以提权到SYSTEM。此漏洞包括最新发行的版本2.2.4-alpha，目前正在积极与作者取得联系。如果确实需要使用这类软件，请禁用他的守护进程。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/kzkqdAEDfXfnN74Q8zcIkckzZZfbllunP7KDeibXoDUgiaXqvkaWHxQyHfXDpKbWOibGUrQaH4kiaFE01icBAbliciaLA/640?wx_fmt=png&from=appmsg "")  
  
建议措施：  
  
Windows下打开服务管理，禁用Clash Verge服务；Linux下请通过systemctl停止并禁用clash-verge-service服务;Mac下请在系统设置中关闭名为"won fen"的允许在后台权限自启动项。  
  
