#  【工具分享】一个综合性比较强的java漏洞集合工具（集成多种实用小工具）   
pureqh  篝火信安   2025-01-17 02:00  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLAhpBvY92480zuIMjfdVeFC4MyricBxX3FlCYKxAzVaeicXqC3iaT7Makw/640?wx_fmt=png&from=appmsg "")  
  
简介  
  
该工具参考多个开源项目，取长补短，捏合成的一个综合性比较强的Java漏洞利用工具集，该工具集成常见Java漏洞检测以及多种实用小工具；运行jar即可使用，采用图形化界面，简明易操作。  
  
该工具有效解决了攻防的时候，需要打开切换多个jar包，操作不方便的问题。  
  
特点  
- 工具中包含Struts2、Fastjson、Weblogic（xml）、Shiro、Log4j、Jboss、SpringCloud等漏洞检测利用模块，及免杀Webshell生成模块 Bypass、以及一些小工具模块等。  
  
- 本项目的部分payload进行了一些混淆，具备一定过Waf能力，作者有空会继续更新。  
  
- 最新版本已支持MAC和Windows。  
  
使用  
  
1、加载之后界面如下，最上一行切换不同的功能模块，包含常见漏洞Struct2，FastJson，WebLogin等，同时包含Bypass，小工具，以及重要系统利用模块。  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLtqRE9lxiaTDY95pOZSnMd2hnTRo7U6iabZ4WzeMLcGRKOI9wuROuj6fQ/640?wx_fmt=jpeg "")  
  
2、漏洞利用模块的操作比较简单，配置好必要项后，点击“检测漏洞”开启扫描。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLUndSLGbu2bP00DyUATeAnQYZImE9jx9gHLcnd8Z3VVdosVI4CcEWRQ/640?wx_fmt=png&from=appmsg "")  
  
3、DNSlog有两种配置方式，一种是在当前目录创建config.txt手工配置，另一种是在需要用到dnslog的漏洞模块中直接填写配置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLF7YjlLPG3boPN1ibibGvB92oVeUjtwFDWL9q2y1C75uEjTs8ib4sIozng/640?wx_fmt=png&from=appmsg "")  
  
4、Bypass模块可以生成不同工具、不同语言的免杀Webshell，以及Windows和linux的混淆后的命令执行语句。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLVd7QGkt3eRZdRHSI82uR5bUM6tHItU6az6ORA8ws4tPfzM3R9ND1YA/640?wx_fmt=png&from=appmsg "")  
  
5、Tool模块包含字典生成、目录扫描、Tomcat爆破等等功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLJE7f4gPEYYlgSWDUib2fJhEwSYrTHFUibehgld6hochdlsicJOfiapTwUw/640?wx_fmt=png&from=appmsg "")  
  
6、RedTeam模块目前集成了Confluence、Gitlab系统的漏洞利用检测，以及Jenkins masterkey解密的功能。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CQf7uHzmVb08MNLaKgzkPHG0ro6TqZMLTnUAygQ4OfGYvQgVEkJf5FuIzRZsQd69jMnBicRTwZSZDYvHJsLicgkw/640?wx_fmt=png&from=appmsg "")  
  
## 免责声明  
  
  
本工具旨在提供安全评估和漏洞扫描等相关服务，但使用本工具时请注意以下事项：  
- 仅供学习和授权的测试，任何人不得用来做违法犯罪活动，出现问题均与本人无关。  
  
- 本工具的使用者应对其使用产生的结果和后果负全部责任。本工具仅作为辅助工具提供，不对使用者所进行的操作和决策承担责任。  
  
- 本工具尽力提供准确、及时的信息和评估，但无法保证其完全无误。使用者应自行判断和验证本工具提供的信息，并对使用本工具所产生的结果进行独立评估。  
  
请在使用本工具之前仔细阅读并理解上述免责声明。使用本工具即表示您同意遵守上述条款，并自行承担相应责任。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CQf7uHzmVb3icxXWABkpMvXDJ1aDF6RgkCFLMvzDgLEx7jjY4A1n7yTEc2AZmg5CFFoeHJLb3AiblNHRLVFBqlfw/640?wx_fmt=gif&from=appmsg "")  
  
```
```  
  
  
