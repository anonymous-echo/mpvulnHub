#  GeoServer 综合漏洞扫描工具V1.2 发布！   
 信安404   2024-07-19 20:55  
  
**0x01 工具更新**  
  
增加了注入内存马的功能，修复了检测漏洞的判断方式，减少了误报率  
  
**0x02 使用方法**  
  
由于程序调用的是jMG-gui-obf-1.0.8，没有内置加载的payload，所以将java环境带了上去进行调用  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo75IXV3icbNQYdAa9VicWicLYJFbPZ62hh46nGk3Lic75Z2ORbvibJWsVv96LQ/640?wx_fmt=png&from=appmsg "")  
  
后续会  
内置一些Payload。  
  
生成Payload  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo75k2ezjF1zb2cMakpdrv9e3aFWyGTSiaXubrbEuTibJRs7HqeTe28U9pBQ/640?wx_fmt=png&from=appmsg "")  
  
****  
根据对方中间件来选择组件类型，jdk11的情况下，对方是Tomcat中间件，使用Listener组件，Jetty中间件，使用Filter组件，需要自定义类名，不能用工具随机生成的，java.lang.xxxx 即可。（这里感谢Windsss师傅的帮助!）****  
  
使用蚁剑连接的时候，需要添加上生成的header头，将结果复制到工具中即可，由于payload太长，复制过去是下面这样，属于正常。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo75f8JcHEVokZUsEQTIibBicr2UpxZoKMER3KnLVrgzoLm0BLNYaRCa4m0w/640?wx_fmt=png&from=appmsg "")  
  
**0x03 工具截图**  
  
****  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo75kJRQhHh7vKgkFCequA5APDHibZgmupWica0bM16ibqRUvicOMTa7IWtvxg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo756JFZF8GmucuJRAnyMcTbibrllGBLpR17bbbqYdBa1G5ebXQUicscDeibA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo75HsmNEtxZaPHuA2mbXqR8nL9ysiciaJWq85uLhqJRszOywsViaJOiavE7FQ/640?wx_fmt=png&from=appmsg "")  
  
**0x04 下载地址**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/OiaZBsiciaGvkTnxTESqtVrYMJJpSVwuo75Jrv28S5NLeDwMSmk9XaQjWTDSDrq0jtXFju2ykErpXpxwFX8N6zlIA/640?wx_fmt=png&from=appmsg "")  
  
  
