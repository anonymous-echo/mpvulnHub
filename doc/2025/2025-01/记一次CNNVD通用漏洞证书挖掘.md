#  记一次CNNVD通用漏洞证书挖掘   
 craxpro安全实验室   2025-01-19 09:54  
  
## 一、什么是CNNVD  
  
中国国家信息安全漏洞库（CNNVD，China National Vulnerability Database of Information Security），于2009年10月18日正式成立，是中国信息安全测评中心（中文简称：国测，英文简称：CNITSEC，China Information Technology Security Evaluation Center）为切实履行 漏洞分析 和 风险评估 的职能，负责建设运维的国家信息安全漏洞库，面向国家、行业和公众提供灵活多样的信息安全数据服务，为我国信息安全保障提供基础服务。CNNVD在国家专项经费支持下，负责建设运维的国家级信息安全漏洞数据管理平台，旨在为我国信息安全保障提供服务。CNNVD官网：http://www.cnnvd.org.cn/  
## 二、CNNVD原创漏洞证书获取条件  
#### 通用型：  
  
漏洞证书获取方式，通用型发证要求为高危漏洞或者超危，中危漏洞是不发证的。需要给出漏洞证明案例至少十起（例如：一个建站平台下的十个网站都存在  
SQL注入  
，你就需要提供这十个网站的URL，具体漏洞复现方式需要在你上传的doc文件中至少详细复现3~5个，剩下的只需要将URL附上即可。还有漏洞指纹也记得附在报告中。  
#### 漏洞详情要求填写:  
  
1、基础信息  
  
漏洞利用的完整过程，相关URL、截图、代码以及POC。若不符合规则，漏洞可能会审核不通过。  
  
2、IoT漏洞还需提供：  
  
（1）漏洞触发对应的二进制位置  
  
（2）目标配置情况  
  
（3）漏洞研究环境：若为真实硬件设备，请提供购买相关链接；若为模拟仿真，需描述环境的搭建以及调试方法等。  
  
3、如在漏洞利用过程中使用到组件，则需提供下载链接，或压缩后在附件处上传  
  
4、对较复杂漏洞，可提供攻击过程的视频/图片，图片可在细节中直接上传；视频请提供链接或压缩后在附件处上传  
  
5、PoC或Exp语言不限。要求思路清晰、可阅读性高、易于复现提供的信息越全面，给出的奖励越高  
  
三、CNNVD原创漏洞证书挖掘  
  
CNNVD漏洞挖掘和CNVD有点像，基本上通用系统都会收录  
  
个人觉得比较好挖的如下：  
  
资产测绘语法：xx打印机设备、xx商城、注册、后台登录等等，提取相关系统指纹,例如路由器,监控等系统，规则列表等等。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrNZMG0Eu2SdiavRuvYvYSWcDZQ7ibR1snttpdWqgIzUX12ToRia5bicBEI6g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrN9qGia956MrAxtJpKL1icwCoDtpuHelibSvVDB7pY49GuPchjYSkcUqNibQ/640?wx_fmt=png&from=appmsg "")  
  
本次挖掘为设备弱口令进入后台加上漏洞利用，造成远程命令执行漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrN8LNzZvwYDqRkhk0uchmWJ34qnbfVYnPuMDZUNMKTy90LOKWfxgIjjQ/640?wx_fmt=png&from=appmsg "")  
  
通过弱口令成功登录：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrN23oYicypVkIdtcW27SJwMcoKJey4mxHExy5gOSmp05yPfRwDIQ4jcjw/640?wx_fmt=png&from=appmsg "")  
  
在网络诊断进行测试ping功能发现并不存在漏洞，发现存在  
Tracert检测功  
  
能，通过payload成功执行漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrN61rcopXmAbicIUdnDy2YMnnqaqzkJTG70qmaicl2JeUKjNibzuic5bS0cw/640?wx_fmt=png&from=appmsg "")  
  
payload为：  
127.0.0.1;cat /etc/passwd 师傅们如以后遇见相关功能点可以进行尝试  
  
接下来就是写其余案例 写报告提交平台等待审核  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrNo0YMMkDiciaPLNpG5mkcG9LZwy0SJsPxM2opibsOQI9GwH6rgFuX9HyRQ/640?wx_fmt=png&from=appmsg "")  
  
通过漫长的审核时间，最后也是成功下发了证书  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrNgnW36FMISygXk8Y3RVUwM8EdHUYGqvuDtGac8p9Ok9BLDKamCc6iaPQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/FxYwHqCMGPF2XojbTpickMwDveYl9IqrN4epLJWXicFZxMSI3sIN0qxKI5K6sWurpUcrNnhaecNLiaQXVEZovibgDg/640?wx_fmt=png&from=appmsg "")  
  
  
  
