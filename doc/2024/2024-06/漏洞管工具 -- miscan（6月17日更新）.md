#  漏洞管工具 -- miscan（6月17日更新）   
mifine666  Web安全工具库   2024-06-20 22:42  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
漏洞管理工具，支持漏洞管理、漏洞扫描、发包测试功能。编写本工具的目的在于帮助安全人员更方便更高效的编写漏洞规则，以方便漏洞利用和漏洞验证。  
0x02 安装与使用  
一、漏洞管理  
  
可以对漏洞进行增删改查操作，默认是本地模式，漏洞保存后会以文件形式保存到当前路径下，右上角可以调整模式为协作模式，密码：暂不提供。协作模式下漏洞库查看和编辑权限需要key文件，暂不提供。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibu8ZJfrKSRpa4UpiaAVlM5Pn0kaOh9RdnyjNJkBI8uMicqfpicia6Cwf3d14n4khhHLlWicdYtIckh6otA/640?wx_fmt=png&from=appmsg "")  
  
  
二、漏洞扫描  
  
支持对一条或多条URL漏洞扫描，同时可以自定义一些信息，例如：自定义头、添加脏数据、启用代理、线程数、超时时间等。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibu8ZJfrKSRpa4UpiaAVlM5PnZO0x0BicXRauSsicI3H4aZicSZfgicIAA14U0EjRaVbUXicfibmIkViczyGPg/640?wx_fmt=png&from=appmsg "")  
  
三、漏洞资产  
  
扫描过程中检测出漏洞的资产详情会出现在漏洞资产列表。包括直接展示完整数据包，可以根据数据包判断漏洞检测结果是否准确。（如果数据包点开关不掉可以点击旁边的格子或者点上面的检测结果）  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibu8ZJfrKSRpa4UpiaAVlM5Pn9griabTTibvibfib92gbGMicRf694YSkrSg6dvhTlMPBtIfSOoibiaibiadHLug/640?wx_fmt=png&from=appmsg "")  
  
  
四、发包测试  
  
直接粘贴完整数据包，类似burpsuite的Repeater功能  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibu8ZJfrKSRpa4UpiaAVlM5PnibJs2NR1hqFHNGE4xhf92V6Hkt5UATn6M8ofbjCp4icnsFG4reXd3SWA/640?wx_fmt=png&from=appmsg "")  
  
五、编写POC  
  
发送一个请求包，匹配返回的关键字。例如下面这个任意文件下载漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3Uibu8ZJfrKSRpa4UpiaAVlM5PnuibZ6nsuWFf8BWVmM701mWiaThogcXZFnXVZI97KxefldqiahQAyibWJaA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：https://pan.quark.cn/s/02a63c9450a3  
  
  
  
**·****今 日 推 荐**  
**·**  
  
  
教程合集下载：  
  
https://docs.qq.com/sheet/DUHNQdlRUVUp5Vll2?tab=d500sn  
  
