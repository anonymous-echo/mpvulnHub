#  漏洞管理工具 -- miscan（11月22日更新）   
mifine666  Web安全工具库   2024-11-21 16:00  
  
===================================  
免责声明请勿利用文章内的相关技术从事非法测试，由于传播、利用此文所提供的信息而造成的任何直接或者间接的后果及损失，均由使用者本人负责，作者不为此承担任何责任。工具来自网络，安全性自测，如有侵权请联系删除。个人微信：ivu123ivu  
0x01 工具介绍  
漏洞管理工具miscan，支持漏洞管理、漏洞扫描、发包测试功能。编写本工具的目的在于帮助安全人员更方便更高效的编写漏洞规则，以方便漏洞利用和漏洞验证。  
0x02 安装与使用### 一、漏洞管理  
  
  
可以对漏洞进行增删改查操作，默认是本地模式，漏洞保存后会以文件形式保存到当前路径下，右上角可以调整模式为协作模式，密码：暂不提供。协作模式下漏洞库查看和编辑权限需要key文件，暂不提供。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzleqBIjib1OnbqAhlQ8HZAHF2LuYhpoib2Hs3Q4cfLRkZFEvS67D8Hp2ZA/640?wx_fmt=png&from=appmsg "")  
### 二、漏洞扫描  
  
  
支持对一条或多条URL漏洞扫描，同时可以自定义一些信息，例如：自定义头、添加脏数据、启用代理、线程数、超时时间等。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlhymZDxenyQdub8icbWOKpZOwYj10yb2cC0TLrdmdzTVynRTQWhX3DjQ/640?wx_fmt=png&from=appmsg "")  
### 三、漏洞资产  
  
  
扫描过程中检测出漏洞的资产详情会出现在漏洞资产列表。包括直接展示完整数据包，可以根据数据包判断漏洞检测结果是否准确，同时还支持搜索和导出功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlFsiaFh3HH9OPGA5scju2YSFYo0c5JebpMotQSsjvLxia0jruKB2HprUQ/640?wx_fmt=png&from=appmsg "")  
### 四、发包测试  
  
  
直接粘贴完整数据包，类似burpsuite的Repeater功能  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlxb5lyHN2x8AmRgN6M3bk3VJ6nfGGJE2GXRfYyAQnFUQTHTe8a2je0A/640?wx_fmt=png&from=appmsg "")  
## 五、编写POC  
  
#### 编写POC时可能遇到的四种场景  
  
  
场景一：发送一个请求包，匹配返回的关键字。因为是正则匹配，所以匹配特殊字符需要进行转义。例如下面这个任意文件下载漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlEBtW4YIlkdeOGZ1rSgic7u9f7tfPaHbOrtS0soNGzXqbdrBP2gSgialQ/640?wx_fmt=png&from=appmsg "")  
  
场景二：发送多个请求包，后面的请求需要使用到前一个响应包中的信息，例如下面这个蓝凌getLoginSessionId任意用户登录漏洞。  
  
1、获取sessionId  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlHGPN6aHHx5VNVa5uSUnwFibftTGWzgohBvAz2WmPDSRqOz3v9MotEPw/640?wx_fmt=png&from=appmsg "")  
  
2、将sessionid添加到第二次的请求。然后获取返回cookie  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzl7HvhX2cnyVdZyAHC37Tent0ESicXXxjoVnXJricD6wjZzzcxxwl8jOTw/640?wx_fmt=png&from=appmsg "")  
  
3、将cookie替换访问  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlnOfe6siaicTxLH5d1D1WJVVWp1NO6F9vHypufsslkcGyOB4ic0tIWmZuA/640?wx_fmt=png&from=appmsg "")  
  
场景三：需要使用dnslog验证漏洞存在。例如下面这个XXE漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzljTndeTiblL9icFKdC11ia84dxWQ9saJC0jxmYGnzEnic9kkP40SX67qXuw/640?wx_fmt=png&from=appmsg "")  
  
场景四：发送的请求包中存在字节流的数据。例如下面这个帆软反序列化漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzleqBIjib1OnbqAhlQ8HZAHF2LuYhpoib2Hs3Q4cfLRkZFEvS67D8Hp2ZA/640?wx_fmt=png&from=appmsg "")  
  
**0x03 项目链接下载**  
  
1、点击阅读原文，从原项目地址下载。  
  
2、网盘下载链接：  
https://pan.quark.cn/s/96cfc3e07204  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/8H1dCzib3UibsyShLiaHRtxHje3zedPYhzlcWu1JJZnncMgpnGj0r5OW1ACDQwrHXIp3Xq1JRLI0qdQ2gn843peOg/640?wx_fmt=png&from=appmsg "")  
  
  
  
**·****今 日 推 荐**  
**·**  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/8H1dCzib3Uibu7uX2oYjbbibndft14nzUMIoRia7UqCAgMXSZAu1iaBDWSWLLuFnyibwfOiaCLO7YXaC6qib8icgHXwoe3Q/640?wx_fmt=jpeg "")  
  
