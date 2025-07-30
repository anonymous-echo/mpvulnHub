#  0day！POC管理和漏洞扫描小工具   
点击关注👉  马哥网络安全   2024-04-20 17:02  
  
**项目简介**  
  
本工具是采用javafx编写，使用sqllite进行poc储存的poc管理和漏洞扫描集成化工具。主要功能是poc管理，并且采用多线程进行漏洞扫描。  
  
**使用场景：**  
  
这个工具可以看作一个简单的漏洞扫描框架，需要扫描什么漏洞，就可以自己进行调试添加；调试好的poc可以导出分享给团队成员，也可以导入他人调试好的poc。  
  
它可以是oa漏洞扫描工具，也可以是框架漏洞扫描工具，也可以是默认弱口令扫描工具，这完全取决于添加的poc。  
  
**功能模块**  
  
**POC管理**  
  
显示当前poc列表，右键poc可以删除、编辑，也可以导出分享poc。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbKibFNZau8zibx99wIHf02XqM0FvHtibr7s0ZqGQbtyVHxOaNxliclf1ZJw/640?wx_fmt=png&from=appmsg "")  
### 增加POC  
  
第一页填写poc介绍信息；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbaQDILmrdJJibhYKBNABJmC4Idee9Hmn68m2rnxKQFZjticAias2IKcTMQ/640?wx_fmt=png&from=appmsg "")  
  
第二页填写漏洞扫描时所使用的参数，注意选择合适的回显验证方式，目前提供5种方式，若选择两种组合验证，还需选择两者之间的组合关系；若为文件上传漏洞，可以勾选shell验证来对上传后的文件进行验证；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbURSZzrYpkHbIfjC2ibrBdIrmBtHzI4yn8BibM4tba0O4VJTWwpeibQjNg/640?wx_fmt=png&from=appmsg "")  
### 漏洞扫描  
  
全部扫描即扫描当前所有漏洞，资产数量过多时需要以文件形式导入，否则会乱码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbnMneZk29v3KRPuL6axHEnibRe9a5wvBmYKE6ZozI2l1DnLfI4pLL1Qg/640?wx_fmt=png&from=appmsg "")  
  
单项扫描即扫描某个漏洞；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbAcKOdI8yhwDZloJ0KmWCn11WiciciaLPYj2rQz5ldjyaDlMHKtCBpEwiag/640?wx_fmt=png&from=appmsg "")  
  
cms扫描即扫描某个cms的漏洞，这取决于添加poc时填入的cms名称；  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbAdQsWChB2fPGT6LGm1LkEzFiba83YmQ3X08Gf1kyfRtRHPFiaQMBmt0Q/640?wx_fmt=png&from=appmsg "")  
  
自定义扫描即自由选择本次扫描需要的漏洞进行扫描，双击添加进待扫描漏洞列表。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbvOSUMtWvz7MbrbhibJM0ydA9IicaL3TqibgBTsBVBv4HibMcTpHLEHxl2Q/640?wx_fmt=png&from=appmsg "")  
### 调用脚本  
  
某些不方便添加poc参数的漏洞，可通过脚本形式进行调用，其实就是一个python脚本收集的功能，方便对脚本进行收藏管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbzrofahzKauH1H6h3YTNETBg2PZRT4ldQoxs7OiabClViaLUMa1dGW2rQ/640?wx_fmt=png&from=appmsg "")  
### web识别  
  
为了快速发现web端口，对端口扫描的结果进行http，https的识别。结果可保存到文件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbHokgDXNXhg4qHzBKbUBoK4icSMW9yibicmPlupux66nh8TicCMGHaTRwzg/640?wx_fmt=png&from=appmsg "")  
### Log记录  
  
每次扫描都会在根目录下log文件夹内的log文件内写入记录；   
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9JPpNb7icHgHt2gWZCBS0zqxEFbUaJttbxRYBf1NhHibZTdeWkQ0XjxaibicVOFco8Wy6CFLlxv2mKq6fATWXeuWVA/640?wx_fmt=png&from=appmsg "")  
  
**下载地址**  
  
https://github.com/Janhsu/oday  
  
文章转自菜鸟学信安，侵删  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAnXye3iaGgpeOLjDLHQXnqfEciapv51iaibicic7HsibhdoQ9PwYeNTliaVzGR9ehiavELSYyInvy4LemqwAVg/640?wx_fmt=png&from=appmsg "")  
  
  
