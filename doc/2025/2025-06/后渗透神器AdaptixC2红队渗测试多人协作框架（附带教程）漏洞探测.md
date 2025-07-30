#  后渗透神器AdaptixC2红队渗测试多人协作框架（附带教程）|漏洞探测   
RalfHacker  渗透安全HackTwo   2025-06-03 16:15  
  
0x01 工具介绍  
  
  
Adaptix 是一个专为渗透测试人员打造的可扩展后利用和对抗模拟框架。Adaptix 服务器采用 Golang 编写，以提供灵活的操作方式。GUI 客户端采用 C++ QT 编写，可在 Linux、Windows 和 MacOS 操作系统上使用  
！  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEQciboByqNUZs54x620yiblxJxy6tBky5JNzNAh7xtvBxjdN6LXxZkk4w/640?wx_fmt=png&from=appmsg "")  
  
  
**注意：**  
现在只对常读和星标的公众号才展示大图推送，建议大家把  
**渗透安全HackTwo**  
"**设为****星标⭐️**  
"  
**否****则可能就看不到了啦！**  
  
**下载地址在末尾#渗透安全HackTwo**  
  
0x02   
功能简介  
  
  
用户界面  
：  
  
AdaptixClient 用户界面分为两部分。界面顶部显示代理及其任务。界面底部显示与您交互的每个功能的选项卡。您可以点击这两部分之间的区域并根据需要调整其大小。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEnJG1dy5ETa1TNn16XYEmVtnjiaZxcYnpJQIoU2ajtbj4Ncakbick8HeQ/640?wx_fmt=jpeg&from=appmsg "")  
## 主菜单1. 项目  
  
项目管理菜单。“关闭项目”将断开当前项目与 C2 服务器的连接并关闭项目区域。“新建项目”将打开一个新的登录窗口。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEmqVYiapGDBHzxQHnTGQ5VgOxicIU0gwAXeej8CmjoqKXPhJdZN6ssibUw/640?wx_fmt=png&from=appmsg "")  
  
授权后，客户端底部面板将出现一个新的项目选项卡。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEicB5FRIjCBmaQtHlmOzJmfcnaicksfQOGDA0BVicT4uc0t3hu7ibXWOXUA/640?wx_fmt=png&from=appmsg "")  
### 2. 扩展器  
  
打开客户端的扩展窗口。有关扩展的更多信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEBIMuLOKicSoVlbN5AlQkHUvA4IlWedMSxLVzW8RibSibribC3Ao2cqr2mg/640?wx_fmt=png&from=appmsg "")  
  
3. 设置  
  
打开客户端设置窗口。  
  
主要设置  
  
会话表  
  
任务表  
  
客户端基本设置：主题、字体、客服控制台中的时间显示模式。  
  
工具栏  
  
AdaptixClient 顶部的工具栏可快速访问常见的 Adaptix 功能。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEDGn74keQmlbrzTWrcu1lWr7nMwvO56ediaXMWuNqWCjnM3p4UCdNsaw/640?wx_fmt=png&from=appmsg "")  
  
会话表  
  
会话表显示哪些代理已向 AdaptixServer 注册。  
  
用户字段显示使用的访问令牌。会话表包含以下坐席标记：已终止、非活动、解除链接、无响应。操作员可以将坐席标记为非活动或活动，还可以选择条目或整行的颜色。将坐席标记为无响应的时间在会话表设置中设置。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEol8Ejspa3Dlc0YLK35Lo0PicA2xVW1y4s3nvsMvMhglpgArPo1x1mGg/640?wx_fmt=png&from=appmsg "")  
  
将鼠标悬停在“睡眠”字段上将显示当前的“终止日期”和“工作时间”设置（如果已设置）。在非工作时间，代理将被标记为“无工作时间”。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeE19aC3kbj8HFy1vmugaBxjTaFV7ADS1JoA5BCIQia03UasGlXl2EMyTg/640?wx_fmt=png&from=appmsg "")  
  
双击代理行将打开代理控制台。代理可以通过会话表的上下文菜单进行管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEIEtZiaLeOKjGjTFaFzO8CouCNTHwQPU5OHfEFeic0hlCibKIV06ftXMicg/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEJ4YvRibIOoPGxf8jjeSI6xfE4u7jtJYYNKOp3zl4S7zMxK7jnVcqhKg/640?wx_fmt=png&from=appmsg "")  
  
通过会话表菜单的“从服务器中删除”菜单项从服务器中删除代理时，现在需要确认该操作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeERHq5ovw7hofJzad9YqibdsBE565iaPtcoutIsaRoLibKEmU3pia84JCWmQ/640?wx_fmt=png&from=appmsg "")  
  
Ctrl+F要激活搜索栏，您必须使用会话表中的组合键。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEz7vauq9M6rMynOWp8GUHXdbVb4icsUgiajPoaiaGgjtbllTUXrKKNOuVA/640?wx_fmt=png&from=appmsg "")  
### 会话图  
  
如果没有可视化的呈现，追踪和理解 4 或 5 个关联代理的链条将会非常困难。这时，会话图就派上用场了。  
  
会话图以自然的方式显示代理链。每个代理会话都有一个计算机图标，指示其操作系统和权限级别。如果图标为红色，则表示代理正在特权进程中运行。灰色图标表示代理当前已检查（可能处于非活动状态）。  
  
防火墙图标表示代理的出口点。每行包含负责处理代理数据的监听器的名称。**绿色虚线**表示使用“外部”监听器。  
  
连接一个代理会话和另一个代理会话的**黄色实线**表示两个代理（“内部”监听器）之间的链接。这些线包含监听器名称和链接名称（例如p1）。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEpzjhERs0eAeiaEhRDJNibDicibI7uldmQn8pZrypxgIjecZKqKl7ZjMb9g/640?wx_fmt=png&from=appmsg "")  
  
代理通过会话表的上下文菜单进行管理。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEjOdoG5oFvibE9b9qycPGj2XB0u20ePHVpKphoVUbmOjIvGD0ialgS1Jw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeETlkQSTtCPSbEKKyUkFRFAZdELtuFLq71T6Thia21BGF8MFpIgAFu70A/640?wx_fmt=png&from=appmsg "")  
### 座席控制台  
  
代理控制台如下所示。每个命令包含操作员名称、任务 ID 和代理类型。控制台会保存输入命令的历史记录，并自动完成命令。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEwjfia0f4VdDQbNqmcZogKQ6ib6EfZxZRXaRSdpvErXDxiatticRJ4nEC0g/640?wx_fmt=png&from=appmsg "")  
  
要清除控制台，请使用Ctrl+L输入字段中的组合键。  
  
您可以在应用程序设置中禁用控制台中的时间显示。  
## 特征  
  
```
用于多人游戏支持的服务器/客户端架构
跨平台 GUI 客户端
完全加密的通信
监听器和代理作为插件（扩展器）
用于添加新工具的客户端扩展性
任务和作业存储
文件和进程浏览器
Socks4 / Socks5 / Socks5 Auth 支持
本地和反向端口转发支持
转炉支持
链接代理和会话图
代理健康检查器
代理 KillDate 和 WorkingTime 控件
Windows/Linux/MacOs 代理支持
远程终端
```  
  
  
0x03 更新说明  
  
```
增加了 Windows 支持
已实现对多线程并行 SOCKS5 隧道的支持。
为下载存储添加了取消功能
在会话表和图表的上下文菜单中添加了退出选项
FilesBrowser现在支持文件下载和上传
使固定：
现在可以识别符号链接，并且FilesBrowser可以正确将它们显示为文件或目录
由于块大小仅为 10 字节，文件下载速度之前非常慢。现在默认下载块大小为 1 MB
```  
  
  
0x04 使用介绍  
  
📦安装  
  
AdaptixС2 的源代码可以在夸克云盘上找到。该main分支是稳定版本，不包含最新的更改。  
```
下载AdaptixC2.zip解压
cd AdaptixC2
```  
  
预安装  
  
要构建服务器和扩展器，您需要安装其他依赖项。请注意，编译和运行 AdaptixServer 需要golang 1.23版本。  
  
Linux Debain系统命令  
```
sudo apt install golang-1.23 mingw-w64 make
sudo ln -s /usr/lib/go-1.23/bin/go /usr/local/bin/go
```  
  
Linux Arch系统命令  
```
 sudo pacman -S --needed go mingw-w64 make
```  
  
要构建客户端，您需要安装额外的依赖项  
  
Linux Debain系统命令  
```
sudo apt install make cmake libssl-dev qt6-base-dev qt6-websockets-dev
```  
  
Linux Arch系统命令  
```
sudo pacman -S --needed make cmake openssl qt6-base qt6-websockets
```  
  
MacOS系统命令  
  
```
# https://brew.sh/
brew install make cmake openssl qt@6
```  
  
Windows系统命令  
```
需要https://doc.qt.io/qt-6/qt-online-installation.html
```  
## 服务器  
  
**AdaptixServer 和 Extenders（goplugins）必须使用相同版本的 golang**包构建。  
```
make server
make extenders
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEfYAL1hLowlVfwFPzNt9tlo7aXsHEPUWfmDZficuT4ia9oVmaqaOicRAyg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEYUMr1X1qcVicNcuB2MxByHc7K73v3wIBd93sUH3fZpMj9pDcfZ7PoHg/640?wx_fmt=jpeg&from=appmsg "")  
  
所有编译的文件都将位于 dist 目录中。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEZre0dcrRicl8J6TT4YFVfedn6lX7IQYtj4DbTWQSziaDJobTibQ4vibrpw/640?wx_fmt=jpeg&from=appmsg "")  
## 客户Linux / MacOS  
  
AdaptixClient 是从 cmake 配置编译而来的。  
```
make client
```  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEYwkjttxxIomcoUGJjenT8C11zALE5iaL5Kr64NcCVnrChibvCJZ29EQA/640?wx_fmt=jpeg&from=appmsg "")  
  
AdaptixClient 文件将位于 dist 目录中。  
  
Windows  
  
从官方网站下载QT在线安装程序：  
```
https://doc.qt.io/qt-6/qt-online-installation.html
```  
  
启动安装程序后，在包下载页面上，选中如下面的屏幕截图所示的框。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeECqsj8kicRPVdlQrx0kFhXx7cVuiaudevcH07VEumL1lkvu5mgR9GibyAg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEXoeUfTPyAzSePic6sbKFTOWLI3dQDq1db2PQ6HBAGDoealKtzuO2ocw/640?wx_fmt=jpeg&from=appmsg "")  
  
在 QT Creator 中，选择**“打开项目”**，然后选择**CMakeLists.txt**文件。下载项目后，将构建类型更改为**“发布”**，然后构建项目。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEyZFcPc9jibQsB36dMsD6ZiaX8oVwlfycQ4gZP0tIcEBiaZSyeDKHVLUXg/640?wx_fmt=jpeg&from=appmsg "")  
  
为客户端创建一个目录，所有依赖项都将被复制到该目录。将 AdapticClient.exe 可执行文件移动到此目录，打开 cmd.exe 并运行**windeployqt.exe。**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/RjOvISzUFq50HYbNkiccNGKtlxZiaFkWeEUtB9yNAUa9yME05OeHru5v1NagibiaCvSyXhofWp4WFbrQUxWucgZNWw/640?wx_fmt=jpeg&from=appmsg "")  
  
包含应用程序和依赖项的目录可以传输到任何计算机。  
  
  
**0x05 内部VIP星球介绍-V1.4（福利）**  
  
        如果你想学习更多**渗透测试技术/应急溯源/免杀/挖洞赚取漏洞赏金/红队打点**  
欢迎加入我们**内部星球**  
可获得内部工具字典和享受内部资源和  
内部交流群，**每1-2天更新1day/0day漏洞刷分上分****(2025POC更新至4000+)**  
**，**  
包含网上一些**付费****工具及BurpSuite自动化漏****洞探测插件，AI代审工具等等**  
。shadon\Quake\  
Fofa高级会员，CTFShow等各种账号会员共享。详情直接点击下方链接进入了解，觉得价格高的师傅可后台回复"   
**星球**  
 "有优惠券名额有限先到先得！全网资源  
最新  
最丰富！**（🤙截止目前已有1800多位师傅选择加入❗️早加入早享受）**  
  
****  
  
**👉****点击了解加入-->>内部VIP知识星球福利介绍V1.4版本-1day/0day漏洞库及内部资源更新**  
  
****  
  
  
结尾  
  
# 免责声明  
  
  
# 获取方法  
  
  
**公众号回复20250604获取下载**  
  
# 最后必看-免责声明  
  
  
      
文章中的案例或工具仅面向合法授权的企业安全建设行为，如您需要测试内容的可用性，请自行搭建靶机环境，勿用于非法行为。如  
用于其他用途，由使用者承担全部法律及连带责任，与作者和本公众号无关。  
本项目所有收录的poc均为漏洞的理论判断，不存在漏洞利用过程，不会对目标发起真实攻击和漏洞利用。文中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用。  
如您在使用本工具或阅读文章的过程中存在任何非法行为，您需自行承担相应后果，我们将不承担任何法律及连带责任。本工具或文章或来源于网络，若有侵权请联系作者删除，请在24小时内删除，请勿用于商业行为，自行查验是否具有后门，切勿相信软件内的广告！  
  
  
  
# 往期推荐  
  
  
**1.内部VIP知识星球福利介绍V1.4（AI自动化工具）**  
  
**2.CS4.8-CobaltStrike4.8汉化+插件版**  
  
**3.最新BurpSuite2025.2.1专业版（新增AI模块）**  
  
**4. 最新xray1.9.11高级版下载Windows/Linux**  
  
**5. 最新HCL AppScan Standard**  
  
  
渗透安全HackTwo  
  
微信号：关注公众号获取  
  
后台回复星球加入：  
知识星球  
  
扫码关注 了解更多  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/RjOvISzUFq6qFFAxdkV2tgPPqL76yNTw38UJ9vr5QJQE48ff1I4Gichw7adAcHQx8ePBPmwvouAhs4ArJFVdKkw/640?wx_fmt=png "二维码")  
  
  
  
[全面资产收集流程及方法解析 万字长文窥探信息收集|挖洞技巧](https://mp.weixin.qq.com/s?__biz=Mzg3ODE2MjkxMQ==&mid=2247491574&idx=1&sn=48d865c82a228bd135a035419c765e94&scene=21#wechat_redirect)  
  
  
