#  渗透测试神器之漏洞利用代理工具Empire   
原创 OneDay一卒的老付  老付话安全   2025-03-21 20:25  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/7UnMUNqGIz071DWbJdrzpdJpDxlHDFtnMDlvK8TeibfibdovgH3vMKfIloQibicL6TTiaXQib28nacKJv8qx7AJNnm8g/640?wx_fmt=gif "")  
  
**点击蓝字**  
  
**关注我们**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/MVPvEL7Qg0E3EDiaBQZPhveZ4OnRicVw4gYtShmROav0FxbCicibPVXF436z721PLib1ymKaug1Rs2IYJmtibczLuNLg/640?wx_fmt=gif "")  
  
  
**始于理论，源于实践，终于实战**  
  
**老付话安全，每天一点点**  
  
**激情永无限，进步看得见**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/lB1oaPhdMNvxZ67rEjeQWUFqwCxiacBblWHRAxzuoMfYPQXETZ7Y5bsGSLBPy2QGDKIbia74ruAWgJXhWkMlGgkA/640?wx_fmt=png "")  
  
**严正声明**  
  
  
  
本号所写文章方法和工具只用于学习和交流，严禁使用文章所述内容中的方法未经许可的情况下对生产系统进行方法验证实施，发生一切问题由相关个人承担法律责任，其与本号无关。  
  
特此声明！！！  
  
  
       Empire是一款针对Windows平台的、使用Powershell脚本作为攻击载荷的渗透攻击框架工具，具有从stager生成、提权到渗透维持的一系列功能。  
  
Empire实现了无需powshell.exe就可运行Powershell代理的功能，还可以快速在后期部署漏洞利用模块，其内置模块有键盘记录、Mimikatz、绕过UAC、内网扫描等，使用能够躲避内网检测和大部分安全防护工具的查杀，简单来说就有点类似Metasploit，是一个基于PowerShell的远程控制木马。  
  
  
**安装Empire：**  
- 安装依赖项  
  
sudo apt update   
  
sudo apt install -y git python3 python3-pip python3-dev libffi-dev libssl-dev   
  
pip3 install wheel pyopenssl cffi  
  
- 克隆新版本仓库  
  
git clone https://github.com/BC-SECURITY/Empire.git   
  
- 安装 Empire  
  
sudo python3 setup.py  install  # 使用系统级安装# 或python3 -m pip install --user .  # 用户级安装（推荐避免权限冲突）  
  
cd  Empire  
  
cd setup/  
  
./install.sh  
  
  
**Empire的基本使用**  
  
****  
运行Empire后，输入help命令查看具体的使用帮助。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9NqsZiaOn4oHLqNrTYjJ86UCv1YRX4BKTrsa0Hx1J1t3YI20SHgLXQfJVUibBuiaicb7VibRmbKNM6Rbpg/640?wx_fmt=png "")  
  
  
输入Listeners命令进入监听线程界面，  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9NqsZiaOn4oHLqNrTYjJ86UCpb61UYq1NS2jaFuHPLbNYNTvF6bCLHT4uKpFlvPzpaU4stmc8IwBtg/640?wx_fmt=png "")  
  
  
输入uselistener来设置采用何种监听模式  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9NqsZiaOn4oHLqNrTYjJ86UCogicjeMYwatzy7n0Ne5tK2Iqp5BggZUE9ZBVTx4jWmErZALt9k9WtHA/640?wx_fmt=png "")  
  
  
采用http监听模式，输入uselistener http，然后输入info命令查看具体参数设置。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9NqsZiaOn4oHLqNrTYjJ86UCocpVA9mxcwGv2DLqNvsckam9GaazAwdWibcsSISeibA7w5hicHTayaticw/640?wx_fmt=png "")  
  
  
通过set配置参数，并提供execeute执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9NqsZiaOn4oHLqNrTYjJ86UCd7rfXGicCEuzAjLXAMOP92hhNbNxGIA12IO7w0SdE58Il5FoQlwdTRg/640?wx_fmt=png "")  
  
  
**生成木马**  
  
输入usestager windows/all的命令，输入info命令查看详细参数，通过set配置参数，通过execute执行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/icKb2wsWzy9NqsZiaOn4oHLqNrTYjJ86UCjSMQUhVeBDZ9gfiaPKCAnIPdBXq7mDVjfbq6q5Cx1wKiaOtnFh7icx5icQ/640?wx_fmt=png "")  
  
  
  
**END**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oZN2pbzJKdWUK3Ne8uSjJibGEKUc8s8FbE3ibZ4mjQicF2gDe1DTSIqmWKU5YsEtQgKubRf5IySO9NkDcr1valibkw/640?wx_fmt=png "")  
  
**老付**  
  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/icKb2wsWzy9ORYSWhDNicEicRGRDKAtYKxHiczj6Y36GXkmREcnyoDuomV4Mv8R0f00X8nWby1hdNDwYGv2owdnCXg/640?wx_fmt=jpeg "")  
  
欢迎扫码  
  
关注我们  
  
网络安全  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/MGCuM8RxgBrAiaXKicQAtmSp9YTKetGPJPuXs2qjPqsAS6kA3H68OxicpeGaHD7vgMPgNbbfib6kd8FmLtchGWqDFQ/640?wx_fmt=png "")  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/pvny8ibJ30HReTzy7GMPOG1ib3WIDLJlkPkdfm6xOwn2eQhjuJlia70sMafqZ16R8kLJ1vDiarD8qib0icQ2VntWGFpA/640?wx_fmt=png "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/e7Rk3vLDb5uzoEC41NayHia3vKfBKJ4jNYnEaVF35mYHxOQW9ukUibcn2iaFxJichsBBZHmbMibOWia3JfRfSmPApevA/640?wx_fmt=png "")  
  
  
