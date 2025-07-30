#  03-Git信息泄露及其漏洞利用   
原创 simeon的文章  小兵搞安全   2024-04-29 06:37  
  
1.1  
Git信息泄露及其漏洞利用  
     
  
Git是由林纳斯·托瓦兹（Linus Torvalds）命名的，它来自英国俚语，意思是“混账”，Git是一个分布式版本控制软件，最初由林纳斯·托瓦兹（Linus Torvalds）创作，于2005年以GPL发布。最初目的是为更好地管理Linux内核开发而设计。Git最初只是作为一个可以被其他前端（比如CoGito或StGit）包装的后端而开发的，但后来Git内核已经成熟到可以独立地用作版本控制。很多著名的软件都使用Git进行版本控制，其中包括Linux内核、X.Org服务器和OLPC内核等项目的开发流程。Git与常用的版本控制工具CVS, Subversion 等不同，它采用了分布式版本库的方式，不需要服务器端软件支持。  
  
Git的官方网站：https://Git-scm.com/，Git代码托管仓库Github.com （  
https://Github.com  
） 是世界上最大的Git源代码管理网站。GIT不仅仅是个版本控制系统，它也是个内容管理系统，工作管理系统等。GIT把内容按元数据方式存储， GIT没有一个全局的版本号， GIT的内容存储使用的是SHA-1哈希算法。这能确保代码内容的完整性，确保在遇到磁盘故障和网络问题时降低对版本库的破坏。  
### 1.1.1Git常见命令    
  
git 提供了windows和linux版本，其下载地址为：https://git-scm.com/downloads，其最新版本为2.13。  
  
1.git安装  
  
   在当前linux系统直接输入git命令，如果系统无该命令则需要手动安装：  
  
（1）Debian或Ubuntu Linux 安装sudo apt-get install git /apt-get install git  
  
（2）centos系列安装：yum install git      
  
（3）windows安装直接根据提示进行即可，git还提供了基于gui  
  
界面的管理工具，感兴趣的朋友可以自行去下载（  
https://git-scm.com/download/gui/windows  
）  
  
2.git版本  
  
（1）获取当前git的版本：git –version  
  
 kali linux默认的git版本为git version 2.9.3。  
  
3.常用命令  
  
（1）初始化Git仓库  
  
git init  
  //使用当前目录  
  
git init newrepo // 使用newrepo作为仓库的根目录  
  
（2）添加任务文件  
  
git add filename  
  
（3）提交版本  
  
git commit -m "Adding files"  
  
git commit -a -m "Changed some files"  
  
git commit 命令的-a选项可将所有被修改或者已删除的且已经被git管理的文档提交到仓库中，千万注意，-a不会造成新文件被提交，只能修改。  
  
（4）发布版本  
  
我们先从服务器克隆一个库并上传。  
  
git clone ssh://www.antian365.com/~/www/project.git  
  
现在我们修改之后可以进行推送到服务器。  
  
git push ssh://www.antian365.com/~/www/project.git  
  
（5）取回更新  
  
git pull   
   
//取回默认的更新  
  
git pull http://git.example.com/project.git   
   
//取回某个站点的更新      
  
（6）删除：git rm file  
  
git rm --cached antian365.com.txt 只从stage中删除，保留物理文件  
  
git rm antian365.com.txt 不但从stage中删除，同时删除物理文件  
  
git mv a.txt b.txt 把a.txt改名为b.txt  
### 1.1.2Git信息泄露    
  
Git泄露漏洞是指开发人员使用Git进行版本控制，对站点自动部署，由于配置不当，将.Git文件夹直接部署到线上环境，导致其源代码等敏感信息泄露。  
  
Git信息泄露的危害很大，渗透测试人员、攻击者，可直接从源码获取敏感配置信息（如：邮箱，数据库连接文件），也可以进一步审计代码，挖掘文件上传、SQL注射等安全漏洞。  
  
1.搜索引擎在线搜索git信息泄露漏洞  
  
利用百度等搜索引擎对“index of /.git/”进行搜索，可以获取存在git信息泄露的站点，例如：  
  
http://www.caucedo.com/.git/  
  
https://codemirror.net/.git/  
  
http://jenicarvalho.com.br/.git/  
  
https://new.hotel-portomare.com/.git/  
  
http://www.bearcereju.com.hk/.git/  
  
http://www.kantaifm.cn/.git/  
  
2.手工测试  
  
在url后输入“/.git/config”，如果存在且能被访问，有些config文件会包含git配置信息，使用这些信息可以直接访问github代码托管仓库，可以直接下载源代码。  
### 1.1.3Git漏洞利用工具    
  
1.  
 GitHack  
  
下载地址：  
https://github.com/BugScanTeam/GitHack  
      
  
（1）  
  
安装githack  
  
下载源代码包：  
https://github.com/BugScanTeam/GitHack/archive/master.zip  
  
下载git windows安装程序：  
  
https://github.com/git-for-windows/git/releases/download/v2.13.0.windows.1/Git-2.13.0-32-bit.exe  
  
设置系统环境变量：右键单击“我的电脑或者计算机”-“属性”-“高级系统设置”-“高级”-“系统环境变量”，在系统变量中找到Path，然后双击打开，如图1所示，增加变量值“C:\Program Files (x86)\Git\bin”，记得在添加前增加“;”符号，设置完成后，打开cmd命令，输入git，显示git的命令，则说明git环境变量设置成功。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxgwicaib2LWT9K4b20ibbuHLJbYo2BUxtzGynHHcVs59bh3hqiaC2MHibLqw/640?wx_fmt=jpeg "")  
  
  
图1 设置git环境变量  
  
解压缩GitHack-master.zip到相应的文件夹下，执行命令：  
  
githack.py   
http://global.*******.com/.git/  
  
程序会自动扫描和获取git泄露文件，如图2所示。      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfx0dRH2Up29OeqicPXed09SXkGYMQJSn298BssSibgLkZ5Vxq8jtyJHUjg/640?wx_fmt=jpeg "")  
  
  
图2获取git泄露文件及其信息  
  
githack 默认会在当前文件夹下生成dist目录，获取的结果将以网站名字进行命令，该文件夹下会包含所有的git泄露的信息和文件。  
  
2.  
其它工具  
  
（  
1  
）  
 GitMiner  
  
https://Github.com/UnkL4b/GitMiner  
  
https://Github.com/UnkL4b/GitMiner.Git  
  
（  
2  
）  
GitPrey  
  
https://Github.com/repoog/GitPrey  
  
https://Github.com/repoog/GitPrey.Git  
  
（  
3  
）  
weakfilescan  
  
https://Github.com/ring04h/weakfilescan  
  
GitHub敏感信息扫描工具  
  
（  
4  
）  
Gitrob  
  
https://Github.com/michenriksen/Gitrob  
  
（  
5  
）  
 GitHack  
  
https://Github.com/lijiejie/GitHack，GitHack可以快速获取源代码，但git相关信息不能获取到本地。  
  
（  
6  
）  
GitHarvester  
  
https://github.com/metac0rtex/GitHarvester      
  
   对网上推荐的以上  
6  
款软件进行测试效果都不如GitHack  
（  
https://github.com/BugScanTeam/GitHack  
），  
BugScanTeam写的GitHack获取代码速度较慢，有时候会报错，lijiejie的GitHack获取代码速度较快  
。  
### 1.1.4一个利用实例    
  
1.扫描并获取git信息泄露漏洞  
  
  通过wvs对某目标网站进行漏洞扫描，如图3所示，wvs显示Git  
 repository found高危信息。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxGpNJOiaFxVqx1jQlzcGvsjqXCAepWYr8YEykuwa3mdfibymiapAjw1Zicg/640?wx_fmt=jpeg "")  
  
  
图3Git repository found信息泄露漏洞  
  
2.使用githack工具直接利用该漏洞  
  
   在kali下执行./GitHack.py  
 http://www.*****.cn/.git/，如图4所示，如果漏洞存在将获取相关信息。      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxz2deFcK05picb50icauLpeNa4c7pMhSib2YRIPW9ibMHia4mkibyrSicETCGA/640?wx_fmt=jpeg "")  
  
  
图4进行漏洞利用  
  
3.在本地生成源代码  
  
   GitHack.py工具将会在当前目录下的dist目录中生成目标网站命名的文件夹，将其复制到Windows下，如图5所示，可以看到目标网站的相关源代码。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxuVNZV5l2rLfn2BNfiaKWxJ6picTHiaHOQMrtJDCYjh4TdhWyOhfL9RicIg/640?wx_fmt=jpeg "")  
  
  
图5获取网站源代码  
  
             
  
             
  
                 
### 1.1.5一道CTF有关GIT信息泄露题目    
  
1.CTF题目  
  
  考试题目为一道web题，如图6所示，访问地址为http://106.75.109.168:9005，通过web漏洞扫描工具未发现明显漏洞。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxDicSXvVPJpFlfRmp5VJmB6YicPfTLicYMqP81u0JialFWv1cuc5WUIJZKQ/640?wx_fmt=png "")  
  
  
图  
6考试题目  
  
2.git信息泄露  
  
   通过手工测试，发现存在git信息泄露：  
http://106.75.109.168:9005/.git/  
，如图  
7所示，可以对./git目录进行浏览。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxibaR01TelEnjcUYdMsLPvvNacf683DH5frpH9bibjB9Y7nnwyS0ibcsiaA/640?wx_fmt=png "")  
  
  
图  
7git信息泄露  
  
3.使用githack获取源代码  
  
早期使用lijiejie写的GitHack（https://github.com/lijiejie/GitHack）获取其源代码，GitHack.py   
http://106.75.109.168:9005/.git/  
，如图  
8所示，获取网站所有的源代码。  
      
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxezOOGcg6ibftvvFia2Dw0y8MzRZdIO1RFNbefNcqea9dJXwMez7nsZQw/640?wx_fmt=png "")  
  
  
图  
8获取网站源代码  
  
4.对源代码进行审计及查看  
  
   在下载的源代码中发现存在一个Flag.php文件，其中提示“Flag  
 is not here,try to find other palce”，如图9所示，同时还对其它代码进行代码审计及查看，未发现Flag存在地址。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxUicJIEicEaia8aTfp4zO5ON6nVxWp6NHxGq9TpSV2B3KYcia8HxW0GBf1g/640?wx_fmt=png "")  
  
  
图  
9对源代码进行审计及查看  
  
5.git代码比较获取flag  
  
   使用命令diff  
 --git a/templates/Flag.php /b/templates/Flag.php，如图10所示，成功获取flag值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/icCXA7Jkf1VGicJQ7Jvbqr5y46THzVzUfxABjyZEorBSjuJay6UvL4bj9YB7sNy6sShyQMoVISpIMjqBYNQZNdjA/640?wx_fmt=png "")  
  
  
图  
10获取flag值  
      
### 1.1.6Git信息CTF解题思路及总结    
  
1.CTF比赛git信息泄露解题思路  
  
（1）flag在源代码中  
  
对于Flag在源代码中，可以通过git信息泄露工具来获取其源代码，通过比对或者回滚来获取Flag值。  
  
（2）flag不在源代码中  
  
对于flag不在源代码中，可以通过分析源代码，寻找程序中的各种漏洞，通过利用漏洞来获取webshell权限等方法来获取flag。  
  
2.CTF比赛git信息泄露解题命令  
  
（1）git回滚代码获取flag  
  
git log  
 //查看git日志，获取文件修改的hash值  
  
git reset --hard hash值  
 //通过hash值进行回滚，flag一般藏在这里  
  
（2）文件比较法  
  
执行类似命令：  
  
diff --git a/templates/Flag.php /b/templates/Flag.php  
### 1.1.7安全防范    
  
  使用nginx  
 来让外网具备访问文件目录的能力，所以此权限就在 nginx 层做配置，只需要将不需要被外界访问的目录进行排除设置即可。例如，不允许外部访问 .git 目录：  
  
server {  
  
    location  
 ~ /\.git {  
  
        deny  
 all;  
  
    }  
  
}  
  
                 
### 1.1.8参考文章    
  
https://www.polyu.edu.hk/its/general-information/newsletter/109-year-2016/mar-16/508-how-to-use-Github-without-leaking-your-credentials  
  
https://snyk.io/blog/leaked-credentials-in-packages/  
  
http://www.freebuf.com/sectool/66096.html, GitHack：一个Git泄露利用脚本  
  
https://zh.wikipedia.org/wiki/Git，Git  
百科  
  
http://www.runoob.com/manual/git-guide/，git -简明指南  
  
https://www.jianshu.com/p/934f39d386f3  
  
https://github.com/BugScanTeam/GitHack  
  
             
  
             
  
             
  
                 
  
