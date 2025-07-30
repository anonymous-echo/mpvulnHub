#  漏洞扫描工具：AWVS   
 泷羽SEC-ohh   2025-02-14 11:46  
  
>   
> 由于传播、利用本公众号所提供的信息而造成的任何直接或间接的后果及损失，均由使用者本人负责，公众号及作者不为此承担任何责任，一旦造成后果请自行承担!如有侵权烦请告知，我们会立即删除并且致歉。谢谢!  
  
## 一、AWVS简介   
  
AWVS（Acunetix Web Vulnerability Scanner）是一款专业的Web漏洞扫描工具，用于检测网站的安全漏洞。它通过网络爬虫测试网站安全，检测流行安全漏洞，适用于任何中小型和大型企业的内联网、外延网和面向客户、雇员、厂商和其它人员的Web网站  
## 二、AWVS安装   
### 1、解压压缩包  
```
cd awvs  #进入awvs目录
unzip Acunetix-v24.6.24-Linux.zip -d /awvs       #解压压缩包

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHwM4lZG4HlN09ahJ79w4YmqtQ9VHrW3kqp2uDgNtnMiccpuuwNWXWdug/640?wx_fmt=png&from=appmsg "")  
### 2、安装脚本添加执行权限  
```
chmod 777 acunetix_install.sh 

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHvibBZtAbFL5945bszJDCp7XEwiba0ndnB2M97U8amIjBlMrInn4J3icXw/640?wx_fmt=png&from=appmsg "")  
### 3、执行安装脚本  
```
./acunetix_install.sh
./crack.sh  

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHf06cChHW7HGOIjrfkicKzoMeCx3QiaibndZvGWu1yqZceWVUlK0OlNnAw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHDhjlNvBloOgtQjlvsrQiaWMYPvKad1yTUH2iaooya5P2yR1NFgMsJQGQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHPILfMpVSJZ4c1c4eqcUhYxnUb0cZtCaK2I1VIKepf8YCIX2aELXIsA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHxSR2cicIjDOMLcrica8z1OZ2eKC5EzEYSUk9J8WbCkMeUsuFMHw5snWA/640?wx_fmt=png&from=appmsg "")  
## 三、登录AWVS   
  
输入刚才安装时输入的邮箱名跟密码进行登录![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHOJaYhU0ibXGrL1PG5J1dePfXicTlKCr0eUkeiaDNuFN5W9pt8drXAzdibw/640?wx_fmt=png&from=appmsg "")  
  
## 四、AWVS扫描   
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHhq5UGnRbicWssCymPyDichFehd9WTU4Fsh8LOUDXFtuMVHRRWNQKTribQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHKDBFByyp0m9kkQuFX2qt5ZiaeyUYbnl4C3iaOeseYofZa0SmJcMDu8NA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKH1ibtrtvdsM5z9rpphS8N4L84taoAmDGA3egVMekrhozfc4Wqs4Ntxlg/640?wx_fmt=png&from=appmsg "")  
## 五、AWVS密码重置   
```
 cd /home/acunetix/.acunetix  
 ./change_credentials.sh   #执行后可以直接重置密码

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/wul7icMxhHHBAibyBOWTZvTNrBQCJ6ImKHmAibOia3BlhDYysldkpbh1F8ZuhaQX6rYI7Sw4W7UWmdwaOK4kqpmXgg/640?wx_fmt=png&from=appmsg "")  
## 六、下载地址   
  
链接：https://pan.quark.cn/s/457b0cd1591a 提取码：R3FM  
  
  
