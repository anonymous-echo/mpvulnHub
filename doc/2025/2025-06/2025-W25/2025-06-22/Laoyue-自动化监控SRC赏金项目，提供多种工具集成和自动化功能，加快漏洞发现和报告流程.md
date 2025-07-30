> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkzODQzNDU5NQ==&mid=2247486381&idx=1&sn=027accf79c46ae004c1443ec79150b2d

#  Laoyue-自动化监控SRC赏金项目，提供多种工具集成和自动化功能，加快漏洞发现和报告流程  
秀龙叔  黑客之道HackerWay   2025-06-22 01:00  
  

```
   __                       
  / /__ ____  __ ____ _____ 
 / / _ `/ _ \/ // / // / -_)
/_/\_,_/\___/\_, /\_,_/\__/ 
            /___/          
```

  
简介：  
  
Laoyue是一个面向安全研究人员和漏洞赏金猎人的自动化监控工具集，专注于提升漏洞发现与资产管理的效率。它集成多种常用安全工具与扫描模块，支持对目标资产进行周期性探测、敏感信息收集与常见漏洞检测，并可将结果实时推送至指定渠道。  
  
使用参数：  

```
-h, --help  : 显示帮助信息
-d, --domain: 指定单个域名或包含多个域名的文件（如：src.txt）。
-m, --ml    : 使用ffuf扫描目录。可在./inifile/dict目录下添加字典。
-n, --nl    : 使用nuclei进行漏洞扫描。
-f, --fs    : 使用fscan进行漏洞扫描。
-a, --av    : 使用awvs进行漏洞扫描。
-z, --hostz : 进行host碰撞。
-N, --notauto: 启用被动扫描模式，手动收集URL资产后使用(资产放在./result/notautolist/notautolist.txt里)。
```


```
声明：删除了之前的主域名收集接口,请自行收集要跑的SRC主域名。
```

  
快速开始：  
  
1、使用git拉取项目到vps(centos7/ubutu20)服务器，python3以上即可，java需要1.8环境  

```
git clone https://github.com/Soufaker/laoyue.git
```

  
2、在config.ini中填入自己的各种key，包括某查的cookie，某fa的key，某图的key，钉钉的key(可以搞多个账号白嫖每天的500积分)  
  
![image-20230201140843918](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDsMibKyTaxOHOJVe15ZfNGoj7QYtHnpnD3qzPAguW5VALrJAexuSPqsw/640?wx_fmt=png&from=appmsg "")  
  
3、注意你自己使用的python3表示方式，有的师傅服务器python3用的是pyhon或者python3.x啥标识，自行更改build.sh中和laoyue.py中的python表示方式，默认为python3  
  
4、使用chmod 777 biuld.sh加权限安装所需依赖，根据系统环境安装，如果是centos安装build_centos7.sh，如果是ubutu，就按照build_ubutu.sh  

```
./build_centos7.sh or ./build_ubutu.sh
```

  
5、常用命令如下：  

```
常用自动化监控命令(可以先不加nohup手动测试一下看看能跑通不,能跑通就用下面的命令,可以自行增加删除参数,下面的是都跑一遍):
单域名扫描: nohup python3 laoyue.py -d example.com  -m -f -n -z -a  > laoyue.out 2>&1 &
多域名扫描: nohup python3 laoyue.py -d &#34;SRC.txt&#34;  -m -f -n -z -a  > laoyue.out 2>&1 &
被动扫描: nohup python3 laoyue.py -m -n -f -z -a -N &
```

  
6、新增自动化定时检测是否卡死的功能代码，请在执行上述自动化指令后手动执行该代码(运行该命令之前，请先运行build.sh文件或者手动在shell执行命令：sed -i "s/\r//" check_nohup_size.sh，定时检查nohup.out是否变化防止卡死导致自动化停止)  

```
nohup ./check_nohup_size.sh >check_size.out 2>&1 &
```

  
效果展示：  
  
新增暴露面资产：  
  
![image-20230201143343863](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDibfpYF7Do9bOPv2qoy6sJw3W4HicK7ISm21QyH3vezmibXNnC2qoVTPJA/640?wx_fmt=png&from=appmsg "")  
  
敏感信息：  
  
![image-20230201143025595](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDC7O3LwCxIo3JVXA8CRibQlBgWnH84tibfS7S1nKCW9VZVSc07Qz6e7bQ/640?wx_fmt=png&from=appmsg "")  
  
漏洞信息(awvs,fscan,nuclei)：  
  
![image-20230306095756391](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDb8V2sYkzzibChccCtc3j2F9Yk5Fevbnn4tEqfHA4OtKkDe2AFoX8gEQ/640?wx_fmt=png&from=appmsg "")  
  
![image-20230306095756391](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDrkGmFoby86aTvRLkqse30f3nMA2TiaiaErVvJMZMHnNPySLHEdjlw9uQ/640?wx_fmt=png&from=appmsg "")  
  
服务器目录下生成文件信息：  

```
一个总的excel(./result/baolumian)
```

  
![image-20230201143627247](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwDJpfCC2ymLBOMDVR2SLIKjLmic9JEkjRicntp8bus5MvYOqKvXGxLwHTg/640?wx_fmt=png&from=appmsg "")  
  
![image-20230201143627247](https://mmbiz.qpic.cn/sz_mmbiz_png/g68qqsJpeZLCFbJXr1LkWK5AtD1jsVwD8Bg4GjFYYXdulHWQaGKlQDiapFhibzibVxjLana4P9UQBDKTGUedmp3Zw/640?wx_fmt=png&from=appmsg "")  
  
- 公众号回复“  
9931  
”获取下载链接  
  
**用您发财的小手点个赞鼓励一下吧❥(^_-)**  
  
**关注公众号便于更好的为您分享(#^.^#)**  
  
  
  
  
**免责****声明**  
  
本公众号“黑客之道HackerWay”提供的资源仅供学习，利⽤本公众号“黑客之道HackerWay”所提供的信息而造成的任何直接或者间接的后果及损失，均由使⽤者本⼈负责，本公众号“黑客之道HackerWay”及作者不为此承担任何责任，一旦造成后果请自行承担责任！  
  
  
谢谢 !  
  
  
