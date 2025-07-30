#  Bugsy：一款功能强大的代码安全漏洞自动化修复工具   
Alpha_h4ck  FreeBuf   2024-03-27 18:58  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于Bugsy**  
  
  
  
Bugsy是一款功能强大的代码安全漏洞自动化修复工具，该工具本质上是一个命令行接口工具，可以帮助广大研究人员以自动化的形式修复代码中的安全漏洞。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib5ic2tKzv4pphJqfd9E1X8NVzGjzmniagxJzWSA04oZuGklYCk53wGtAsaic9ZSu91hxNc3S75iaBcfw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Bugsy是  
Mobb  
（一款自动化安全漏洞修复工具，能够结合多种工具生成代码修复程序供开发人员审查和提交代码）的一个社区版本，也是第一个与供应商无关的自动安全漏洞修复工具，Bugsy旨在帮助开发人员快速识别和修复代码中的安全漏洞。  
  
  
**功能介绍**  
  
  
  
当前版本的Bugsy提供了两个功能模式，即扫描模式和分析模式。扫描模式不需要SAST报告，而分析模式下用户需提供预生成的SAST报告。  
  
### 扫描模式  
  
****  
1、使用Checkmarx或Snyk CLI工具在给定的开源GitHub/GitLab/ADO代码库上执行SAST扫描；  
  
2、分析漏洞报告以确定可以自动修复的安全问题；  
  
3、生成代码修复程序并将用户重定向到Mobb平台上的修复报告页面；  
  
****### 分析模式  
  
****  
1、分析Checkmarx/CodeQL/Fortify/Snyk漏洞报告，以确定可以自动修复的问题；  
  
2、生成代码修复程序并将用户重定向到Mobb平台上的修复报告页面；  
  
  
**工具要求**  
  
##   
  
NodeJS  
  
NPX  
  
  
**工具下载**  
  
  
  
广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/mobb-dev/bugsy.git
```  
  
  
**工具使用**  
  
  
  
我们可以直接在命令行中使用npx运行Bugsy：  
```
npx mobbdev
```  
  
  
上述命令将会给我们显示工具的使用帮助信息：  
```
Bugsy - Trusted, Automatic Vulnerability Fixer

 

Usage:

mobbdev <command> [options]

 

 

Commands:

  mobbdev scan     扫描代码漏洞，生成自动化修复程序

  mobbdev analyze  生成漏洞报告和相关代码库，生成自动化修复程序

 

Options:

  -h,--help    显示工具帮助信息  [boolean]

 

Made by Mobb
```  
  
  
**工具使用样例**  
  
  
##   
  
扫描一个目标代码库：  
```
mobbdev scan -r https://github.com/WebGoat/WebGoat
```  
  
  
针对目标代码库执行新的SAST扫描，并获取漏洞修复程序：  
```
npx mobbdev scan --repo https://github.com/mobb-dev/simple-vulnerable-java-project
```  
  
  
获取预生成的SAST报告：  
```
npx mobbdev analyze --scan-file sast_results.json --repo https://github.com/mobb-dev/simple-vulnerable-java-project
```  
  
  
查看工具扫描模式和分析模式的帮助信息：  
```
npx mobbdev scan -h

npx mobbdev analyze -h
```  
  
  
以CI/CD管道使用Bugsy：  
```
npx mobbdev analyze --ci --scan-file $SAST_RESULTS_FILENAME --repo $CI_PROJECT_URL --ref $CI_COMMIT_REF_NAME --api-key $MOBB_API_KEY
```  
  
  
**工具运行截图**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib5ic2tKzv4pphJqfd9E1X8NoicV12UFzVHUmiaggKjUK8Zemc8X9myX1QNiaKGlRWTLNkTH0ic5eSzNjA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ib5ic2tKzv4pphJqfd9E1X8N4DeQVrIdvpPuIAe5TH2q0WViaiauaxichn0fveohHQ6OvBcpHuMzYr4lQ/640?wx_fmt=jpeg&from=appmsg "")  
##   
  
**许可证协议**  
  
  
  
本项目的开发与发布遵循  
MIT  
开源许可证协议。  
  
  
**项目地址**  
  
  
##   
  
**Bugsy：**  
  
https://github.com/mobb-dev/bugsy  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复“加群”，申请加入群聊  
】  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
> https://www.mobb.ai/  
> https://github.com/mobb-dev/simple-vulnerable-java-project  
> https://bit.ly/Mobb-discord  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492995&idx=1&sn=cd4660fdf363a0173e2e8fa7f3879710&chksm=ce1f1f1cf968960ac99038a74f5ac2b9718e581753b97ff86f473ae80f1c2cc0e17fa3ed60de&scene=21#wechat_redirect)  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492835&idx=1&sn=a76625a0ed94ef9e3ccce9c92b384984&chksm=ce1f1e7cf968976aa3947aa7f69fe9318187d8160fa930c46e7347de2c2d7e1290164b0661e1&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
