#  如何使用Rayder组织编排漏洞侦查和渗透测试工作流   
Alpha_h4ck  FreeBuf   2024-03-20 19:02  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif "")  
  
  
**关于Rayder**  
  
  
  
Rayder是一款针对漏洞网络侦查和渗透测试自动化工作流工具，该工具本质上是一个命令行工具，旨在帮助广大研究人员更轻松地组织、编排和执行漏洞侦查和渗透测试工作流。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibib875ET0dhn0SA7ib0u5DrDvCicMESaL2auaKmJaMr074JQ0HI6utl3OW74TiaFXu4S9lGaTMmRPGbQ/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Rayder允许我们在YAML文件中定义一系列功能模块，且每个模块都由要执行的命令所组成。Rayder可以帮助广大研究人员自动化复杂的流程，使重复的模块变得简单，并在命令不相互依赖的情况下并行执行。  
  
  
**工具要求**  
  
  
> Go v1.16+  
  
  
  
**工具安装**  
  
  
  
首先，我们需要在本地设备上安装并配置好Go v1.16+环境。然后直接运行下列命令即可安装最新版本的Rayder：  
```
go install github.com/devanshbatham/rayder@v0.0.4
```  
  
  
Rayder提供了一种非常简单且直接的工作流执行方法，所有要执行的内容都在YAML文件中定义，使用下列命令即可直接运行Rayder：  
```
rayder -w path/to/workflow.yaml
```  
  
定义在YAML文件中的工作流数据结构如下所示：  
```
vars:

  VAR_NAME: value

  # 这里可以添加更多的变量...

 

parallel: true|false

modules:

  - name: task-name

    cmds:

      - command-1

      - command-2

      # 这里可以添加更多的命令...

    silent: true|false

  # 这里可以添加更多的模块...
```  
  
  
**在工作流中使用变量**  
  
  
  
Rayder支持在工作流配置文件中使用各种变量，这种方式不仅实现了命令参数化，而且也能够更大程度地实现灵活性。我们可以在YAML工作流文件的vars部分定义变量，然后使用双大括号{{}}在命令字符串中引用这些变量。  
  
### 定义变量  
```
vars:

  VAR_NAME: value

  ANOTHER_VAR: another_value

  # Add more variables...
```  
### 在命令中引用变量  
```
modules:

  - name: example-task

    cmds:

      - echo "Output directory {{OUTPUT_DIR}}"
```  
### 通过命令行提供变量  
```
rayder -w path/to/workflow.yaml VAR_NAME=new_value ANOTHER_VAR=updated_value
```  
###   
### 使用样例一  
  
****  
我们可以按照下列方式在工作流配置文件中定义、引用和提供变量：  
```
vars:

  ORG: "example.org"

  OUTPUT_DIR: "results"

 

modules:

  - name: example-task

    cmds:

      - echo "Organization {{ORG}}"

      - echo "Output directory {{OUTPUT_DIR}}"
```  
  
执行工作流时，我们可以在命令行命令中提供ORG和OUTPUT_DIR的变量值：  
```
rayder -w path/to/workflow.yaml ORG=custom_org OUTPUT_DIR=custom_results_dir
```  
  
上述命令将会覆盖这些变量原用的值，并使用命令行提供的新值。  
  
### 使用样例二  
  
  
以下是一个为反向whois定制的工作流配置示例，它将根域名重新配置并处理为子域名，然后解析它们并检查哪些是有效域名：  
```
vars:

  ORG: "Acme, Inc"

  OUTPUT_DIR: "results-dir"

 

parallel: false

modules:

  - name: reverse-whois

    silent: false

    cmds:

      - mkdir -p {{OUTPUT_DIR}}

      - revwhoix -k "{{ORG}}" > {{OUTPUT_DIR}}/root-domains.txt

 

  - name: finding-subdomains

    cmds:

      - xargs -I {} -a {{OUTPUT_DIR}}/root-domains.txt echo "subfinder -d {} -o {}.out" | quaithe -workers 30

    silent: false

 

  - name: cleaning-subdomains

    cmds:

      -  cat *.out > {{OUTPUT_DIR}}/root-subdomains.txt

      -  rm *.out

    silent: true

 

  - name: resolving-subdomains

    cmds:

      - cat {{OUTPUT_DIR}}/root-subdomains.txt | dnsx -silent -threads 100 -o {{OUTPUT_DIR}}/resolved-subdomains.txt

    silent: false

 

  - name: checking-alive-subdomains

    cmds:

      - cat {{OUTPUT_DIR}}/resolved-subdomains.txt | httpx -silent -threads 1000 -o {{OUTPUT_DIR}}/alive-subdomains.txt

silent: false
```  
  
如需执行上述工作流，运行下列命令即可：  
```
rayder -w path/to/reverse-whois.yaml ORG="Yelp, Inc" OUTPUT_DIR=results
```  
  
  
需要注意的是，如果将配置文件中parallel字段设置为true，则模块将会并行执行。  
  
  
**工具运行截图**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ibib875ET0dhn0SA7ib0u5DrDWVE4G4F1DRSHoHfiaJPG2ugtD0VU8soM1Dg5PN18ueqB2dFUiab3wF8g/640?wx_fmt=jpeg&from=appmsg "")  
  
  
  
**许可证协议**  
  
  
  
本项目的开发与发布遵循  
MIT  
开源许可证协议。  
  
  
**项目地址**  
  
  
##   
  
**Rayder：**  
  
https://github.com/devanshbatham/rayder  
  
  
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
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=jpeg&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oQ6bDiaGhdyodyXHMOVT6w8DobNKYuiaE7OzFMbpar0icHmzxjMvI2ACxFql4Wbu2CfOZeadq1WicJbib6FqTyxEx6Q/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ61icYlLmBLDpdYEZ7nIzpGovpHjtxITB6ibiaC3R5hoibVkQsVLQfdK57w/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
> https://github.com/devanshbatham/rayder-workflows  
> https://taskfile.dev/  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3icEEJemUSFlfufMicpZeRJZJ7JfyOicficFrgrD4BHnIMtgCpBbsSUBsQ0N7pHC7YpU8BrZWWwMMghoQ/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
[](http://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492835&idx=1&sn=a76625a0ed94ef9e3ccce9c92b384984&chksm=ce1f1e7cf968976aa3947aa7f69fe9318187d8160fa930c46e7347de2c2d7e1290164b0661e1&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=Mzg2MTAwNzg1Ng==&mid=2247492505&idx=1&sn=76aed8d6c7225f5a246f32645fc77167&scene=21#wechat_redirect)  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
