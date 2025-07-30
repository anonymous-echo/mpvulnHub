#  容器镜像安全：安全漏洞扫描神器Trivy   
 马哥网络安全   2025-04-27 09:00  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/2rMyvdWluHvTBYyBWZhW4pP5FT0l7LebJwy5efjtuOgicSqeG8a7Ym9pPaXnfmXI2IMzM0QTPDUMtKviaOSshCSw/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
![]( "")  
  
目录  
- 一.系统环境  
  
- 二.前言  
  
- 三.Trivy简介  
  
- 四.Trivy漏洞扫描原理  
  
- 五.利用trivy检测容器镜像的安全性  
  
- 六.总结  
  
# 一.系统环境  
  
本文主要基于Docker version 20.10.14和Linux操作系统Ubuntu 18.04。  
  
<table><thead><tr><th style="padding: 8px 14px;background-color: rgb(250, 250, 250);border-top-width: 1px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;"><section><span leaf="">服务器版本</span></section></th><th style="padding: 8px 14px;background-color: rgb(250, 250, 250);border-top-width: 1px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;"><section><span leaf="">docker软件版本</span></section></th><th style="padding: 8px 14px;background-color: rgb(250, 250, 250);border-top-width: 1px;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;"><section><span leaf="">CPU架构</span></section></th></tr></thead><tbody><tr><td style="padding: 8px 14px;vertical-align: top;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;"><section><span leaf="">Ubuntu 18.04.5 LTS</span></section></td><td style="padding: 8px 14px;vertical-align: top;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;"><section><span leaf="">Docker version 20.10.14</span></section></td><td style="padding: 8px 14px;vertical-align: top;border-color: rgb(192, 192, 192);border-collapse: collapse;min-width: 50px;"><section><span leaf="">x86_64</span></section></td></tr></tbody></table>  
# 二.前言  
  
随着容器技术的普及，容器镜像的安全性问题日益凸显。容器镜像中可能存在的漏洞会被攻击者利用，从而导致整个应用的安全风险。因此，对容器镜像进行安全漏洞扫描成为了必要的需求。Trivy是一款由aquasecurity团队开发的容器镜像安全漏洞扫描工具，支持Docker、Kubernetes等多种容器技术，具有易于使用、支持多种漏洞数据库等特点。  
# 三.Trivy简介  
  
Trivy是一款全面且多功能的安全扫描程序。Trivy 具有查找安全问题的扫描器。Trivy官网为：https://github.com/aquasecurity/trivy ，Trivy软件包下载地址为：https://github.com/aquasecurity/trivy/releases/ 。  
  
Trivy 可以扫描的对象为：  
- 容器镜像；  
  
- 文件系统；  
  
- Git Repository （远程）；  
  
- 虚拟机映像；  
  
- Kubernetes；  
  
- AWS系统。  
  
Trivy能够发现的问题有：  
- 正在使用的操作系统包和软件依赖项 （SBOM）；  
  
- 已知漏洞 （CVE）；  
  
- IaC 问题和错误配置；  
  
- 敏感信息和机密；  
  
- 软件许可证。  
  
# 四.Trivy漏洞扫描原理  
  
Trivy通过分析容器镜像的文件系统，识别出其中的软件包及其版本号，然后与漏洞数据库进行匹配，找出存在安全漏洞的软件包。Trivy采用了以下技术实现漏洞扫描：  
1. Dockerfile解析：Trivy可以根据Dockerfile自动解析出容器镜像的构建过程，获取镜像中包含的软件包及其版本号。  
  
1. 漏洞数据库匹配：Trivy将容器镜像中的软件包及其版本号与漏洞数据库进行匹配，找出存在安全漏洞的软件包。  
  
1. 漏洞详情展示：Trivy提供了详细的漏洞信息，包括漏洞描述、影响版本、修复建议等，帮助用户了解漏洞风险。  
  
CVE全称是Common Vulnerabilities and Exposures，即通用漏洞披露，它是MITRE公司维护和更新的安全漏洞列表，列表中的每个条目都会有一个唯一的CVE编号，即CVE ID，供安全研究员和受攻击的软件供应商使用，以便确定和回应安全漏洞。CVE条目包含了与CVE ID相关的漏洞的描述性数据（即简要描述和至少一个参考）。当前CVE累计收录了19万+个安全漏洞。  
  
Trivy漏洞扫描原理简单来说就是：**Trivy下载漏洞数据库CVE到本地，Trivy本地数据库记录了常见的漏洞信息，Trivy读取镜像里的程序和本地数据库进行比对，确定镜像是否存在漏洞**  
。  
# 五.利用trivy检测容器镜像的安全性  
  
首先需要安装docker。  
```
[root@etcd2 ~]# yum -y install docker-ce
```  
  
查看docker版本。  
```
[root@etcd2 ~]# docker -vDocker version 20.10.12, build e91ed57
```  
  
配置docker镜像加速器。  
```
[root@etcd2 ~]# cat /etc/docker/daemon.json{"registry-mirrors":["https://frz7i079.mirror.aliyuncs.com"]}
```  
  
提前下载好镜像做准备，我们下载了redis，busybox，nginx镜像。  
```
[root@etcd2 ~]# docker pull redis[root@etcd2 ~]# docker pull busybox[root@etcd2 ~]# docker pull nginx[root@etcd2 ~]# docker imagesREPOSITORY                    TAG       IMAGE ID       CREATED        SIZEbusybox                       latest    ec3f0931a6e6   4 months ago   1.24MBnginx                         latest    605c77e624dd   5 months ago   141MBredis                         latest    7614ae9453d1   5 months ago   113MB
```  
  
下载好trivy安装包。  
```
[root@etcd2 ~]# ls trivy_0.28.1_Linux-64bit.rpm trivy_0.28.1_Linux-64bit.rpm
```  
  
安装trivy。  
```
[root@etcd2 ~]# yum -y install trivy_0.28.1_Linux-64bit.rpm
```  
  
现在trivy就安装好了。  
```
[root@etcd2 ~]# which trivy/usr/local/bin/trivy
```  
  
查看帮助：trivy --help。  
```
[root@etcd2 ~]# trivy --help
```  
  
查看trivy扫描镜像的语法：  
```
[root@etcd2 ~]# trivy image --help
```  
  
trivy image nginx 表示检测nginx镜像的漏洞，第一次检测漏洞会下载漏洞数据库，漏洞数据库目录默认是~/.cache/trivy 。  
```
[root@etcd2 ~]# trivy image nginx2022-06-16T17:06:01.035+0800	INFO	Need to update DB2022-06-16T17:06:01.036+0800	INFO	DB Repository: ghcr.io/aquasecurity/trivy-db2022-06-16T17:06:01.036+0800	INFO	Downloading DB...32.56 MiB / 32.56 MiB [------------------------------------------------------------------------------------------------------------------------------------------------------------]100.00% 42.01 KiB p/s 13m14ss2022-06-16T17:19:28.400+0800	WARN	Increase --timeout value2022-06-16T17:19:28.400+0800	FATAL	image scan error: scan error: image scan failed: failed analysis: analyze error: timeout: context deadline exceeded
```  
  
漏洞数据库下载好之后，就可以检测镜像漏洞了，显示了5个级别的漏洞：UNKNOWN: 1, LOW: 93, MEDIUM: 43, HIGH: 41, CRITICAL: 24。  
```
[root@etcd2 ~]# trivy image nginx2022-06-16T17:23:11.533+0800	INFO	Detected OS: debian2022-06-16T17:23:11.533+0800	INFO	Detecting Debian vulnerabilities...2022-06-16T17:23:11.585+0800	INFO	Number of language-specific files: 0nginx (debian 11.2)Total: 202(UNKNOWN: 1, LOW: 93, MEDIUM: 43, HIGH: 41, CRITICAL: 24)┌─────────────────────┬──────────────────┬──────────┬────────────────────┬─────────────────────────┬──────────────────────────────────────────────────────────────┐│       Library       │  Vulnerability   │ Severity │ Installed Version  │      Fixed Version      │                            Title                             │├─────────────────────┼──────────────────┼──────────┼────────────────────┼─────────────────────────┼──────────────────────────────────────────────────────────────┤│ apt                 │ CVE-2011-3374    │ LOW      │ 2.2.4              │                         │ It was found that apt-key in apt, all versions, do not       ││                     │                  │          │                    │                         │ correctly...                                                 ││                     │                  │          │                    │                         │ https://avd.aquasec.com/nvd/cve-2011-3374                    │├─────────────────────┼──────────────────┼──────────┼────────────────────┼─────────────────────────┼──────────────────────────────────────────────────────────────┤│ bsdutils            │ CVE-2021-3995    │ MEDIUM   │ 2.36.1-8           │ 2.36.1-8+deb11u1        │ util-linux: Unauthorized unmount of FUSE filesystems         ││                     │                  │          │                    │                         │ belonging to users with similar uid...                       ││                     │                  │          │                    │                         │ https://avd.aquasec.com/nvd/cve-2021-3995                    │├─────────────────────┼──────────────────┼──────────┼────────────────────┼─────────────────────────┼──────────────────────────────────────────────────────────────┤......├─────────────────────┼──────────────────┼──────────┼────────────────────┼─────────────────────────┼──────────────────────────────────────────────────────────────┤│ zlib1g              │ CVE-2018-25032   │ HIGH     │ 1:1.2.11.dfsg-2    │ 1:1.2.11.dfsg-2+deb11u1 │ zlib: A flaw found in zlib when compressing (not             ││                     │                  │          │                    │                         │ decompressing) certain inputs...                             ││                     │                  │          │                    │                         │ https://avd.aquasec.com/nvd/cve-2018-25032                   │└─────────────────────┴──────────────────┴──────────┴────────────────────┴─────────────────────────┴──────────────────────────────────────────────────────────────┘
```  
  
trivy缓存漏洞数据库目录如下：  
```
[root@etcd2 ~]# ls .cache/trivy/ -lh总用量 0drwxr-xr-x 2 root root 436月  1617:19 dbdrwx------ 2 root root 226月  1617:06 fanal
```  
  
trivy会下载漏洞数据库到本地，有时候下载会很慢，可以直接把已经安装好的~/.cache/trivy文件夹直接打包，放到新安装的机器上，就可以直接使用trivy了。  
  
Trivy开始运行时每 12 小时下载一次漏洞数据库。这通常很快，因为数据库的大小只有 10~30MB。但是，如果您甚至想跳过它，请使用该--skip-db-update选项：trivy image --skip-db-update nginx:1.16。  
  
trivy只下载漏洞数据库语法为：  
```
[root@etcd2 ~]# trivy image --download-db-only
```  
  
检测redis镜像漏洞。  
```
[root@etcd2 ~]# trivy image redis | head2022-06-16T17:38:18.504+0800	INFO	Detected OS: debian2022-06-16T17:38:18.505+0800	INFO	Detecting Debian vulnerabilities...2022-06-16T17:38:18.520+0800	INFO	Number of language-specific files: 0redis (debian 11.2)===================Total: 108(UNKNOWN: 0, LOW: 63, MEDIUM: 18, HIGH: 16, CRITICAL: 11)┌──────────────────┬──────────────────┬──────────┬───────────────────┬─────────────────────────┬──────────────────────────────────────────────────────────────┐│     Library      │  Vulnerability   │ Severity │ Installed Version │      Fixed Version      │                            Title                             │
```  
  
检测nginx镜像漏洞。  
```
[root@etcd2 ~]# trivy image nginx | head2022-06-16T17:38:35.172+0800	INFO	Detected OS: debian2022-06-16T17:38:35.172+0800	INFO	Detecting Debian vulnerabilities...2022-06-16T17:38:35.189+0800	INFO	Number of language-specific files: 0nginx (debian 11.2)===================Total: 202(UNKNOWN: 1, LOW: 93, MEDIUM: 43, HIGH: 41, CRITICAL: 24)┌─────────────────────┬──────────────────┬──────────┬────────────────────┬─────────────────────────┬──────────────────────────────────────────────────────────────┐│       Library       │  Vulnerability   │ Severity │ Installed Version  │      Fixed Version      │                            Title                             │
```  
  
注意Trivy 漏洞报告格式默认是表格。  
```
[root@etcd2 ~]# trivy image -f table nginx:1.16
```  
  
Trivy 漏洞报告格式也可以设置为JSON格式（-f）， -o指定输出打印到文件里。  
```
[root@etcd2 ~]# trivy image -f json -o results.json nginx:1.16
```  
# 六.总结  
  
Trivy是一款功能强大、易于使用的容器镜像安全漏洞扫描工具。通过在docker环境下的实践，我们了解到Trivy可以有效地检测容器镜像中的安全漏洞，帮助我们保障应用的安全性。  
  
致力于一条龙式的为您解决问题  
  
链接：https://www.cnblogs.com/renshengdezheli/p/18261192  
  
**（版权归原作者所有，侵删）**  
  
****  
马哥亲授🔥大模型公开课！「驯服」AI 的底层逻辑 + 实战公式  
  
✅摸透 AI 逻辑：解析语义机制，结构化提需求  
  
✅精准操控 AI：示例教学 + 角色设定 + 规则限定  
  
✅破解复杂任务：追问深挖 + 指令链串联  
  
4月29日下午16:00在线直播，提升效率，干货满满，别错过！  
  
![](https://mmbiz.qpic.cn/mmbiz_png/UkV8WB2qYAkibSLtx2MRia79mst2UzCvnzKria9oBcehVeC9xF1dSq5A5I8DzHtUR06xmNRqTX1ic1bqodSyr9jMvA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/UkV8WB2qYAlzgyVsAuLGBAYISN8q3gvEsaG9bqIKTk0kJshKvFJx6Vuv4h9C4aMM4ibY6tanxBWBVSDIT8nNJmg/640?wx_fmt=jpeg&from=appmsg "")  
  
****  
  
