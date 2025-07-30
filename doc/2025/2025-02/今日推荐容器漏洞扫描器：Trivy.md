#  今日推荐容器漏洞扫描器：Trivy   
原创 Wuli王蜀黎  三沐数安   2025-02-14 05:22  
  
### 目录  
- 介绍  
- 安装  
- 扫描 Git 存储库  
- 扫描容器镜像  
- 扫描文件系统  
- 扫描正在运行的容器  
- 在 Dockerfile 中嵌入 Trivy  
### 介绍  
  
**Trivy 是aqua security**开发的一款开源工具，用于扫描漏洞和配置错误。该工具可在多个层面发挥作用：它可以评估基础设施即代码、检查容器镜像、提供配置文件帮助、分析 Kubernetes 实现以及审查 Git 存储库中的代码。由于易于使用，只需安装并将二进制文件添加到项目中，即可轻松将其集成到 CI/CD 管道 (DevSecOps) 中。Trivy 提供跨编程语言和操作系统包的完整可见性，并拥有广泛的漏洞数据库，可快速扫描关键 CVE。该工具的各种新进展帮助渗透测试人员和网络安全研究人员确保持续扫描，从而使 DevSecOps 流程更快、更高效。  
  
  
### 安装  
  
安装非常简单。按照下面给出的命令从你的 ubuntu 机器上的官方存储库安装 Trivy。  
```
sudo apt-get install wget apt-transport-https gnupg lsb-release
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main | sudo tee /etc/apt/sources.list.d/trivy.list
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicaY1WcOoueJ0Oibp4QPoTNNSicdbB0jwZ8qhsv2fMKibtt547mvQRs1TSaQ/640?wx_fmt=png&from=appmsg "")  
```
sudo apt-get 更新
sudo apt-get 安装 trivy
```  
  
安装并更新该工具后，您就可以扫描文件了。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicakbrGuSc2icODoCib1EuYDiajk1n2Y6vEE0lpeAEPgTrF0RgBicfzUIHE3g/640?wx_fmt=png&from=appmsg "")  
### 扫描 Git 存储库  
  
****正如我上面所描述的，我们可以使用 trivy 来扫描多个平台之间的安全漏洞。  
  
 如果您正在使用 Git 存储库，则可以直接扫描 git 文件而无需下载整个包。  
```
sudo trivy repo https://github.com/appsecco/dvna
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicaFe5kgcoiaoYZ58ZcibCJ5gsYVxj4bgv3HcbNFOTkuriaoNUgAdPwOUsRA/640?wx_fmt=png&from=appmsg "")  
### 扫描容器镜像  
  
随着对 Docker 安全的威胁日益增加，Trivy 是市场上用于扫描容器镜像的最佳工具之一。   
  
您可以按照以下步骤轻松地对 docker 镜像进行快速扫描以报告任何漏洞。  
  
步骤1：检查需要扫描的容器镜像的镜像ID。  
```
sudo docker images
```  
  
步骤2：使用下面给出的命令扫描容器镜像。  
```
sudo trivy image 4621d4fe2959
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicaibIvPgLOSXH8lorZazQ7clNntea85rbRdPTc9XLicm88myoVrQDXDqvQ/640?wx_fmt=png&from=appmsg "")  
  
您还可以扫描图像以查找特定严重程度的漏洞，并使用以下命令以文本格式保存报告。  
```
sudo trivy image --severity HIGH 4621d4fe2959 > result.txt
tail result.txt
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4Tica8ialzyco2YknYzt3QHdsEAnW1XIrltU4ibDpS5yH83WXTB3OICPAfH4Q/640?wx_fmt=png&from=appmsg "")  
  
### 扫描文件系统  
  
Trivy 可用于扫描文件系统（例如主机、虚拟机映像或解压的容器映像文件系统）。  
  
（注意：我们在此实际使用文件系统中的易受攻击的节点。）  
  
使用下面给出的命令扫描任何文件系统是否存在漏洞。  
```
trivy conf services/
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicaSyEwMicdNEglWZZQz5DWd9ngCaCguT5emC26hf8oRInXaSkElWR8HicA/640?wx_fmt=png&from=appmsg "")  
### 扫描正在运行的容器  
  
您可以从内部快速扫描正在运行的容器。按照以下步骤扫描 docker 文件。  
  
步骤1：运行要扫描的docker文件。  
```
sudo docker run -it alpine
```  
  
步骤2：将Trivy扫描器添加到文件并运行它。  
```
apk add curl \
&& curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin \    && trivy filesystem --exit-code 1 --no-progress /
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicaAwDto1FmTlmHfS5HIPpblA53chI0BndCXCqYegtVukQ5zdCjYXudVQ/640?wx_fmt=png&from=appmsg "")  
### 在 Dockerfile 中嵌入 Trivy  
  
您还可以通过将 Trivy 嵌入 Dockerfile 中来扫描镜像作为构建过程的一部分。此方法可用于更新当前使用 Aqua 的 Micro 扫描仪的 Dockerfile。按照以下步骤在构建 docker 文件时对其进行扫描。  
  
步骤1：将trivy添加到docker文件中。  
```
FROM alpine:3.7
 RUN apk add curl \
    && curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/master/contrib/install.sh | sh -s -- -b /usr/local/bin \
    && trivy filesystem --exit-code 1 --no-progress /
```  
  
****步骤2：构建图像。  
```
sudo docker build -t vulnerable image .
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicaK1Svq2ViaChTBRTFWGuUENdTs4GXJDSVMTZlcrVcxLmoqJ1xk1ezkicg/640?wx_fmt=png&from=appmsg "")  
  
它将在构建镜像时扫描docker文件并给出如下所示的报告。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Szloeso1r8jiauuW7MxalXTGTM6yq4TicajzFRia6pxcLa1wibMHOYqPDGicSOHpjo9UPCsAZ71GaZutKB0FjXduXcQ/640?wx_fmt=png&from=appmsg "")  
  
  
  
