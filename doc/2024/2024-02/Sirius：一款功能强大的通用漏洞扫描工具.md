#  Sirius：一款功能强大的通用漏洞扫描工具   
Alpha_h4ck  白帽学子   2024-02-17 08:11  
  
##  关于Sirius   
  
  
Sirius是一款功能强大的通用漏洞扫描工具，该工具可以帮助广大研究人员在大多数场景下识别和验证应用程序中存在的安全漏洞。  
  
  
现如今，信息安全社区仍然是收集网络安全情报数据最佳且最有利的来源，而且社区本身的表现经常会优于商业性质的安全供应商，这也是Sirius的主要优势之一。  
  
  
该框架围绕四个通用的漏洞识别概念构建，即漏洞数据库、网络漏洞扫描、基于代理的发现和自定义评估分析。Sirius旨在通过将这些功能整合至一个易于使用的UI接口上，以实现网络安全行业的快速发展。  
##   
##  工具服务   
  
****  
当前版本的Sirius系统由以下几个服务组成：  
  
> 1、Mongo：一个NoSQL数据库，用于存储数据；  
> 2、RabbitMQ：用于管理服务之间通信的消息代理；  
> 3、Sirius API：一个API服务，用于访问存储在Mongo数据库中的数据；  
> 4、Sirius Web：一个Web UI接口，允许用户查看和管理他们的数据管道；  
> 5、Sirius引擎：用于管理数据管道的引擎服务；  
  
##   
##  工具安装   
  
****  
我们建议广大研究人员在Docker环境下安装和使用Sirius，因此我们首先需要在本地设备上安装并配置好Docker容器环境，请注意，一定要安装好docker和docker-compose。  
  
  
接下来，我们可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/SiriusScan/Sirius.git
```  
  
  
然后切换到项目目录中，启动Docker：  
```
cd Sirius

docker-compose up
```  
```
```  
### 登录账号密码  
  
  
Sirius的默认登录用户名和密码如下：  
```
admin/sirius
```  
##   
##  工具使用   
  
  
如需使用Sirius，首先需要通过下列命令启动Sirius的所有服务：  
```
docker-compose up
```  
```
```  
  
  
启动之后，直接打开Web浏览器并访问下列地址即可使用Sirius的Web UI接口：  
```
localhost:5173
```  
  
  
然后只需要按照界面功能提示进行漏洞扫描操作即可。  
###   
### 远程扫描  
  
  
如果你想要在一台远程设备上安装和使用Sirius进行漏洞扫描的话，你需要修改下列文件内容，并填写服务器的详细数据即可：  
```
./UI/config.json
```  
  
  
后台回复：  
**240217**  
，获取工具  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_gif/LYy9xnADcdhic61NkXCWKufScrUrmmsG8tztWD8fDRiatPUaljxxpKc1PpnYNFjPibU5FwJmcuO4mZoQg5aXsAcog/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
声明：该公众号大部分文章来自作者日常学习笔记，也有部分文章是经过作者授权和其他公众号白名单转载，未经授权，严禁转载，如需转载，联系开白名单。  
  
请勿利用文章内的相关技术从事非法测试，如因此产生的一切不良后果与本公众号无关。  
  
✦  
  
✦  
  
