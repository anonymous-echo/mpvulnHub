#  DeepSeek 大火下的本地部署问题：Ollama + 暴露端口 = 安全漏洞？   
 实战安全研究   2025-02-15 02:00  
  
## 全民热议的 AI 新星：DeepSeek 的火爆现象  
  
春节前夕，DeepSeek 在科技界与大众生活中掀起了一股热潮。其影响力广泛覆盖各个群体，从致力于科技创新的科技工作者，到处于知识启蒙阶段的小学生，上至专注于学术研究的科研人员，下至日常忙于生活琐事的普通百姓，DeepSeek 已然成为众人皆知的热门话题。  
  
这款具备免费使用特性的深度思考 AI，凭借其卓越的功能，为人们的工作效率提升带来了显著的积极影响。在性能表现方面，它能够与国际知名的 OpenAI 相媲美，展现出了强大的技术实力和应用潜力。  
  
随着 DeepSeek 的广泛传播和高度关注，许多人开始对其进一步的应用产生了浓厚兴趣，尤其是如何在本地进行大模型的部署。网络上相关的教程大量涌现，为有需求的用户提供了丰富的学习资源和操作指南。  
  
任何一个搜索引擎或者是社交软件，搜索DeepSeek都是铺天盖地的本地搭建教程或者是使用指南。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLWQuPj5icBia6MjTWOZj8BBbIA4Pns5ibUjBSQL3sOkazD8XareBZRElmA/640?wx_fmt=png&from=appmsg "")  
## 本地部署的兴起：IP地址泄漏？显卡“白嫖”？  
  
我从谷歌、微信公众号、抖音、小红书等多个平台搜索本地部署教程，发现大多数本地图形化部署教程都与olloma有关。  
  
Ollama是一个强大的开源框架，主要用于在本地机器上便捷地部署和运行大型语言模型（LLM）。Ollama旨在简化在Docker容器中部署大型语言模型的过程，使得非专业用户也能方便地管理和运行这些复杂的模型。问题的关键在于Ollama 服务的端口（默认为11434），用户如果在公网部署ollama，并且不加以限制，那么攻击者就可以在网络空间测绘上轻而易举地发现众多暴露在互联网上的 Ollama 11434 端口。  
  
这里我尝试搜索公网上的olloma端口  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLa0B1Zv5m8PFRRcBXgl3D0ud48k51ly9C4hw2AcWdF2CGCqwqceDiawg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLzib8DraOcDcsTwCqBFFnmzQnqUgoQoP0zsial5Th4Dr6H5Kj1CmFHqwQ/640?wx_fmt=png&from=appmsg "")  
  
大概有7w条IP。随便访问一下，可以看到ollama正在运行  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLaz5V3UhzN4vVeLfAa3MzmzV0ticpbBx5G7hUmcCXZwelJshWNOe03qQ/640?wx_fmt=png&from=appmsg "")  
## 安全隐患：被忽视的风险  
  
这种ollama直接暴露在公网，我们其实是可以直接调用的，以其中一个为例子:  
  
我们先使用以下命令调用一下目标本地有哪些模型  
```
curl http://ip:11434/api/tags | jq

```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLLibH0gPBuvD5mnsDpbd9dkhar1Ws9vPReXbiaZqgnDs6Q08UnYicicwmcg/640?wx_fmt=png&from=appmsg "")  
  
可以部署了一个1.8B的r1。  
  
使用以下格式发起一次会话。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLULsxJxEEvQ4q4hVxT3uwTKamQINaqvYreibEq8Z8vJAXlPuMTDXEibng/640?wx_fmt=png&from=appmsg "")  
  
甚至可以将他的 ip 配置到任意一个 chatbot  
  
![](https://mmbiz.qpic.cn/mmbiz_png/OPGiamZ2dJeW5VyzmDWxU0KjqwicG7mLOLN9Ax3qeyrXKGsqsdsMfhbYYWwiaJEfjnVBWMXj9Wib8m8lPsBeffVCeA/640?wx_fmt=png&from=appmsg "")  
  
然后就可以无损、免费对话了。  
  
这里我没有随便的去调用别人的ollama，建议大家也不也去随便调用。  
## Ollama 完全不能用了吗？  
  
相对安全做法：将 Ollama 只监听本地地址export OLLAMA_HOST=127.0.0.1  
。或者做好防火墙策略。  
### Linux 系统防火墙策略设置  
#### 1. 使用 iptables（适用于较旧的 Linux 发行版）  
- 允许本地 127.0.0.1 访问 11434 端口：  
  
```
sudo iptables -A INPUT -s 127.0.0.1 -p tcp --dport 11434 -j ACCEPT

```  
- 阻止其他所有 IP 访问 11434 端口：  
  
```
sudo iptables -A INPUT -p tcp --dport 11434 -j DROP

```  
- 保存规则，不同发行版保存方式不同，例如在 CentOS 中可以使用：  
  
```
sudo service iptables save

```  
#### 2. 使用 firewalld（适用于较新的 Red Hat、CentOS 等发行版）  
- 允许本地 127.0.0.1 访问 11434 端口：  
  
```
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="127.0.0.1" port port="11434" protocol="tcp" accept'

```  
- 阻止其他所有 IP 访问 11434 端口：  
  
```
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" port port="11434" protocol="tcp" reject'

```  
- 重新加载防火墙规则：  
  
```
sudo firewall-cmd --reload

```  
#### 3. 使用 ufw（适用于 Ubuntu 等发行版）  
- 允许本地 127.0.0.1 访问 11434 端口：  
  
```
sudo ufw allow from 127.0.0.1 to any port 11434

```  
- 阻止其他所有 IP 访问 11434 端口：  
  
```
sudo ufw deny 11434

```  
- 启用 UFW：  
  
```
sudo ufw enable

```  
### Windows 系统防火墙策略设置  
#### 1. 打开 Windows 防火墙  
- 按下 Win + R  
 组合键，输入 wf.msc  
 并回车，打开“高级安全 Windows Defender 防火墙”。  
  
#### 2. 创建入站规则  
- 在左侧面板中，右键点击“入站规则”，选择“新建规则”。  
  
- 在“规则类型”中选择“端口”，点击“下一步”。  
  
- 选择“TCP”，并指定“特定本地端口”为 11434，点击“下一步”。  
  
- 选择“允许连接”，点击“下一步”。  
  
- 根据需要选择适用的网络位置，点击“下一步”。  
  
- 为规则命名，例如“允许本地访问 11434 端口”，点击“完成”。  
  
#### 3. 配置规则作用范围  
- 右键点击刚刚创建的规则，选择“属性”。  
  
- 在“作用域”选项卡中，在“远程 IP 地址”部分，选择“这些 IP 地址”，点击“添加”，输入 127.0.0.1  
 ，点击“确定”。这样就只允许本地 IP 地址访问 11434 端口。  
  
#### 4. 创建阻止规则（可选）  
- 重复上述创建入站规则的步骤，但在“操作”步骤中选择“阻止连接”，并在“作用域”中不指定特定 IP 地址，这样可以阻止其他所有 IP 访问 11434 端口。  
  
## 自查指南  
  
检查是否只监听本地命令:netstat -an | grep 11434  
, 应该只看到127.0.0.1:11434  
的监听，而不是0.0.0.0:11434  
。  
  
  
