#  Group3r：一款针对活动目录组策略安全的漏洞检测工具   
Alpha_h4ck  FreeBuf   2025-01-08 10:56  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR38jUokdlWSNlAjmEsO1rzv3srXShFRuTKBGDwkj4gvYy34iajd6zQiaKl77Wsy9mjC0xBCRg0YgDIWg/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
  
**关于Group3r**  
  
  
## Group3r是一款针对活动目录组策略安全的漏洞检测工具，可以帮助广大安全研究人员迅速枚举目标AD组策略中的相关配置，并识别其中的潜在安全威胁。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Ss9pGh5mF1017p8zV2fejpgHnsOviaSbh7bGj5U6BjKfGhJk5vCwJ7xnTfDQTyXibdSmsWszgVIEg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
Group3r专为红蓝队研究人员和渗透测试人员设计，该工具可以通过将 LDAP 与域控制器对话、解析域 SYSVOL 共享中的 GPO 配置文件以及查看 GPO 中引用的其他文件（通常在文件共享上）来实现这一点，例如脚本、MSI 包、exe 等。  
  
  
**工具安装**  
  
  
  
**源码获取**  
  
  
广大研究人员可以直接使用下列命令将该项目源码克隆至本地：  
```
git clone https://github.com/Group3r/Group3r.git
```  
  
  
然后使用最新版本的Visual Studio打开项目代码，然后根据操作系统架构完成代码编辑即可。  
###   
### 发布版本  
  
  
我们还可以直接访问该项目的  
Releases页面  
下载最新版本的Group3r。  
##   
  
**工具使用**  
  
  
> -s：将结果发送到标准输出；  
> -f group3r.log：将结果发送到文件；  
> -u domain\user：将使 Group3r 尝试执行文件权限检查，就像以该用户身份运行一样；  
> -w：将限制输出仅显示具有相关“发现”的设置；  
> -a 4：将限制输出仅包含严重程度最高的发现；  
> -e仅显示已启用的 GPO、策略类型和设置；  
  
##   
  
**工具运行演示**  
  
  
## 输出读取  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Ss9pGh5mF1017p8zV2fejabGmlc3Q0PF2JcuhgzzboibTkljQj97hwbbmiahtKjsWy1oEooz1ial0A/640?wx_fmt=jpeg&from=appmsg "")  
  
  
用红色突出显示的位是组策略对象 (GPO)。该部分的顶部栏会告诉您它是一个 GPO、GPO 的显示名称 ( testgpo123)、GPO 的唯一标识符（括号中的位）以及 GPO 是当前的还是“已变形的”。此时可以获得有关 GPO 本身的一些基本信息，包括它链接到哪些 OU（如果有）。  
  
  
用粉红色突出显示的位是一个设置，块侧面的缩进和小 ASCII“尾巴”是为了更容易看到它与上面的 GPO 相关联。顶部栏标识它是一个设置，以及它是什么类型的设置。在本例中，它是一个 MSI 包，被推送到计算机以安装 PuTTY。  
  
用绿色突出显示的位是发现，顶部栏中的颜色是分类级别，使用与 Snaffler 相同的级别 - 绿色、黄色、红色和黑色。  
  
### 发现的设置示例  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Ss9pGh5mF1017p8zV2fejeCzCiawwKQFhyvsiaiaVqXtoYOdYCehBKx7xyLSkW8jYIaR6cjfnyJTuA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
在这个例子中，我们可以看到，由于域用户被添加到目标计算机上的 BUILTIN\Administrators，因此出现了一个发现。  
  
****### 发现的启动脚本设置  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR39Ss9pGh5mF1017p8zV2fejICNmxkPUyKQynKCHJibGFWHCD1W26CuglVHxppw6nBEia9zuAEf1hhzg/640?wx_fmt=jpeg&from=appmsg "")  
  
  
其中的脚本参数看起来像硬编码的密码。  
##   
  
**许可证协议**  
  
  
  
本项目的开发与发布遵循  
GPL-3.0  
开源许可协议。  
##   
  
**项目地址**  
  
  
  
**Group3r**：  
  
  
https://github.com/Group3r/Group3r  
  
  
【  
FreeBuf粉丝交流群招新啦！  
  
在这里，拓宽网安边界  
  
甲方安全建设干货；  
  
乙方最新技术理念；  
  
全球最新的网络安全资讯；  
  
群内不定期开启各种抽奖活动；  
  
FreeBuf盲盒、大象公仔......  
  
扫码添加小蜜蜂微信回复「加群」，申请加入群聊】  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/qq5rfBadR3ich6ibqlfxbwaJlDyErKpzvETedBHPS9tGHfSKMCEZcuGq1U1mylY7pCEvJD9w60pWp7NzDjmM2BlQ/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&retryload=2&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR3ic5icaZr7IGkVcd3DT6vXW4B4LOZ1M7YkTPhS1AT2DQJaicFjtCxt5BRO7p5AOJqvH3EJABCd0BFqYQ/640?wx_fmt=other&from=appmsg&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
  
  
  
  
  
  
[](https://mp.weixin.qq.com/s?__biz=MjM5NjA0NjgyMA==&mid=2651253272&idx=1&sn=82468d927062b7427e3ca8a912cb2dc7&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/qq5rfBadR3icF8RMnJbsqatMibR6OicVrUDaz0fyxNtBDpPlLfibJZILzHQcwaKkb4ia57xAShIJfQ54HjOG1oPXBew/640?wx_fmt=gif&wxfrom=5&wx_lazy=1&tp=webp "")  
  
