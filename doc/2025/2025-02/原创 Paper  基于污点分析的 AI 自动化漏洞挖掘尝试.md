#  原创 Paper | 基于污点分析的 AI 自动化漏洞挖掘尝试   
原创 404实验室  知道创宇404实验室   2025-02-20 02:43  
  
**作****者：longofo@****知道创宇404实验室**  
  
**时间：2025年2月16日**  
  
**本文为知道创宇404实验室内部分享沙龙“404 Open Day”的议题内容，作为目前团队AI安全研究系列的一部分，分享出来与大家一同交流学习。**  
  
**1.概述**  
  
  
参考资料  
  
本文是受Protect AI的vulnhun  
tr项目[1]的  
启发，结合自己的经验做的另一种AI挖洞的尝试，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9je8ZibalK0qkDQicRZ2CBlTIcfq3fwGiaqZFPJRO4PUP0WTsGfxmC6CQt5w/640?wx_fmt=jpeg&from=appmsg "")  
  
与vulnhuntr思路不同的是，我们先逆向找到sink到source的链路，再利用AI做Source到Sink的正向污点分析来检测和判断整个链路的连通性。当然这种方式只适用于调用链不是很深的常规漏洞挖掘，因为链路查找如果不做污点分析，对于反序列化利用链这种情况会延伸出很多无效链路，肯定是不现实的。后面我也设计了V2版本来适配做反序列化利用链的查找，但是用AI测试的效果并不好，不过只是一种尝试罢了。  
  
为什么想用AI做污点分析？  
  
最初的想法：用AI做污点传递连通性检测可能更有优势，它的知识量很大而且很智能，根  
据网页版交互使用体验和测试，它有时候确实能给你惊喜，所以做了下去。  
  
**2.调用链查找-工具端-V1版**  
  
  
参考资料  
  
由于做Java方面多一些，对编译后的字节指令和源代码更熟练一点，后续部分都是以Java语言为例。  
### 2.1 整体设计  
  
大致分为两部分，一部分处理类信息库，一部分做反向搜索链的查找，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9je1hW0KucYwM8oFQeTbWW0h1CIqV7GDARNtUFQtzBElezia2O3TQPmpFQ/640?wx_fmt=jpeg&from=appmsg "")  
  
类信息库处理：  
- 源代码：AST方式，优点是AI可能识别和处理效果好一点，缺点是信息的补全处理以及需要人工模拟栈调用  
  
- 字节码：ASM，当然也可以反编译然后转AST方式，优点是不用补全信息以及栈模拟调用，缺点可能是AI识别和处理可能会差一点？也不一定，得看模型的处理能力  
  
反向调用链查找：  
- Sink规则：可以自己收集，可以从一些开源的、非开源的工具提取  
  
- Source规则：可以是通用的框架、常规入口点，可以是根据实际审计环境自定义入口  
  
- 搜索算法：由于没有做污点分析，Sink->Source就是一直向上找"who call me"，还有就是多态、Object、Collection等特殊情况的处理  
  
- 提示信息：可以为每层调用添加提示AI的信息，例如多线程无显示调用，我在代码中做了关联，需要用提示信息提示AI做对应的处理  
  
### 2.2 为什么要反向找链  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeWuzv9wib8V7Ag2UdkAz4dm0Mic119ibekHibIDR9VCPASqTO97NpB4oYlA/640?wx_fmt=jpeg&from=appmsg "")  
### 2.3 附加提示信息  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeibVZcRKhxkqrkUX0oGWjtvpSl7NQ9VBFcv9tWr20po8b83UNq1r2NPw/640?wx_fmt=jpeg&from=appmsg "")  
  
附加信息可以提示AI做对应的转换处理。  
  
**3.链路连通性检测-AI端-V1版**  
  
  
参考资料  
#### 3.1 整体设计  
  
由于目前Java对AI处理的适配性没有Python、JS好，所以做了API/RPC这种结构，AI端需要的信息从远程Java端进行获取，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeKuOJGQdTXI2zZY3CGXsYTlOzIWRr1WOasnibO0LUzD4UtCQO2h6mnFA/640?wx_fmt=jpeg&from=appmsg "")  
  
整体思路就是从Java端拿到调用链信息，发送携带调用链信息的Request，响应的Response需要哪些信息，就在上一次Request的基础上添加这些信息，如此循环直到AI判断无法继续向下走或者拥有足够的信息能判断最终链路连通。  
### 3.2 Prompt  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9je7SAM3bGVMiaquKiasGUTZp8pAykwao24pQEdRyxoYsxrGG1xQ5fyxDrQ/640?wx_fmt=jpeg&from=appmsg "")  
  
主要就是限定请求模板和相应模板做数据映射和控制，以及具体的分析方法。  
### 3.3 分析方法  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeqpibomX24pfSOnib3Mo1jqiak11XJfrzt20ys5pyoN1ojicUrkXQaSXCQQ/640?wx_fmt=jpeg&from=appmsg "")  
  
这里还可以加入sanitize检测，但是目前AI对sanitize的检测不太行，而且很多bypass方法AI可能还没有人工处理得好，因此这里没有加入。  
  
**4.漏洞演示-V1版**  
  
  
参考资料  
  
这个版本是去年做的，当时XAI的grok线上模型有免费的额度，用之前某cms旧版本做了下小测试，录了个演示视频，可以在此处观看：  
  
  
**5.一个JDK链引发的改版-V2版**  
  
  
参考资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeQfv6jushOZByDYkkspWjwovAg2OoMNWW40T3ykZe8FIzHyBuRhbaJg/640?wx_fmt=jpeg&from=appmsg "")  
  
当时是一个朋友问我，虽然最初的想法本就不是做这种反序列化的利用链的挖掘，但是还是做了下尝试，然后引出了改版以适配做这种反序列化利用链挖掘，如果能适配好有能力挖掘反序列化利用链的能力，那挖常规漏洞更是易如反掌了。  
  
**6.试错-V2版**  
  
  
参考资料  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jenTE5j41kJ7jSOz6f5tYiaPtMCU7cKF472hIxvrNyOt69MKuqlY4fCgg/640?wx_fmt=jpeg&from=appmsg "")  
  
中间做了很多试错的测试，最后得出用每两层之间做污点分析的方法：从上一层->sink，上上层->上一层...，通过使用这种思路，如果sink->上一层的通路都无法进行了，那就没必要继续了。这种方式提前加入污点分析，就能更早中止链路，防止后续无效链路的延伸。  
  
**7.条件控制-V2版**  
  
  
参考资料  
  
为了防止无效链路出现，需要加入更多的条件控制，对于每两层调用，首先要做的就是检测被调用函数，如下图所示：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9je8WbWRiaaXYrWoqZF4VnGZib5hxNzs463wKaWLp6PZscMA8eXLCdsKCiag/640?wx_fmt=jpeg&from=appmsg "")  
  
这里其实是对多态的处理，需要AI根据上下文推测实际的类型，如果没有绑定其他类型并且该处调用是属性对象、参数对象或经过污染的对象调用，那么这个位置才能被认为可以用被调用函数替代。  
  
污点分析的条件控制：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeRvq97NiaPdcu6t5zZdZoDd0NpZch9zk6bDWzI48bbQmJa2Ql7wuaH3g/640?wx_fmt=jpeg&from=appmsg "")  
  
图中红色标记处也是处理多态的情况，只是这是在两层调用之间出现的中间调用。  
  
**8.现实很骨感-V2版本**  
  
  
参考资料  
  
由于控制条件太多，抑或是我的prompt无法准确描述想要的东西，测试过一些本地模型和线上模型，实际效果都不太好：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9je37lYScHGoY560Y7DAP2s2hIFHMfgWPsObUs208rCibBJt537EM0EkgQ/640?wx_fmt=jpeg&from=appmsg "")  
  
后面也想过做条件拆分，在代码中做结果整合，但是很棘手，因为漏洞本身就是需要上下文和条件控制的，仅根据我目前的认知，漏洞挖掘这个场景做条件拆分再组合我实在是很难办到。  
  
**9.结论**  
  
  
参考资料  
  
  
可以看到上面所做的工作，核心的东西都是利用prompt描述做控制，强依赖AI，中间过程具有极其的不稳定性。其实在做V1和V2版本的过程中，我就意识到自己在做一个对标codeql的东西，但是我知道凭我是肯定没办法实现codeql那种效果的，想用几千个文字描述codeql做的东西，确实有些异想天开了，不过较下劲尝试下，毕竟它有时候确实能给你惊喜。经过这一系列折腾，给我的感觉是对于这类条件控制很多或者需要精细处理的场景，AI只有赋能在已经具有稳定性的架构中，核心的东西不能过于强依赖AI，才可能最大的发挥AI的作用以及获得较好的效果。  
  
以上只是本人结合AI做漏洞挖掘粗浅和拙劣认知，AI目前还有很多技术，结合这些技术或许能在自动化漏洞挖掘方面达到期望的效果。  
  
**10.参考链接**  
  
  
参考资料  
###   
  
[1]   
https://github.com/protectai/vulnhuntr  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3k9IT3oQhT0mSRTxbY7fsoLUFViaxk1nhQByibgTdbwbMqNibWMKbHKrjwUUY8GNZlAoUlcic5ibVhyCebVwoNialnow/640?wx_fmt=png&wxfrom=5&wx_lazy=1&wx_co=1 "404 logo-b04.png")  
  
  
**作者名片******  
  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/3k9IT3oQhT0dEG2QiabTxP29gvGmSS9jeWWSSoVYcjFQLqQ27YUqBEE3h73rLJLxrBZvqagGOna2kqlDaBgvicJw/640?wx_fmt=jpeg&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT0Z79Hq9GCticVica4ufkjk5xiarRicG97E3oEcibNSrgdGSsdicWibkc8ycazhQiaA81j3o0cvzR5x4kRIcQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
**往 期 热 门******  
  
(点击图片跳转）  
  
[](https://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650990663&idx=1&sn=d3612bcdf320efdc783e5740d519c69d&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650990591&idx=1&sn=a1f162313bc06603add4797b30daeba3&scene=21#wechat_redirect)  
[](https://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650990418&idx=1&sn=405bbaf00d5b589ebc3756c200afd631&scene=21#wechat_redirect)  
  
  
[](http://mp.weixin.qq.com/s?__biz=MzAxNDY2MTQ2OQ==&mid=2650983547&idx=1&sn=11b495e0560d63b885d206bbb88a9803&chksm=80798e49b70e075f669f6db892034bc0ea5fbca188095b7a5e16c4c5c1fefd70bdc3eea66396&scene=21#wechat_redirect)  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3k9IT3oQhT3XlD8Odz1EaR5icjZWy3jb8ZZPdfjQiakDHOiclbpjhvaR2icn265LYMpu3CmR1GoX707tWhAVsMJrrQ/640?wx_fmt=gif&wxfrom=5&wx_lazy=1 "")  
  
戳  
“阅读原文”  
更多精彩内容!  
  
  
