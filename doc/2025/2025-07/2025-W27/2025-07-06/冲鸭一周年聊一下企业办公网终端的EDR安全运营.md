> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzkyOTc0NDY2Nw==&mid=2247485266&idx=1&sn=fa7586fab518f5e8a727016fd4e4c41d

#  冲鸭一周年:聊一下企业办公网终端的EDR安全运营  
原创 为了安全鸭  冲鸭安全   2025-07-06 07:37  
  
## 前言  
  
不知不觉,在安全行业干了4年整了,所以今天不聊技术,聊一下安全运营.众所周知,鸭哥在戎码负责开发EDR的同时还要负责内网运营和情报运营。  
如何给领导(以下都叫做客户,因为作为安全运营人员,领导就是自己的客户)提供安全感,是每个安全运营都需要学会的东西。  
只聊一下终端,其他设备还没经验,以后万一有业务了有经验了再聊。  
## EDR运营三要素  
  
内网EDR的运营我总结出有三要素或者叫做三指标需要参考:  
1. 误报率  
  
1. 数据源采集能力  
  
1. 性能  
  
**误报率**  
是目前首当其冲的需要考核的东西.因为误报率直接和运营成本挂钩,值得注意的是,我们需要警惕测评作弊行为,表现为,平时一套规则,测评另外一套啥都告警的规则,主打100%过测评.但是实际误报率未知.  
包括ATT&CK测评你可以看到很多Configuration Change:  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmiaspgBYIcdtUdNr09pwoYDzbVgb7BDRjlLdwUS8nhN3M3OtFSy93kSg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJm6rf0NYPkXSxBWX5em9cj4B6icYC9y7YkqQQrE3sNdB3jZUllmBI0NPQ/640?wx_fmt=png&from=appmsg "")  
  
实际上,有验收能力的甲方可能更希望自己收获的是货真价实的产品,高误报率会产生告警疲劳,疲劳了就会导致,只有特殊时期演练的时候才看一眼设备,**所以误报率其实是一个很好的检测EDR指标.**  
  
目前来说,我们的告警精准度在1w台日活里面,每天只产生20左右条告警,AI优化后,实际10-15条确定威胁左右。  
做到这种程度没有乱七八糟的高科技,实际上非常简单,一个简单的金字塔模型,从下到上分别是,日志采集->威胁行为->告警行为->威胁事件**而这些其实都叫做,ATT&CK架构**  
https://attack.mitre.org/  
### 日志采集(DataSource)  
  
DataSource is all you need.  
现代安全架构,日志是安全运营唯一需要的东西**.如果内网不够安全,说明日志采集能力不够**  
.windows终端这块,一般来说黑科技比较多,Macos和Linux就比较中规中矩.  
而采集这块我们需要按照att&ck模型来归类,而不是拿所谓的进单点行为进行归类。  
att&ck强调的是**数据源**  
（DataSource)  
https://attack.mitre.org/datasources/  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmACtfrRpibE8jMtk5iaky2jLib8OOs1Go0ibHuOjicX8ve0yhvklYyep5uBw/640?wx_fmt=png&from=appmsg "")  
  
  
很多人喜欢把 数据源 和自己 能检出的技术 混在一起了,比如 有人说, 我能采集 远程线程注入/我能采集内存加载,  
而这两个实际上只属于 Process 这一类  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmowyhribVd5pdwdImibTFh4ia74LfpViapNPj8KVXPjXyPuDRU2dmqwCl5A/640?wx_fmt=png&from=appmsg "")  
  
比如远程线程注入,在process的数据源的位置:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmc21jUicY0kr7C6EicKHGwOiblVbEdKibL4hgaglucn3Z9IvQg9GjcPibg2A/640?wx_fmt=png&from=appmsg "")  
  
反射代码加载,在process的数据源的位置  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmy4hsmoNu1sj4yCot9mO1JkaFfB84DVXUqia4P3iawB1XrFM7zMz4jfwg/640?wx_fmt=png&from=appmsg "")  
**因此在我看来,他们都属于一类,不应该为了显得自己多而拆成两个。**  
DataSource的好处是,我们可以量化指标,以及知道自己需要采集什么,数据源能映射的攻击技术有什么.如果EDR无法检出某些威胁/误报很多,**只说明一种可能性,数据源不够.**  
### 威胁行为 (Techniques/Tactics)  
  
传统单条日志告警,跟hips没任何区别,甚至是做的不如一些传统安全软件的单步hips.比如执行whoami,执行net.exe 这算威胁吗.不算,所以这些不能告警.而是叫做敏感行为:  
  
而这些本质上是日志采集上来后,直接过原始规则得到的.类似于单步主防的日志,原始日志在这一步,被映射为对于的TA和T了.比如这是翼龙的EDR日志,已经是映射为T的结果.  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmoXlDax6EIBVtlj2W31xbjqtKcNYBpNFapZxYOgWcr0fRGrgqlMdfmw/640?wx_fmt=png&from=appmsg "")  
  
### 进程告警  
  
在对日志进行ATT&CK矩阵映射后,这一部分已经过滤了70%的日志了,剩下的30%日志我们将会与进程绑定在一起,并且做中高低排序,这样我们就实现一个进程告警.  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmaT7ciaalBsMdg6S5ibd9NpYppibhSDXMvWov2KibOU9hZ6iczfyI9fkZqJA/640?wx_fmt=png&from=appmsg "")  
  
通常来说,传统主防模型这一步就结束了,我们有进程,我们有恶意行为,可以愉快展示告警了.而实际上,这并没有结束.实际中,会发现很多误报,告警依然海量,会有很多广告软件,流氓软件造成告警,并且我们会遇到跟传统主防一样的问题:被断链/被各种乱七八糟的DCOM/RPC/鼠标模拟/白利用/白加黑绕过进程链防护.因此,我们需要更进一步  
### 威胁事件(TTPS)  
  
到现在这一步,为了最终解决问题,我们需要TTPS的加入,TTPS更简单来说,是主机行为关联,主机链  
单个威胁告警,并不是告警,而TTPS则是确认威胁的最佳实战.举个例子:  
1. 单个浏览器访问恶意域名/某个软件写自启动,这并不是一个有效的威胁事件,可能第一个是不小心访问到了,这在内网非常常见,不小心访问到钓鱼网站但是实际没下到任何东西.软件自启动也是,可能就是单纯的安装某个软件.  
  
1. 用户访问恶意域名后,下载某个软件,窃取了凭据,进行了回连 ->这个是恶意攻击.  
  
我们以实际银狐来举例:  
  
用户执行下载:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmIIPKCxBOqARO3g0nU9JLxQjHflKFhuy0QnjlLKuJbnu5BibTgj0gVSA/640?wx_fmt=png&from=appmsg "")  
  
IOC检出到恶意域名/IP访问  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmO2Cn4cYCwLBYJxuicGkue8w8zOhNBQkhsSErJSOj0SjZSy3tILb6NyA/640?wx_fmt=png&from=appmsg "")  
  
行为检出到svchost出现异常行为:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJm1gP44INt06NPshKu5tdJWW45Fnc8uJC5NoM18Kdr54gUenxXch77pw/640?wx_fmt=png&from=appmsg "")  
  
services收到了远程RPC指令(很明显,银狐用了pipe管道写服务):  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmsXias5RztI0KvWXdePZrLaepW5fyJBbuP7mvYTpzibsiaD1eaHibhGNgTg/640?wx_fmt=png&from=appmsg "")  
  
那么连在一起,我们确定了是一个恶意攻击:  
  
你可以最开始由explorer启动,然后发了RPC创建了服务并且注入到系统进程里面.整个过程几个阶段.由不同的攻击技术和进程链组合在一起,最终组成主机链,从而确定告警,这些单独出现不代表有恶意攻击,比如svchost行为异常有可能是某些输入法/流氓软件引起的,访问恶意域名也有可能是用户不小心访问到.杀毒告警可能是误报:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmOWbV3PPbWPcLlJHicZKowmLdsnuMhHXMAMwEOojHdBPMavdwGzzzKaA/640?wx_fmt=png&from=appmsg "")  
  
  
TTPS如下:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJm33VhHVb0WsEdJzyYvodib35X46Vkg7la9S0Ro31eMib1YhcAtSNEpzsQ/640?wx_fmt=png&from=appmsg "")  
  
根据行为/进程告警,然后聚合TTPS,我们很清晰的看到了整个事情发生过程,也不需注入svchost/service调用I_RpcBindingInqLocalClientPID或者用什么手段hook alpc一套API这种做法去做所谓的RPC解密,  
> 说实在的,我挺讨厌这种注入拿RPC信息的事情,因为RPC进程是系统服务进程,一旦hook时机有问题崩溃了就很容易造成蓝屏,即便是蓝屏概率只有1%,自己客户有100万台终端下也很恐怖,而且RPC的结构体每个系统都会有一些改变,此外这样会让EDR有严重攻击面能被致盲甚至是漏洞利用  
  
  
结论: 以攻击覆盖阶段为指标的告警,由于主机链,TTPS的存在,能解决以上说的断链/告警误报太多的问题.这也是为什么我们推崇这玩意的原因.完美符合ATT&CK最佳实战.  
### 性能  
  
一个现实是,EPP等传统杀毒软件是没办法拦截未知病毒的,反而会因为过多的hips导致卡系统,这很合理,因为hips是同步的,而同步实现原理是本来多核的事件强行变成单核处理(采集到信息->卡住->弹窗等用户), 这一个过程先不说会不会造成bug  
实际来看,这种主动拦截会非常影响系统,也会影响业务,如果业务无人值守,被hips拦了.  
  
因此就会造成一个问题,未知的威胁,hips拦不住,已知的威胁,杀毒都能杀了.  
  
**因此最佳实战是,纯异步发送日志检出,在不影响任何业务的情况下,发送给服务端让服务端做**  
  
实在想要拦截一点东西的话,在不影响业务的情况下,根据业务可以设置确定性病毒拦截点,比如盗取浏览器凭据/盗取微信聊天记录是确定性的,可以直接拦截部分.但不能使用所谓通用主防逻辑.否则只有一个后果: 用户投诉卡慢.或者业务出现崩溃.  
## 低成本,低预算  
  
上面是通用逻辑,让我们继续运营逻辑,我们不要聊乱七八糟的虚无的某些PPT特有的AI+乱七八糟概念,这种对读者毫无意义。  
让我们从实际出发,这几年学到的唯一概念是,如何低成本运营好内网是一个非常好的学问  
  
让我们逐步拆分  
### 合理运用AI  
  
对大模型最佳实战是,根据内网业务微调.  
  
因为实际上大部分的AI模型并不是网络安全模型,也不了解业务,也不了解公司内网情况,比如有机器是IIS的机器,不能出现iis启动cmd的情况,有机器是样本沙箱,所以会有告警但是需要忽略,所以微调是最佳实战.  
  
业务微调: 首先由人工标注内网中的机器-进程-事件-推理过程-结论，去除敏感信息后, 对模型进行微调, 一般来说，每积攒500事件可以进行一次微调。重点强调让AI知道内网中的进程是干什么的,比如内网有自研的云盘,AI需要知道,嗯这个是自研云盘,行为是这样是正常的,那样是被漏洞利用了.  
  
持续不断坚持微调,可以收获一个基于业务数据而来的大模型,这个模型知道内网情况/知道业务情况,也知道EDR的各个告警是什么意思,哪些可能是误报,这是非常不错的,就如同上面说的银狐,AI在五分钟内研判出是银狐:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmnNHzBwW0icSo2VKE2RafeuRTiacaKuCCXIVzJs8COxQzqia8jgUeM6Pww/640?wx_fmt=png&from=appmsg "")  
  
  
误报也能很快的排除并且报告:  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmX4xCAf7f1sib7iaeahufHQWDZmwrJCtg8g7uXlKd8oerONS3G2gzoeug/640?wx_fmt=png&from=appmsg "")  
  
  
但是局限性也很大,token不能太多,告警不能有迷惑性,否则幻觉,这也是我为什么说不能迷信AI的原因,因为现在的模型并不能完全代替人,**幻觉后+自动处置等会导致非常大的危害.**  
 因此我从来不考虑给AI接所谓的MCP服务器,搞自动IOC查询,自动出报告.现在AI能辅助研判并就已经很不错了.  
  
不过也可能因为我们内网模型微调的是14b/32b的,等以后有资源了搞几百B的看看咋说.但是这就回到标题:  
  
低成本,低预算,但是很安全  
#### 不迷信AI  
  
不过注意,我们不要迷信任何AI自动化,AI确实可以帮助我们一部分,但是不是全部,个人认为所谓的AI Auto Agent,自动化流水线都没必要.  
  
原因很简单,如果告警不精准,采集数据不够多,AI能做什么?做自动kibana搜索?搜出来的数据没有什么用,换句话说,没有菜,厨子再好也做不出来东西.  
### 低成本,低预算  
  
在低误报高检出的情况下,一个14B的模型就能负责接近3-5W台终端的监控,原因无他,它只需要处理EDR出来的事件即可,并且是7x24小时,而剩下的就是接web hook导入到第三方推送里面.成本也只需要,一张2080或者5500元国补的MAC Pro  
## 威胁狩猎  
  
虽然大部分安全事件能及时推送,但是还是有少部分是做不到生成事件的，这部分安全问题可能会被漏掉。  
所以我们要保持一个原则,即 内网透明 这里不讨论管控,只讨论检出。  
### 遥测模块  
  
合格的EDR要区分出遥测模块(给安全专家看的)和前台模块  
前台模块,顾名思义,各种所谓的告警,部分已经标注的T的日志在前台展示  
  
但是这并不是EDR的全部能力,有些日志因为容易误报,或者容易被攻击者学习到绕过技术,并不会展示在前台.  
  
这部分会放到遥测模块中,遥测模块每家合格的EDR/EPP都有,比如MDE/PA/CS/defender/卡巴斯基 在所有个人PC上都有遥测模块,他们的EPP并不关心你是不是真的成功绕过了他们的EPP,因为你不是企业用户.他们只需要做在你”绕过”他们的时候,上传关于木马的全部信息并且给后台威胁狩猎人员进行打猎即可.  
  
这回到了我们一开始说的, EDR的核心能力是数据源采集,不是某个单点行为报不报得出来,单点行为只是日志加一点规则的事情,而日志采集能力非常重要.  
  
而威胁狩猎,就是对前台黑客不可见的数据进行打猎.寻找出隐藏的攻击.  
### 内网文件信誉系统  
  
一个很遗憾的事实是, 在真的EDR的数据面前, 乱七八糟的免杀 没啥意义.  
  
另外一个遗憾的事实是,一部分APT不会跟BAS一样,乱戳告警,不会有乱七八糟的内存加载/sleepmask/bof/乱七八糟的行为  
而是直接golang/rust + ollvm一波偷文件,偷数据,或者beacon.dll直接上线链接socket,这些一般来说不会对EDR产生任何告警.因为他确实没做其他的行为,读取文件很常见,链接网络也很常见.  
  
**为了检测这种攻击,作为运营人员,需要对内网通过EDR构建一个内网的可执行文件的信誉系统.**  
即,每天内网新增X可执行文件,也不需要丢沙箱。因为我们自己是EDR,重点检查X可执行文件的行为.并且标记为可信/不可信/待观察.  
  
**一万台在线终端处理得当一天也就几百个新可执行文件**  
大部分都是一样的文件更新.可以批量处置掉,人是可以处理过来的. 特殊时期可以直接不可信文件落地推送告警。业务开发机器可以按目录排除。  
以上这些基本上能做到,未知文件4小时分析完毕并且推送.  
此外我们可以优化整个流程,根据EDR日志,使用如下手段,做到**10**  
分钟内分析出文件是否安全:  
1. fuzzhash  
fuzzhash是文件相似度匹配的hash算法,能找出相似的文件  
我们可以把文件全部统一过fuzzhash,找出是否是内网已知的文件,这边推荐使用的是ssdeep,如果有VT账户,还能直接找VT上相似的文件。跟历史文件相似直接pass  
  
1. 观察规则  
很好理解,我们可以只调查是否有联网的文件,是否有RPC请求的文件,是否读了敏感数据的可执行文件.不过注意这些观察规则不要直接暴露,安全讲究的就是博弈对抗.小黑认为自己成功绕过了edr,其实一切都在掌握之中.这也是国外主流overwatch干的事情.  
  
1. Malware Query Engine  
crowdstrike领先优秀的点除了客户端外,还有一个原因是他们的服务端大数据玩的好,比如他们的Malware Query Engine(下面叫做MQE)能做到内网文件秒级yara查询狩猎。  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmaykwJRWnz8gadbBQjNFGeKZSKqCmRTkiblGhLJqSq6KIia0psH6vrnqg/640?wx_fmt=png&from=appmsg "")  
  
对于未知文件能做到秒级分析,检查同类有没有被别的安全人员标记过可能是什么文件.  
  
通过以上手段,这样APT/小黑各种乱七八糟的sleepmask/致盲/unhook/各种乱七八糟的loader  
在运行之前就已经上传信息到安全人员的手里了.剩下的只需要观察具体行为就能确定是否是攻击.**特殊时期,整个过程做的好的不超过10分钟.就能发现所谓的免杀木马.**  
### 内网流量信誉系统  
  
这对于流量设备很困难,因为流量设备信息不够,没办法建立流量信誉,但是对于EDR,非常容易.我们只需要建立流量基线就行,一个hash表即可  
  
可执行文件信息-可执行文件信誉-访问的IP/域名  
  
这样我们能快速筛选出,低信誉文件+访问的网络情况.从而建立一个内网流量信誉系统.不过一般来说,效果对于银狐很好,对于演练木马不太可以,因为演练木马会走合法域名上线。建议有人力的时候这样干。  
### 私有IOC生产  
  
  
在确定攻击流程后,我们就可以生产自己的IOC,比如如下是一个未知的新型攻击,其他家的平台标记未知,而我们通过TTPS,狩猎和文件信誉系统确定是新的钓鱼攻击,可以看到释放浏览器插件,盗取凭证等恶意攻击行为:  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmBQlaIngIwvnpTLt0xlLIBfNacSEZnfwHlNgBT1VCcHibn4owibTvn2WA/640?wx_fmt=png&from=appmsg "")  
  
确定后,我们就可以产生IOC,并且全网加黑.确保不会出现第二次攻击.  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ejibWMxI7nWLc8BxZu46XjDWuiad2LcbJmHWAkyAUCrPlOk3DNn4ufktttd4obg2Ll1DRicyM0VR3icOMmIfHzwI0w/640?wx_fmt=png&from=appmsg "")  
  
IOC的生产是非常重要的指标,要记住,EDR的作用是检测未知攻击,而产生IOC是可以很好的衡量EDR的标准,如果EDR全靠已知IOC指标,代表这个EDR就是一个EPP.  
### 其他狩猎  
  
威胁狩猎说起来很复杂很多  
  
比如我们可以查看内网中有多少文件是从微信来的并且执行的从而确定是钓鱼文件,可以看是否有模拟鼠标的操作点击了微信确定是不是有人远控法东西,有驱动动态加载是不是漏洞驱动利用,编写MQE的语句搜索未知文件是否是以前的木马,这些都是线索.  
  
我们就不展开进行讨论了.这块在国外有专门的行业,也有相关的课程.  
感兴趣可以私信我单独开一章介绍.  
### 总结  
  
EDR的运营需要实现所谓的闭环,就是  
  
发现已知IOC->直接拦截  
  
发现未知IOC但是产生了事件告警->AI研判->人工确定->分析报告->修正AI的结果用于下次微调->产生IOC  
  
定时(每天/每周/每月)通过遥测模块进行人工内网狩猎->调整规则->产生IOC->修正AI的结果用于下次微调  
  
文件信誉系统/网络信誉系统用于提醒安全人员快速分析.做到30分钟内响应高级威胁(APT)  
## 题外话:  
### 成本控制: 自研vs购买  
  
2025年,自研EDR非常容易,按照我的理解,假设我在甲方,自研windows平台的话我会考虑:  
1. 用sysmon  
  
1. 再接个golang的写的代码,用ETW搜集数据  
  
1. 再做个内存扫描的,导入yara做内存扫描  
  
1. 再接个TI-ETW  
  
1. 可以的话OEM一个杀毒引擎,比如比特梵,再接个威胁情报IOC,不可以也无所谓  
  
1. 以上日志全部导入到ES里面  
  
整套成本不到1W.当然对人要有开发经验,开发周期大概1-3个月左右.但是终究是自研,效果有限.不过检出银狐/演练木马绰绰有余.  
这边建议预算20W以内可以直接考虑自研究  
### 不要搞对抗  
  
这很容易理解,用户电脑并不是战场,更何况这不是外挂软件,搞太多对抗只有一个结果,蓝屏.  
  
大部分方案都是保守的,比如漏洞驱动利用检测,完全可以通过HOOK导入表去判断是不是漏洞驱动,但是在国内环境就是不能这样干,这样干引发的后果会非常严重.  
  
因此不要在终端搞对抗.  
  
  
