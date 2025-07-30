#  最高可达25万美元！谷歌为 KVM 零日漏洞计划支付巨额奖金   
 网络安全应急技术国家工程中心   2024-07-04 16:08  
  
2023 年 10 月，为提高基于内核的虚拟机（KVM）管理程序的安全性，谷歌推出一项新的漏洞奖励计划（VRP）——kvmCTF。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qq5rfBadR38uOwkolTprFg5U4fmh6gSEd33SmnenyzCegMvWic8I3fnBJiboe70JPMYuj9lTqXBJW699tHJEbSeQ/640?wx_fmt=png&from=appmsg&wxfrom=13&tp=wxpic "")  
  
据悉，KVM 是一个开源管理程序，目前已有超过 17 年的发展历史，是消费者和企业环境中的一个重要组件，为安卓和谷歌云平台提供动力。作为 KVM 的积极和重要贡献者，谷歌开发了 kvmCTF 作为一个协作平台，帮助识别和修复安全漏洞。  
  
与谷歌针对 Linux 内核安全漏洞的 kernelCTF 漏洞奖励计划一样，kvmCTF 的重点是基于内核的虚拟机（KVM）管理程序中的虚拟机可触及安全漏洞，参加该计划的安全研究人员将获得一个可控的实验室环境，以便其展示其捕获可利用安全漏洞的标志。  
  
值得注意的是，与其他漏洞奖励计划不同，kvmCTF 仅仅专注于零日安全漏洞，不会奖励针对已知漏洞的漏洞利用。kvmCTF 的奖励级别如下：  
> 完全虚拟机逃逸：25 万美元；任意内存写入：100000 美元；任意内存读取：50000 美元；相对内存写入：50000 美元；拒绝服务：20000 美元；相对内存读取：10000 美元。  
  
  
谷歌软件工程师 Marios Pomonis 表示，参赛者可以预约访问客户虚拟机的时间段，并尝试执行客户对主机攻击，但是其攻击的目的必须是利用主机内核 KVM 子系统中的零日漏洞。如果攻击成功，「攻击者」将获得一个标志，以证明其成功利用了安全漏洞。kvmCTF 计划会根据攻击的严重程度决定奖励金额的大小。（注意：只有在上游补丁发布后，谷歌才会收到已发现零日漏洞的详细信息，以确保与开源社区同步共享信息）  
  
最后，谷歌方面强调，在开始参与 kvmCTF 计划前，参与者必须查看、了解清楚 kvmCTF 的各项规则，其中包括有关预订时间段、连接到客户虚拟机、获取标志、将各种 KASAN 违规行为映射到奖励层级的信息，以及报告漏洞的详细说明。  
  
**参考资料：**  
  
https://www.bleepingcomputer.com/news/security/google-now-pays-250-000-for-kvm-zero-day-vulnerabilities/  
  
  
  
原文来源  
：FreeBuf  
  
“投稿联系方式：010-82992251   sunzhonghao@cert.org.cn”  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/GoUrACT176n1NvL0JsVSB8lNDX2FCGZjW0HGfDVnFao65ic4fx6Rv4qylYEAbia4AU3V2Zz801UlicBcLeZ6gS6tg/640?wx_fmt=other&wxfrom=5&wx_lazy=1&wx_co=1&tp=webp "")  
  
