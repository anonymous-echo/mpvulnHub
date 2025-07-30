#  AI首次独立发现Linux内核可利用0Day漏洞   
 安全客   2025-05-26 06:45  
  
近日，一个编号为**CVE-2025-37899**  
的**Linux内核0Day漏洞**  
被披露。不同于传统由人类安全研究员或自动化工具挖掘，本次漏洞的发现者是OpenAI 最新发布的大语言模型**ChatGPT o3**  
。该事件引发了业内广泛关注，标志着AI在漏洞挖掘领域的实用能力正**从理论走向现实**  
。  
  
  
漏洞概述  
  
CVE-2025-37899是一个影响Linux内核ksmbd模块的高危漏洞。ksmbd是内核中用于实现SMB协议（Server Message Block）的服务端组件，支持SMBv3版本，主要用于文件共享服务。  
  
  
该漏洞被官方确认为一处use-after-free（释放后使用）类型内存管理缺陷。受影响的版本包括：  
  
  
Linux 6.12.27  
  
Linux 6.14.5  
  
Linux 6.15-rc4  
  
  
虽然根据EPSS（Exploit Prediction Scoring System）的评估，该漏洞的利用概率暂为0.02%，但由于其位于Linux  
内核通信协议栈中，具备较高利用潜力。一旦被利用，可能导致内存破坏，甚至实现内核权限下的**远程代码执行**  
，安全风险不容忽视。  
  
  
技术分析  
  
从漏洞成因来看，CVE-2025-37899涉及SMB协议中logoff命令的并发处理逻辑问题，属于典型的**多线程资源竞争下的use-after-free漏洞**  
。  
  
  
触发流程简要说明如下：  
  
  
1  
  
线程A处理客户端的  
logoff  
请求，在处理过程中会释放  
sess->user  
对象；  
  
2  
  
线程B同时处理另一个连接的  
session setup  
请求，试图绑定至刚刚释放的会话；  
  
3  
  
此时另一个线程访问已被释放的  
sess->user  
指针，形成典型use-after-free情况；  
  
4  
  
攻击者可构造竞态条件，实现内核级内存破坏甚至控制执行流。  
  
  
该漏洞可能导致内核崩溃或服务拒绝，严重影响系统的稳定性，攻击者还可利用内存破坏漏洞构建ROP链，实现任意代码执行，最终可能导致权限提升，甚至实现远程持久化控制，对系统安全构成重大威胁。  
目前研究人员已公开漏洞PoC，建议相关用户及时关注并做好防护。  
  
  
发现路径  
  
本次漏洞由安全研究人员Sean通过**OpenAI o3模型API调用**  
独立发现。  
值得注意的是，他在整个过程中未借助任何模糊测试（Fuzzing）、符号执行框架或静态分析平台，仅依靠**语言模型的自然语言交互能力**  
，完成了漏洞的定位与成因分析。  
  
  
具体使用流程如下：  
  
  
  
Sean向o3模型提供了约3.3k行与ksmbd模块相关的源代码（约合27k tokens），涵盖了会话管理、命令解析及资源回收等关键路径；  
  
  
随后，o3模型深入分析了  
logoff  
命令与  
session setup  
命令在并发执行时的状态共享逻辑；  
  
  
模型准确指出了  
sess->user  
对象存在生命周期管理错误，潜藏use-after-free风险；  
  
  
最后，Sean亲自验证并成功复现该问题，确认其为真实的0Day漏洞。  
  
  
在此之前，Sean以他人工发现的另一个漏洞 CVE-2025-37778（Kerberos认证路径的use-after-free）作为基准，利用该漏洞测试o3模型的分析能力。相关代码片段如下：  
  
```
static int krb5_authenticate(struct ksmbd_work *work,
     struct smb2_sess_setup_req *req,
     struct smb2_sess_setup_rsp *rsp)
{
if (sess->state == SMB2_SESSION_VALID)
ksmbd_free_user(sess->user);
retval = ksmbd_krb5_authenticate(sess, in_blob, in_len,
out_blob, &out_len);
if (retval) {
ksmbd_debug(SMB, "krb5 authentication failed\n");
return -EINVAL;
}
}
```  
  
  
基于该案例，o3 展现出优秀的  
跨路径推理能力，能够识别资源释放与并发访问间的复杂依赖关系。Sean表示：  
  
  
“我没有用任何辅助框架，仅**通过o3 API对代码进行分析**  
，就准确地发现了潜在的逻辑漏洞。就我所知，这是**首例****由大语言模型自主识别并被确认的内核级0Day**  
。”  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/Ok4fxxCpBb7PtlwmMVloJZFVO18VtoNRePzZbbh4CIliaibSv7KeXSiariaEYH9pNtEkCnb83MtpPbJEicKcsm813Vg/640?wx_fmt=jpeg&from=appmsg "")  
  
o3模型作出详细解释  
  
  
这一发现意味着语言模型不仅能理解应用层逻辑，也已具备识别系统级漏洞的能力，突破了以往LLM只能“改代码、写脚本”的能力边界。  
  
  
行业影响  
  
此次事件标志着LLM在安全研究中的作用已从“辅助分析”跃升为“独立发现者”，其带来的深远影响包括：  
  
  
**1. AI在漏洞研究中的角色变化**  
  
从“辅助代码审计”到“主动发现漏洞”，AI已初步具备独立完成部分漏洞发现任务的能力，研究范式正在发生根本变化。  
  
  
**2. 人机协同成为主流模式**  
  
未来漏洞研究可能将更多采用“研究员+AI”协同模式。人类专注于策略与链路设计，AI负责代码路径遍历与模式识别，将大幅提升研究效率。  
  
  
**3. 安全行业工具链升级**  
  
安全厂商和研究机构需加快构建基于LLM的审计平台或插件系统，将大语言模型嵌入审计、测试、自动化挖掘等流程中，形成高效漏洞挖掘闭环。  
  
  
Sean强调：“AI不会取代人类研究员，反而将成为我们效率倍增的工具。未来的漏洞研究，将是你与模型并肩作战。”  
  
  
CVE-2025-37899的发现不仅是一项漏洞披露，更是AI参与网络安全攻防实践的里程碑事件。未来，AI与安全研究人员的深度协同或将成为抵御高级威胁的重要力量。  
  
  
消息来源：  
  
https://cybersecuritynews.com/linux-kernel-smb-0-day-vulnerability/  
  
  
推荐阅读  
  
  
  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">01</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788604&amp;idx=1&amp;sn=066bbc04b94c7168b68915950124fe23&amp;scene=21#wechat_redirect" textvalue="欧盟拟放宽GDPR合规要求" data-itemshowtype="0" linktype="text" data-linktype="2">欧盟拟放宽GDPR合规要求</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">02</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788582&amp;idx=1&amp;sn=74048b618b5cc21908468fc74a9905e8&amp;scene=21#wechat_redirect" textvalue="日本通过法案允许在未明确情况下开展网络攻击行动" data-itemshowtype="0" linktype="text" data-linktype="2">日本允许在未明确情况开展网络攻击行动</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">03</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788611&amp;idx=1&amp;sn=51a79771b544473f3a99698a74809e45&amp;scene=21#wechat_redirect" textvalue="Google加速推进Android无密码化" data-itemshowtype="0" linktype="text" data-linktype="2">Google加速推进Android无密码化</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7PtlwmMVloJZFVO18VtoNRtOx1iclUFzGib5rRJagnsCayUR9K2SRJevRNvKLKj5icicaHKqEf5m30jw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb7PtlwmMVloJZFVO18VtoNR5bdWNAyAytsz7IlgwMKxmibtfTGhPKZpMujjABHJy2utZxXRemCiavOg/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
