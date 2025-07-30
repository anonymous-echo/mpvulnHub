> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523322&idx=1&sn=33329d3ec49e0f180be0dcedb8cd70a4

#  谷歌 Gerrit 代码平台漏洞可用于供应链攻击，18个谷歌项目受影响  
Guru Baran  代码卫士   2025-06-18 09:48  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/Az5ZsrEic9ot90z9etZLlU7OTaPOdibteeibJMMmbwc29aJlDOmUicibIRoLdcuEQjtHQ2qjVtZBt0M5eVbYoQzlHiaw/640?wx_fmt=gif "")  
   
聚焦源代码安全，网罗国内外最新资讯！  
  
****  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMRSylJK2k7H6mNqiaS2G6WRaeeK34cLHE6pe9VeOIHYiboAnKB0TMoayZCxFpHMLljzTnz9DnNuFiaqQ/640?wx_fmt=png "")  
  
  
  
专栏·供应链安全  
  
  
数字化时代，软件无处不在。软件如同社会中的“虚拟人”，已经成为支撑社会正常运转的最基本元素之一，软件的安全性问题也正在成为当今社会的根本性、基础性问题。  
  
  
随着软件产业的快速发展，软件供应链也越发复杂多元，复杂的软件供应链会引入一系列的安全问题，导致信息系统的整体安全防护难度越来越大。近年来，针对软件供应链的安全攻击事件一直呈快速增长态势，造成的危害也越来越严重。  
  
  
为此，我们推出“供应链安全”栏目。本栏目汇聚供应链安全资讯，分析供应链安全风险，提供缓解建议，为供应链安全保驾护航。  
  
  
注：以往发布的部分供应链安全相关内容，请见文末“推荐阅读”部分。  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTghPYBFyvxYKFqTiaX0lrmPsibhmRmgDiacSKbwpXc6jhbicEO1Vl5VFwqATeYv0eic7HwY2cXLfz7WHw/640?wx_fmt=png&from=appmsg "")  
  
**严重的供应链漏洞 “GerriScary” (CVE-2025-1568) 本可导致攻击者将恶意代码注入至少谷歌的15个主要项目中，其中包括 ChromiumOS、Chromium、Dart和Bazel。**  
  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTghPYBFyvxYKFqTiaX0lrmPv3BcLqYOwcWy2xy3vgwHRyFyX6PIRAeSRWLZoe4ibhcS0B31wjsaDOw/640?wx_fmt=gif&from=appmsg "")  
  
  
该漏洞由Tenable 公司的安全研究员 Liv Matan 发现，它利用谷歌 Gerrit 代码协作平台中的配置不当问题，使未授权用户通过复杂的供应链来攻陷受信任的软件仓库。  
  
GerriScary 利用三个互联组件实现越权代码提交。首先，Gerrit 的默认配置授予所有注册用户 “addPatchSet” 权限，导致任何具有谷歌账户的人员均可修改现有的代码变更。第二，易受攻击项目的“复制条件”设置中包含多个逻辑漏洞，而该设置用于判断此前的代码审计所批准的标签是否携带到新的版本。  
  
而最危险的地方在于利用自动提交机器人的竞争条件。攻击者可识别那些已被“Commit-Queue+2”标签标记为准备自动合并的代码变更，赶在机器人执行合并前的简短窗口期注入恶意代码。在 ChromiumOS 和 Dart 仓库中，该时间窗口持续大约5分钟，而其它谷歌仓库仅提供数秒到数分钟的时间。  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMTghPYBFyvxYKFqTiaX0lrmP8zxmUasiarXCs20iaibm7RcIiboSl914u3dpHPictvic7qQnoERMRNTqHntg/640?wx_fmt=gif&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/oBANLWYScMTghPYBFyvxYKFqTiaX0lrmPAoYFdpFIjG3h2TmqQQYA7EPibYDWIADw9XdGOofEEXlMw8La9FMr1Ww/640?wx_fmt=png&from=appmsg "")  
  
**GerriScary 导致18个谷歌项目被黑**  
  
  
  
Liv Matan 发现，通过在尝试修改提交信息时分析HTTP响应代码，可以对存在漏洞的项目进行指纹识别。返回“209”状态码说明拥有所需权限且不会在项目日志中产生噪音。这一技术可用于大规模扫描谷歌的 Gerrit 基础设施，识别出受影响的仓库。  
  
该供应链的运作方式是，先监控那些已经满足所有要求、可以提交的代码更改，然后与自动化机器人的提交过程进行竞争。当利用代码检测出被标记为 “Commit-Queue+2”的变更时，它将注入恶意补丁，而由于复制条件配置不当，这些补丁依然保留了之前所有的审批，从而导致未经用户交互的未授权代码合并。  
  
该漏洞影响了谷歌多个领域的关键项目，而其中最有影响力的目标是 Chrome OS 设备的基础 ChromiumOS。其它受影响项目包括 Dart（Flutter的编程语言）、Dawn 和 BoringSSL（Chromium的第三方依赖）、Bazel（给个的构建系统）和Gerrit本身。其它易受攻击的仓库还包括 Ceres Solver、Quiche、Android KVM和各种与Linux相关的项目。  
  
Liv Matan 通过成功将无害注释注入 ChromiumOS 项目，演示了该漏洞的影响。为了遵守道德规范，他们并没有在生产环境中测试完整的条件竞争组件。  
  
谷歌迅速响应，采取了多项修复措施，重新配置了受影响项目的标签保留设置，确保新的补丁集都需要重新进行代码审计和验证。另外，ChromiumOS 团队删除了注册用户的 “addPatchSet” 权限，仅供可信的贡献人员使用。虽然谷歌保护了受管理项目的安全，但研究人员提醒称其它使用 Gerrit的机构可能也易受类似攻击。  
  
正确配置“复制条件”的复杂程度表明，配置不当问题可能广泛存在于更宽泛的Gerrit 生态系统中，或导致很多开源项目和企业项目易受供应链攻击。  
  
如下是受影响的项目列表。  
  
<table><thead><tr><td style="border:solid windowtext 1px;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="font-size:15px;"><strong><span style="color: #222222;font-size: 15px;"><span leaf="">项目名称</span></span></strong></span></p></td><td data-colwidth="189" width="189" style="border-top: 1px solid windowtext;border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-image: initial;border-left: none;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="font-size:15px;"><strong><span style="color: #222222;font-size: 15px;"><span leaf="">Gerrit </span></span></strong><strong><span style="color: #222222;font-size: 15px;"><span leaf="">审计</span></span></strong><strong><span style="color: #222222;font-size: 15px;"><span leaf="">URL</span></span></strong></span></p></td><td data-colwidth="175" width="175" style="border-top: 1px solid windowtext;border-right: 1px solid windowtext;border-bottom: 1px solid windowtext;border-image: initial;border-left: none;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="font-size:15px;"><strong><span style="color: #222222;font-size: 15px;"><span leaf="">说明</span></span></strong></span></p></td></tr></thead><tbody><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">ChromiumOS</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://chromium-review.googlesource.com/c/chromiumos</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Chrome OS 设备的基础操作系统</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Dart</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://dart-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">前端编程语言、Flutter应用的骨干</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Dawn</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://dawn-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">WebGPU实现的Chromium第三方依赖</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">BoringSSL</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://boringssl-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">加密操作的Chromium第三方依赖</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">GN</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://gn-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Chromium、 Fuchsia和相关项目使用的构建系统</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Bazel</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://bazel-review.googlesource.com</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">谷歌的主要构建引擎和自动化系统</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Gerrit</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://gerrit-review.googlesource.com/#(/zull/jobs)</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">本身是代码审计平台（/zull/jobs   和   /gcompute-tools 组件）</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Ceres   Solver</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://ceres-solver-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">建模和解决优先级问题的C++   库</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Code   Review</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://code-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">通用代码审计系统，包括Git镜像实现</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Quiche</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://quiche-review.googlesource.com</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">谷歌面向生产环境的QUIC、HTTP/2、 HTTP/3 协议</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Android   KVM</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://android-kvm-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Android 虚拟化运行时环境</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">OpenSecura</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://opensecura-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">AI 硬件骨干基础设施</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">CUE</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://cue-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">数据验证语言和工具</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Linux</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://linux-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">谷歌对开源操作系统的fork</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Plan9port</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://plan9port-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">带有Plan   9 工具和扩展的Unix实现</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Hafnium</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://hafnium-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">提供内存隔离能力的系统组件</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Nginx</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://nginx-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">高性能 web 服务器实现</span></span></p></td></tr><tr style="box-sizing: border-box;"><td style="border:solid windowtext 1px;border-top:none;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">Weave</span></span></p></td><td data-colwidth="189" width="189" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">https://weave-review.googlesource.com/</span></span></p></td><td data-colwidth="175" width="175" style="border-top: none;border-left: none;border-bottom: 1px solid windowtext;border-right: 1px solid windowtext;box-sizing: border-box;padding:5px 10px;"><p style="text-align:left;margin-bottom: 21px;font-size: 15px;text-indent: 0em;"><span style="color: #222222;font-size: 15px;"><span leaf="">网络应用层协议实现</span></span></p></td></tr></tbody></table>  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMTBzmfDJA6rWkgzD5KIKNibpR0szmPaeuu4BibnJiaQzxBpaRMwb8icKTeZVEuWREJwacZm3wElt7vOtQ/640?wx_fmt=jpeg "")  
  
  
开源  
卫士试用地址：  
https://sast.qianxin.com/#/login  
  
代码卫士试用地址：  
https://codesafe.qianxin.com  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
  
**推荐阅读**  
  
[谷歌修复代码测试工具Bazel 中的严重供应链漏洞](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247518821&idx=1&sn=8a1a67b87d1bbad6e1c80390fe7c1c61&scene=21#wechat_redirect)  
  
  
[谷歌推出开源计划GUAC，保护软件供应链安全](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247514298&idx=2&sn=5971ca324b4d2fe15146eefac3a7192c&scene=21#wechat_redirect)  
  
  
[NPM软件供应链攻击传播恶意软件](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523234&idx=2&sn=ac4e0656fd04218349d356761af176dd&scene=21#wechat_redirect)  
  
  
[隐秘的 npm 供应链攻击：误植域名导致RCE和数据破坏](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247523167&idx=2&sn=4249c8e9e0dace01810c665eda52c421&scene=21#wechat_redirect)  
  
  
[在线阅读版：《2024中国软件供应链安全分析报告》全文](https://mp.weixin.qq.com/s?__biz=MzI2NTg4OTc5Nw==&mid=2247520484&idx=1&sn=8a845b39720a318c297075e98f5fe5e0&scene=21#wechat_redirect)  
  
  
  
  
**原文链接**  
  
  
https://cybersecuritynews.com/gerriscary/  
  
  
**本文由奇安信编译，不代表奇安信观点。转载请注明“转自奇安信代码卫士 https://codesafe.qianxin.com”。**  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSf7nNLWrJL6dkJp7RB8Kl4zxU9ibnQjuvo4VoZ5ic9Q91K3WshWzqEybcroVEOQpgYfx1uYgwJhlFQ/640?wx_fmt=jpeg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/oBANLWYScMSN5sfviaCuvYQccJZlrr64sRlvcbdWjDic9mPQ8mBBFDCKP6VibiaNE1kDVuoIOiaIVRoTjSsSftGC8gw/640?wx_fmt=jpeg "")  
  
**奇安信代码卫士 (codesafe)**  
  
国内首个专注于软件开发安全的产品线。  
  
   ![](https://mmbiz.qpic.cn/mmbiz_gif/oBANLWYScMQ5iciaeKS21icDIWSVd0M9zEhicFK0rbCJOrgpc09iaH6nvqvsIdckDfxH2K4tu9CvPJgSf7XhGHJwVyQ/640?wx_fmt=gif "")  
  
   
觉得不错，就点个 “  
在看  
” 或 "  
赞  
” 吧~  
  
  
