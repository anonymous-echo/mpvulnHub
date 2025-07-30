> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&mid=2649788736&idx=1&sn=d928c3059c6a5c78864232be6184cb05

#  Open VSX 漏洞重创扩展生态，数百万开发者面临供应链劫持  
 安全客   2025-06-27 06:46  
  
近日，Koi Security 安全研究团队披露了一个严重的供应链漏洞：开源项目 **Open VSX Registry（open-vsx[.]org）**  
存在关键安全缺陷，攻击者若成功利用该漏洞，将有可能完全控制**整个 VS Code 扩展市场**  
，进而**控制数百万开发者终端**  
，风险级别可比肩历史上最严重的供应链事件。  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4yfQuRus2fOLgnDWM526K0Zt07mvF1K0RtH8cf6pAhFj3icoXpkd1qgkx856fCndqicAsEjub5KYZA/640?wx_fmt=png&from=appmsg "")  
  
  
**01**  
  
**一个 CI 问题，撬动整个扩展生态**  
  
  
Open VSX Registry 是 Eclipse 基金会主导的开源替代方案，广泛集成于 Cursor、Gitpod、Google Cloud Shell Editor、Windsurf 等多款主流开发工具中。由于其承载着开发者每日依赖的 **VS Code 扩展发布任务**  
，其安全性堪比“包管理系统中的中枢节点”。  
  
  
Koi Security 研究员 Oren Yomtov 指出，漏洞源自 Open VSX 官方维护的 publish-extensions 仓库，该仓库负责管理所有自动发布扩展的配置与流程。开发者只需向仓库中的 extensions.json 文件提交 PR 添加自己的扩展，即可纳入自动化发布流程。一旦 PR 被审核合并，GitHub Actions 会每日在 UTC 时间 03:03 启动任务，读取该 JSON 文件中列出的扩展名，并通过 vsce npm 包将其发布至 open-vsx.org。  
  
  
问题出现在该 GitHub Actions 工作流的执行逻辑中。该流程运行时**加载了特权凭据****——即拥有发布和覆盖任意扩展权限的 @open-vsx 服务账号令牌（OVSX_PAT）**  
：  
  
  
“理论上，这个令牌只应暴露在受信任的代码路径中。但实际流程中，工作流在执行 npm install 时，会运行所有扩展及其依赖中的构建脚本，而这些脚本能访问到环境变量 OVSX_PAT。”  
  
  
这意味着攻击者可通过控制某个被自动发布的扩展或其依赖（例如提交一个带恶意构建脚本的 npm 包），在构建过程中**静默窃取该特权令牌**  
。一旦成功获取 OVSX_PAT，攻击者将获得对 Open VSX Registry 的**完全控制权限**  
，能够任意发布新扩展、覆盖既有扩展，甚至批量注入后门代码分发至全球开发者终端，造成系统性供应链入侵。  
  
  
该漏洞于5月4日通过标准披露流程提交给官方，历经多轮审查与修复，最终于6月25日完成漏洞闭环。尽管目前尚无实际被利用迹象，但考虑到其具备**“可静默入侵 + 自动传播 + 高权限部署”**  
的天然优势，业内对其潜在风险的担忧不容忽视。  
  
  
Yomtov 强调：“Open VSX 被攻陷，是一场供应链噩梦。每一个扩展安装动作，每一次后台自动更新，实际上都是一次对攻击者的隐秘授信。”  
  
  
**02**  
  
**IDE 插件：被忽视的持久化入口**  
  
  
IDE 插件本质上是“**以高权限运行的不受监管软件包**  
”。虽然长期以来，它们被默认为安全工具的组成部分，但攻击者显然正在转向这类隐蔽却高效的攻击面。  
  
  
MITRE ATT&CK 框架已于 2025 年 4 月新增 “IDE Extensions” 技术分类，明确将其纳入**持久化、权限提升与隐蔽访问路径之一**  
，说明其威胁性已获得战术层级的认可。  
  
  
从 PyPI、npm、Huggingface 到 VS Code 插件市场，所有面向开发者的生态平台，都在成为攻击者眼中的“供应链金矿”。但与主流包管理系统相比，IDE 插件市场的**审查流程仍明显滞后**  
，漏洞治理与生态安全机制尚未建立行业共识。  
  
  
IDE 插件往往是开发者最依赖的“效率工具”，但其安全边界却长期缺失审视。当“高权限 + 自动更新 + 免审核”成为常态，任何一个插件都可能演变为隐蔽的远控后门，构建出一条无人知晓的攻击链。  
  
  
此次 Open VSX 漏洞事件，再次提醒行业：在现代软件开发流程中，插件不是辅助工具，而是供应链的一部分；不是开发者的个人选择，而是企业系统的一道潜在后门。  
  
  
企业安全团队应将 IDE 扩展纳入软件物料清单管理，强化构建与发布环节的最小权限原则，严格控制自动化工作流中敏感凭据的暴露风险。同时，需建立完善的插件来源验证机制和安全审计流程。开源平台应推动引入“零信任”构建环境，实现构建过程与执行环境的隔离，防止未经授权的代码执行，切实筑牢供应链安全防线。  
  
  
消息来源：  
  
https://thehackernews.com/2025/06/critical-open-vsx-registry-flaw-exposes.html  
  
  
推荐阅读  
  
  
  
  
  
<table><tbody><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-shadow: rgb(0, 0, 0) 0px 0px 0px;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">01</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788715&amp;idx=1&amp;sn=412ab987accc4c3fb36e94c9f496aa3e&amp;scene=21#wechat_redirect" textvalue="160亿登录凭证泄露" data-itemshowtype="0" linktype="text" data-linktype="2">160亿登录凭证泄露</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">02</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="-webkit-tap-highlight-color: rgba(0, 0, 0, 0);margin: 0px;padding: 0px;outline: 0px;color: rgb(87, 107, 149);text-decoration: none;-webkit-user-drag: none;cursor: default;max-width: 100%;font-family: &#34;PingFang SC&#34;, system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 12px;font-style: normal;font-variant-ligatures: normal;font-variant-caps: normal;font-weight: 400;letter-spacing: 1px;orphans: 2;text-align: justify;text-indent: 0px;text-transform: none;widows: 2;word-spacing: 0px;-webkit-text-stroke-width: 0px;white-space: normal;background-color: rgb(255, 255, 255);box-sizing: border-box !important;overflow-wrap: break-word !important;" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788722&amp;idx=1&amp;sn=de75400767615e978695a98613796da8&amp;scene=21#wechat_redirect" textvalue="OpenVPN驱动曝严重漏洞" data-itemshowtype="0" linktype="text" data-linktype="2">OpenVPN驱动曝严重漏洞</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr><tr style="box-sizing: border-box;"><td data-colwidth="100.0000%" width="100.0000%" style="border-width: 1px;border-color: rgb(62, 62, 62);border-style: none;box-sizing: border-box;padding: 0px;"><section style="box-sizing: border-box;"><section style="display: flex;flex-flow: row;margin: 10px 0% 0px;justify-content: flex-start;box-sizing: border-box;"><section style="display: inline-block;vertical-align: middle;width: auto;min-width: 10%;max-width: 100%;height: auto;flex: 0 0 auto;align-self: center;box-sizing: border-box;"><section style="font-size: 14px;color: rgb(115, 215, 200);line-height: 1;letter-spacing: 0px;text-align: center;box-sizing: border-box;"><p style="margin: 0px;padding: 0px;box-sizing: border-box;"><strong style="box-sizing: border-box;"><span leaf="">03</span></strong></p></section></section><section style="display: inline-block;vertical-align: middle;width: auto;flex: 100 100 0%;align-self: center;height: auto;box-sizing: border-box;"><section style="font-size: 14px;letter-spacing: 1px;line-height: 1.8;color: rgb(140, 140, 140);box-sizing: border-box;"><p style="white-space: normal;margin: 0px;padding: 0px;box-sizing: border-box;"><span style="color: rgb(224, 224, 224);box-sizing: border-box;"><span leaf="">｜</span></span><span style="font-size: 12px;box-sizing: border-box;"><span leaf=""><a class="normal_text_link" target="_blank" style="" href="https://mp.weixin.qq.com/s?__biz=MzA5ODA0NDE2MA==&amp;mid=2649788729&amp;idx=1&amp;sn=9235813f9e50371baa5407d0aebb6609&amp;scene=21#wechat_redirect" textvalue="美国签证新规要求申请人公开社交媒体账户" data-itemshowtype="0" linktype="text" data-linktype="2">美国签证新规要求申请人公开社交媒体账户</a></span></span></p></section></section></section><section style="margin: 5px 0%;box-sizing: border-box;"><section style="background-color: rgb(224, 224, 224);height: 1px;box-sizing: border-box;"><svg viewBox="0 0 1 1" style="float:left;line-height:0;width:0;vertical-align:top;"></svg></section></section></section></td></tr></tbody></table>  
  
  
**安全KER**  
  
  
安全KER致力于搭建国内安全人才学习、工具、淘金、资讯一体化开放平台，推动数字安全社区文化的普及推广与人才生态的链接融合。目前，安全KER已整合全国数千位白帽资源，联合南京、北京、广州、深圳、长沙、上海、郑州等十余座城市，与ISC、XCon、看雪SDC、Hacking Group等数个中大型品牌达成合作。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4yfQuRus2fOLgnDWM526K08wOS5vzHpqy5LPlVwAHGqhLnZaD8YpSGxSnONcYDjITaNXF3fJQhmA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/Ok4fxxCpBb4yfQuRus2fOLgnDWM526K0Uuv1jQPwh6y0srol3IgAe9oiaOMdM5LjBCE5uZFsDb00NSkRibLw9ZicA/640?wx_fmt=png&from=appmsg "")  
  
**注册安全KER社区**  
  
**链接最新“圈子”动态**  
  
