#  安全热点周报：谷歌修复了 Android 上被积极利用的 FreeType 漏洞   
 奇安信 CERT   2025-05-12 08:55  
  
<table><tbody><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 4px solid rgb(68, 117, 241);visibility: visible;"><th align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;background: rgb(254, 254, 254);max-width: 100%;box-sizing: border-box !important;font-size: 20px;line-height: 1.2;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;color: rgb(68, 117, 241);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;font-size: 17px;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">安全资讯导视 </span></span></strong></span></th></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">中国人民银行发布《中国人民银行业务领域数据安全管理办法》</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">美国白宫发布2026财年预算提案，拟削减网络安全预算4.91亿美元</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;border-bottom: 1px solid rgb(180, 184, 175);visibility: visible;"><td valign="middle" align="center" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 5px 10px;outline: 0px;overflow-wrap: break-word !important;word-break: break-all;hyphens: auto;border: 0px none;max-width: 100%;box-sizing: border-box !important;font-size: 14px;visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;clear: both;min-height: 1em;visibility: visible;"><span leaf="" style="-webkit-tap-highlight-color: transparent;margin: 0px;padding: 0px;outline: 0px;max-width: 100%;box-sizing: border-box !important;overflow-wrap: break-word !important;visibility: visible;">• </span><span leaf="">巴基斯坦军方声称网络攻击已使印度70%电网瘫痪，印度否认</span></p></td></tr></tbody></table>  
  
**PART****0****1**  
  
  
**漏洞情报**  
  
  
**1.Elastic Kibana原型污染致任意代码执行漏洞安全风险通告**  
  
  
5月7日，奇安信CERT监测到官方修复Elastic Kibana原型污染致任意代码执行漏洞(CVE-2025-25014)，该漏洞源于Kibana中机器学习和报告端点的原型污染问题，攻击者可以通过精心构造的文件上传和特定的HTTP请求绕过验证机制，攻击者利用该漏洞后，可以在受影响的系统上执行任意代码，可能导致数据泄露、系统被完全控制等严重后果。奇安信鹰图资产测绘平台数据显示，该漏洞关联的国内风险资产总数为69619个，关联IP总数为13216个。鉴于此漏洞影响范围较大，建议客户尽快做好自查及防护。  
  
  
**PART****0****2**  
  
  
**新增在野利用**  
  
  
**1.****FreeType 越界写入漏洞(CVE-2025-27363)******  
  
  
5月7日，谷歌发布了针对大量 Android 安全漏洞的修复程序，包括一个被积极利用的零点击 FreeType 2 代码执行漏洞。该漏洞“可能受到有限的、有针对性的利用”。  
  
CVE-2025-27363 是 FreeType 中的一个越界写入漏洞，FreeType 是一个开源软件库，可将字体（即文本）渲染到数字显示器（例如屏幕）上，并可在包括 Android、iOS、macOS 和 Linux 在内的许多平台上使用。  
  
多年来，FreeType 一直是多个安全漏洞的源头，主要是由于使用格式错误的字体文件来利用内存处理。CVE-2025-27363 影响 FreeType 版本 0.0.0 至 2.13.0，并于2025年3月被 Facebook 标记为可能在野利用。  
  
当库的易受攻击版本尝试解析与 TrueType GX 和可变字体文件相关的字体子字形结构时，就会触发安全问题。该公司解释道：该漏洞代码将一个有符号短整型值赋值给一个无符号长整型值，然后添加一个静态值，导致其回绕并分配过小的堆缓冲区。之后，该代码会将最多 6 个有符号长整型值写入缓冲区边界之外。这可能导致任意代码执行。  
  
Facebook 和 Google 均未透露有关此次攻击的更多细节。Google 仅表示，该漏洞可导致本地代码执行，无需额外执行权限或任何用户交互（即可被利用进行“零点击”攻击）。正如 Malwarebytes 的 Pieter Arntz 所指出的，“可以合理地假设，仅仅打开包含恶意字体的文档或应用程序就可能危及您的设备。”  
  
Google 会定期通过 Google Play 系统更新渠道为这些设备提供关键修复，但不能保证为旧设备提供针对被主动利用的漏洞的具体修复。建议使用 Android 13 以上版本的用户考虑使用包含针对不受支持设备的安全修复程序的第三方 Android 发行版，或者迁移到其 OEM 支持的较新型号。要应用最新的 Android 更新，请转至“设置”>“安全和隐私”>“系统和更新”>“安全更新”> 单击“检查更新”。（此过程可能因 OEM/型号而异）。  
  
  
参考链接：  
  
https://www.bleepingcomputer.com/news/security/google-fixes-actively-exploited-freetype-flaw-on-android/  
  
**PART****0****3**  
  
  
**安全事件**  
  
  
**1.巴基斯坦军方声称网络攻击已使印度70%电网瘫痪，印度否认**  
  
  
5月10日综合消息，印度与巴基斯坦冲突现已蔓延至数字领域，两国关键目标面临日益严峻的网络威胁，同时社交媒体上关于冲突情况的虚假消息也日益增多。巴基斯坦媒体报道称，巴基斯坦对印度发动该地区历史上规模最大、最复杂的网络攻击，摧毁了印度数字基础设施的关键目标，涉及能源、电力、铁路、天然气等多个行业的众多目标。巴基斯坦安全部门消息人士当日称，巴基斯坦通过网络攻击导致印度70%的电网瘫痪。印度新闻信息局则驳斥称此消息纯属谣言，并敦促公众保持警惕，避免被此类散布恐慌的帖子所蒙蔽。巴基斯坦黑客组织近日以“萨拉尔行动”为名对印度开展网络攻击，入侵了4个印度网站，下载了数据并篡改网站主页。同时，巴基斯坦多个官方网站和社交媒体账户也疑似遭受网络攻击。  
  
  
原文链接：  
  
https://www.secrss.com/articles/78593  
  
**2.多家企业遭伪造VS Code扩展攻击数据泄露，工信部漏洞平台发布预警**  
  
  
5月8日网络安全威胁和漏洞信息共享平台消息，工业和信息化部网络安全威胁和漏洞信息共享平台（CSTIS）近日监测发现，攻击者频繁利用伪造的VS Code扩展程序对JavaScript和Python开发者实施攻击，已造成多起企业数据泄露及系统被控事件。攻击者在VS Code官方扩展市场及第三方平台部署含基础功能的诱饵程序，随后通过伪造BitBucket协作平台的更新链接，向开发者设备投递加密恶意模块，再利用JavaScript的eval()函数动态解密并执行恶意代码，值得注意的是，该恶意扩展在激活前会智能检测调试环境与安全工具来规避分析。植入成功后，该恶意扩展会窃取源代码、API密钥等敏感信息，并在软件中创建后门，威胁企业信息安全。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/mRz1hqrvYkAMyMLNzS8Utg  
  
**3.美国医疗设备上市公司遭网络攻击，生产制造受影响 交付被迫延后**  
  
  
5月7日Bleeping Computer消息，美国医疗设备上市公司迈心诺（Masimo）发布SEC公告称，受一起网络攻击事件影响，公司制造设施运行水平低于正常状态，暂时难以履行客户订单，目前正在努力恢复受影响网络系统。迈心诺表示，事件发生在2025年4月27日，公司未透露攻击的具体类型，但指出威胁行为者入侵了其本地部署的网络，迫使公司对受影响系统进行隔离。此次披露的网络安全事件对公司的制造与业务运营造成了显著影响。迈心诺指出，事件的具体性质、范围及实际影响仍在调查中，目前尚无法确定是否涉及客户数据，或是否将对本季度财务表现产生影响。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/medical-device-maker-masimo-warns-of-cyberattack-manufacturing-delays/  
  
**4.IPv6网络功能遭APT组织滥用，大量知名软件更新被劫持**  
  
  
4月30日Bleeping Computer消息，欧洲网络安全公司ESET披露，APT组织“TheWizards”滥用了IPv6的某项网络功能发动中间人攻击，劫持大量知名国产软件更新通道以植入Windows恶意软件。据悉，“TheWizards”制作的黑客工具滥用了IPv6的无状态地址自动配置（SLAAC）功能，发送特定流量伪造成网关，从而监听腾讯小米百度等多个公司的域名，劫持软件更新通道投递后门版更新。该组织至少自2022年起就已活跃，攻击目标涵盖菲律宾、柬埔寨、阿联酋、中国大陆及香港的多个实体，受害者包括个人用户、博彩公司以及其他组织。  
  
  
原文链接：  
  
https://www.bleepingcomputer.com/news/security/hackers-abuse-ipv6-networking-feature-to-hijack-software-updates/  
  
  
**PART****0****4**  
  
  
**政策法规**  
  
  
**1.李强主持召开国务院常务会议，审议通过《政务数据共享条例（草案）》**  
  
  
5月9日，国务院总理李强5月9日主持召开国务院常务会议，审议通过《政务数据共享条例（草案）》。会议指出，要在确保数据安全基础上打通数据壁垒，推动公共服务更加普惠便捷。要构建全国一体化政务大数据体系，推动数据资源融合应用，更好赋能社会治理和繁荣产业生态，增强经济发展新动能。  
  
原文链接：  
  
https://www.gov.cn/yaowen/liebiao/202505/content_7023155.htm  
  
  
**2.中国人民银行发布《中国人民银行业务领域数据安全管理办法》**  
  
  
5月9日，中国人民银行发布《中国人民银行业务领域数据安全管理办法》，自2025年6月30日起施行。该文件共7章56条，包括总则、业务数据分类分级与总体要求、全流程业务数据安全管理要求、全流程业务数据安全技术要求、业务数据安全风险与事件管理、法律责任、附则。该文件要求，业务数据安全工作遵循“谁管业务，谁管业务数据，谁管数据安全”原则，数据处理者应当履行数据安全保护义务，防范业务数据被篡改、破坏、泄露或者非法获取、非法利用等风险。中国人民银行业务领域是指由中国人民银行承担监督和管理职责的货币信贷、宏观审慎、跨境人民币、银行间市场、金融业综合统计、支付清算、人民币发行流通、经理国库、征信和信用评级、反洗钱等业务领域。  
  
  
原文链接：  
  
http://www.pbc.gov.cn/tiaofasi/144941/144957/5702602/index.html  
  
  
**3.自然资源部印发《地理信息数据分类分级工作指南（试行）》**  
  
  
5月7日，自然资源部印发《地理信息数据分类分级工作指南（试行）》。该文件主要内容包括：一是明确地理信息数据分类分级原则。在数据分类、数据分级、目录管理与更新等各环节均应遵循“科学实用、综合判定、动态更新”原则。二是确定数据分类规则。将地理信息数据分为基础地理信息数据、遥感影像数据和专题地理信息数据三大类，大类下再细分若干中类，同时可根据数据管理实际和应用服务场景再细化分类。三是提出数据分级规则。确定了识别地理信息数据分级因素、开展数据影响分析和综合评估定级的分级规则，同时给出了重要数据、核心数据识别的判定指标。四是明确分类分级管理要求。规定了地理信息重要数据目录申报、审核、认定等相关工作程序，以及动态更新情形与更新管理等若干要求。  
  
  
原文链接：  
  
https://mp.weixin.qq.com/s/1fp7LZuUrhUIiH-A5ypMCg  
  
  
**4.强制性国家标准《卫星导航定位基准站网与安全管理要求》公开征求意见**  
  
  
5月6日，自然资源部组织起草了《卫星导航定位基准站网与安全管理要求（征求意见稿）》强制性国家标准，现公开征求意见。该文件规定了卫星导航定位基准站网安全管理的基本要求以及设施、数据和服务的安全要求，包括卫星导航定位基准站网数据中心应配置网络安全防护专用设备和数据安全防护措施，卫星导航定位基准站网的数据处理、服务和管理系统应取得信息系统安全等级保护第三级及以上备案证明，卫星导航定位基准站原始观测数据应采用有线专网或商用密码加密保护后进行传输，卫星导航定位基准站网的其他重要数据应采取用户实名审核注册、鉴权访问控制的方式提供服务，单个基准站提供实时差分定位服务时应采用虚拟基准站技术等。  
  
  
原文链接：  
  
http://gi.mnr.gov.cn/202504/P020250430676626666124.docx  
  
  
**5.美国国防部首席信息官发布《加速安全软件》备忘录**  
  
  
5月5日，美国国防部首席信息官Katie Arrington发布《加速安全软件》备忘录，拟变革国防部软件采购要求，指导制定“软件快速通道”计划。该计划将加强网络安全与供应链风险管理，实施严格的软件安全验证流程，建立安全信息共享机制，通过政府主导的风险评估加快网络安全授权，以实现软件快速采用。首席信息官办公室计划在90天内，制定并提交“软件快速通道”计划的框架与实施方案。  
  
  
原文链接：  
  
https://dodcio.defense.gov/Portals/0/Documents/Library/Memo-AcceleratingSecureSoftware.pdf  
  
  
**6.美国白宫发布2026财年预算提案，拟削减网络安全预算4.91亿美元**  
  
  
5月2日，美国白宫管理和预算办公室向国会提交了特朗普总统2026财年可自由支配预算请求。该文件拟将非国防可自由支配预算削减了1630亿美元，其中网络安全部分削减了4.91亿美元。该文件提出，将美国网络安全与基础设施安全局的核心使命重新聚焦到联邦网络防御和增强关键基础设施的安全性和韧性，取消其打击虚假信息和宣传项目，裁撤国际事务办公室，取消和联邦与州级层面重复的网络安全项目等。  
  
  
原文链接：  
  
https://www.whitehouse.gov/wp-content/uploads/2025/05/Fiscal-Year-2026-Discretionary-Budget-Request.pdf  
  
  
**往期精彩推荐**  
  
  
[Elastic Kibana 原型污染致任意代码执行漏洞(CVE-2025-25014)安全风险通告](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503359&idx=1&sn=3976329cdddd018ab4307524061b68c0&scene=21#wechat_redirect)  
  
  
[安全热点周报：邮件远程代码执行漏洞遭利用，用于攻击日本机构](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503352&idx=1&sn=283ef81dee566006f482ac1dc2eaec42&scene=21#wechat_redirect)  
  
[安全热点周报：黑客精心设计 Craft CMS 漏洞链，用于零日攻击窃取数据](https://mp.weixin.qq.com/s?__biz=MzU5NDgxODU1MQ==&mid=2247503347&idx=1&sn=3e8a4766a143c1ac8b60d02ae3610cc2&scene=21#wechat_redirect)  
  
  
  
  
本期周报内容由安全内参&虎符智库&奇安信CERT联合出品！  
  
  
  
  
  
  
  
