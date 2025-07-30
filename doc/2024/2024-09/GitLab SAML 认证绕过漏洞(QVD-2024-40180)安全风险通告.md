#  GitLab SAML 认证绕过漏洞(QVD-2024-40180)安全风险通告   
 奇安信 CERT   2024-09-19 16:16  
  
●   
点击↑蓝字关注我们，获取更多安全风险通告  
  
<table><tbody style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="center" rowspan="1" colspan="4" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);background-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 255, 255);letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;">漏洞概述</span></strong><br style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"/></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">漏洞名称</span></strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">GitLab SAML 认证绕过漏洞</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" rowspan="1" colspan="1" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;">漏洞编号</strong></span></p></td><td valign="middle" align="left" rowspan="1" colspan="3" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">QVD-2024-40180</span><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;caret-color: rgb(255, 0, 0);letter-spacing: 0.544px;text-align: justify;visibility: visible;">,CVE-2024-45409</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">公开时间</span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">2024-09-17</span></p></td><td valign="middle" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">影响量级</span></strong></span></p></td><td valign="middle" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">百万级</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">奇安信评级</span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;"><span style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">高危</span></strong></span></p></td><td valign="middle" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;cursor: text;color: rgb(0, 0, 0);caret-color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;, sans-serif;visibility: visible;max-inline-size: 100%;outline: none 0px !important;">CVSS 3.1分数</strong></span></strong></span></p></td><td valign="middle" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;caret-color: rgb(255, 0, 0);font-size: 13px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">10.0</span></strong></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">威胁类型</span></strong><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"></span></strong></span></p></td><td valign="middle" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">安全特性绕过</span></p></td><td valign="middle" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">利用可能性</span></strong></p></td><td valign="middle" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">高</span></strong></span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">POC状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;color: rgb(0, 0, 0);letter-spacing: 0.544px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);letter-spacing: 0.544px;visibility: visible;">未公开</span></span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;letter-spacing: 0.544px;font-family: system-ui, -apple-system, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);letter-spacing: 0.544px;visibility: visible;"></span></span></strong></span></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">在野利用状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">未发现</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="1" rowspan="1" align="left" width="136" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">EXP状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="157" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);line-height: 1em;visibility: visible;letter-spacing: 0.544px;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);letter-spacing: 0.544px;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;letter-spacing: 0.544px;visibility: visible;">未公开</span></span><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-size: 13px;letter-spacing: 0.544px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(255, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);letter-spacing: 0.544px;visibility: visible;"></span></span></strong></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="169" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;visibility: visible;">技术细节状态</span></strong></span></p></td><td valign="middle" colspan="1" rowspan="1" align="left" width="95" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;color: rgb(0, 0, 0);font-family: 微软雅黑, &#34;Microsoft YaHei&#34;;font-size: 13px;letter-spacing: 0.544px;visibility: visible;">未公开</span></p></td></tr><tr style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><td valign="middle" colspan="4" rowspan="1" align="left" style="-webkit-tap-highlight-color: transparent;outline: 0px;word-break: break-all;hyphens: auto;border-color: rgb(70, 118, 217);visibility: visible;"><p style="-webkit-tap-highlight-color: transparent;outline: 0px;line-height: 1em;visibility: visible;"><strong style="-webkit-tap-highlight-color: transparent;outline: 0px;visibility: visible;"><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;visibility: visible;">危害描述：</span></strong><span style="-webkit-tap-highlight-color: transparent;outline: 0px;font-size: 13px;letter-spacing: 0.544px;visibility: visible;">攻击者可以利用 GitLab 中的 SAML 认证机制中的漏洞绕过认证，通过创建特制的 SAML 响应来非法获取对 GitLab 实例的访问权限。</span></p></td></tr></tbody></table>  
  
  
**0****1**  
  
**漏洞详情**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响组件**  
  
GitLab 是一款用于仓库管理的开源项目，它提供了一整套工具来帮助开发团队进行项目管理、代码托管、持续集成/持续部署（CI/CD）、监控、以及更多的功能。  
  
**>**  
**>**  
**>**  
**>**  
  
**漏洞描述**  
  
近日，奇安信CERT监测到官方修复**GitLab SAML 认证绕过漏洞(QVD-2024-40180)**，由于GitLab对 SAML 响应的不当处理，使得攻击者可以插入任意值，攻击者从而通过构造特定的 SAML 响应，绕过 GitLab 实例的身份验证机制，无需正确的凭证即可访问受保护的资源。**鉴于该漏洞影响范围较大，建议客户尽快做好自查及防护。**  
  
****  
**02**  
  
**影响范围**  
  
**>**  
**>**  
**>**  
**>**  
  
**影响版本**  
  
GitLab CE/EE 17.3.* < 17.3.3  
  
GitLab CE/EE 17.2.* < 17.2.7  
  
GitLab CE/EE 17.1.* < 17.1.8  
  
GitLab CE/EE 17.0.* < 17.0.8  
  
GitLab CE/EE < 16.11.10  
  
**>**  
**>**  
**>**  
**>**  
  
**其他受影响组件**  
  
无  
  
**03**  
  
**受影响资产情况**  
  
奇安信鹰图资产测绘平台数据显示，**GitLab SAML 认证绕过漏洞(QVD-2024-40180)**关联的国内风险资产总数为1372328个，关联IP总数为24944个。国内风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49yeocNzVvnZpvCYok6GjdzgJ4Fn5jk7ibyY6qyugTFqRwYlyBNbBDAENt5MoNkgb0B0Vdq7OzEBew/640?wx_fmt=png&from=appmsg "")  
  
**GitLab SAML 认证绕过漏洞(QVD-2024-40180)**关联的全球风险资产总数为1577166个，关联IP总数为55582个。全球风险资产分布情况如下：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs49yeocNzVvnZpvCYok6Gjdzn1KuWQia2Lmsibibc9bfib3VsZG46mvLmABGZ3ZYasdh15cWFZRwJ4ibfvA/640?wx_fmt=png&from=appmsg "")  
  
  
**04**  
  
**处置建议**  
  
**>**  
**>**  
**>**  
**>**  
  
**安全更新**  
  
  
将依赖项 omniauth-saml 更新至 v2.2.1 、ruby-saml 更新至 v1.17.0。  
  
目前官方已有可更新版本，建议受影响用户升级至最新版本：  
  
GitLab CE/EE 17.3.* >= 17.3.3  
  
GitLab CE/EE 17.2.* >= 17.2.7  
  
GitLab CE/EE 17.1.* >= 17.1.8  
  
GitLab CE/EE 17.0.* >= 17.0.8  
  
GitLab CE/EE >= 16.11.10  
  
官方补丁下载地址：https://about.gitlab.com/update  
  
**临时缓解方案：**  
  
为 GitLab 上的所有用户启用 GitLab 双因素身份验证并不勾选 SAML 双因素绕过选项。  
  
  
**05**  
  
**参考资料**  
  
[1]https://about.gitlab.com/releases/2024/09/17/patch-release-gitlab-17-3-3-released/  
  
  
**06**  
  
**时间线**  
  
2024年9月19日，奇安信 CERT发布安全风险通告。  
  
  
  
**07**  
  
**漏洞情报服务**  
  
奇安信ALPH  
A威胁分析平台已支持漏洞情报订阅服务：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BY9IJ0MPzeiashvK2XLpdl3XtTtCD91h0jS26fqvuWpEMXgmXa85qLkoA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "漏洞订阅上线.png")  
  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/3tG2LbK7WG3tezJEzJsicLSWCGsIggLbcfk4LB5WK7pdSwMksxPOAoHuibjQpBlEId4nyIIw52n2J8N8MowYZcjA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "")  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/EkibxOB3fs4ibpFEkqfMZfO3smS6RKd9BYBVaibvBq1vXprZIc191LXKibdiaApA16q3UgmibQDv4yW09qT88J3jRUfA/640?wxfrom=5&wx_lazy=1&wx_co=1&wx_fmt=other&tp=webp "CERT LOGO.png")  
  
**奇安信 CERT**  
  
**致力于**  
第一时间为企业级用户提供**权威**漏洞情报和**有效**  
解决方案。  
  
  
点击↓**阅读原文**，到**ALPHA威胁分析平台**  
订阅更多漏洞信息。  
  
