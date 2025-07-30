#  About一个高价值漏洞采集与推送服务   
zema1  黑客白帽子   2024-03-13 08:01  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.6636094571400317&random=0.6219011309810436&random=0.21191420540585404 "")  
  
**感谢师傅 · 关注我们**  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0w6V8YUTyNSuV2udfyY3rWyR6V1UeHWuiab6T80I5ldZicZswCnrbicD4ibpaDMqCZ6UvFmhWLyTzptSA/640?wx_fmt=png&random=0.9829534454876507&random=0.2787622380037358&random=0.29583791053286834 "")  
  
  
由于，微信公众号推送机制改变，现在需要设置为星标才能收到推送消息。大家就动动发财小手设置一下呗！啾咪~~~  
  
![](https://mmbiz.qpic.cn/mmbiz_png/PJG3jJlPv0y50hQk1TiaBIAnSjzqkmZcPS4TWvohHfHPTVUBWM2mFxcqwhiaZKaQM6S7t11fuiajZ2zZqXD5hJJmA/640?wx_fmt=png "")  
  
  
众所周知，CVE 漏洞库中 99% 以上的漏洞只是无现实意义的编号。我想集中精力看下当下需要关注的高价值漏洞有哪些，而不是被各类 RSS 和公众号的   
威胁情报 淹没。于是写了这个小项目来抓取部分高质量的漏洞信息源然后做推送。 WatchVuln意为  
监测 漏洞更新，同时也表示这些漏洞需要  
注意。  
  
当前抓取了这几个站点的数据:  
<table><thead><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><th style=" padding: 6px 13px;font-weight: var(--base-text-weight-semibold, 600) ; ; ; ; ; ; ; ; ; ; ; ">名称</th><th style=" padding: 6px 13px;font-weight: var(--base-text-weight-semibold, 600) ; ; ; ; ; ; ; ; ; ; ; ">地址</th><th style=" padding: 6px 13px;font-weight: var(--base-text-weight-semibold, 600) ; ; ; ; ; ; ; ; ; ; ; ">推送策略</th></tr></thead><tbody><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">阿里云漏洞库</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">https://avd.aliyun.com/high-risk/list</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">等级为高危或严重</td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">OSCS开源安全情报预警</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">https://www.oscs1024.com/cm</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">等级为高危或严重<span style="font-weight: var(--base-text-weight-semibold, 600);">并且</span>包含 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">预警</code> 标签</td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">奇安信威胁情报中心</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">https://ti.qianxin.com/</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">等级为高危严重<span style="font-weight: var(--base-text-weight-semibold, 600);">并且</span>包含 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">奇安信CERT验证</code> <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">POC公开</code> <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">技术细节公布</code>标签之一</td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">微步在线研究响应中心(公众号)</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">https://x.threatbook.com/v5/vulIntelligence</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">等级为高危或严重</td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">知道创宇Seebug漏洞库</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">https://www.seebug.org/</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">等级为高危或严重</td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Struts2 Security Bulletins</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Struts2 Security Bulletins</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">等级为高危或严重</td></tr></tbody></table>> 所有信息来自网站公开页面, 如果有侵权，请提交 issue, 我会删除相关源。  
> 如果有更好的信息源也可以反馈给我，需要能够响应及时 & 有办法过滤出有价值的漏洞  
  
  
具体来说，消息的推送有两种情况, 两种情况有内置去重，不会重复推送:  
- 新建的漏洞符合推送策略，直接推送,  
  
- 新建的漏洞不符合推送策略，但漏洞信息被更新后符合了推送策略，也会被推送  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_jpg/PJG3jJlPv0wTAKs5WaAYoy5UTMCWiaVD6U8w2vPoGtQPnhFmquhTlogIVNRW7wqkgdSStcxEfWibxtpo0ibI76Y4g/640?wx_fmt=jpeg&from=appmsg "")  
## 快速使用  
  
  
支持下列推送方式:  
- 钉钉群组机器人  
  
- 微信企业版群组机器人  
  
- 飞书群组机器人  
  
- Telegram Bot  
  
- Server 酱  
  
- 自定义 Bark 服务  
  
- 自定义 Webhook 服务  
  
### 使用 Docker  
  
  
Docker 方式推荐使用环境变量来配置服务参数  
<table><thead><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><th style=" padding: 6px 13px;font-weight: var(--base-text-weight-semibold, 600) ; ; ; ; ; ; ; ; ; ; ; ">环境变量名</th><th style=" padding: 6px 13px;font-weight: var(--base-text-weight-semibold, 600) ; ; ; ; ; ; ; ; ; ; ; ">说明</th><th style=" padding: 6px 13px;font-weight: var(--base-text-weight-semibold, 600) ; ; ; ; ; ; ; ; ; ; ; ">默认值</th></tr></thead><tbody><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">DB_CONN</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">数据库链接字符串，详情见 数据库连接</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">sqlite3://vuln_v3.sqlite3</code></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">DINGDING_ACCESS_TOKEN</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">钉钉机器人 url 的 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">access_token</code> 部分</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">DINGDING_SECRET</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">钉钉机器人的加签值 （仅支持加签方式）</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">LARK_ACCESS_TOKEN</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">飞书机器人 url 的 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">/open-apis/bot/v2/hook/</code> 后的部分, 也支持直接指定完整的 url 来访问私有部署的飞书</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">LARK_SECRET</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">飞书机器人的加签值 （仅支持加签方式）</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">WECHATWORK_KEY </code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">微信机器人 url 的 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">key</code> 部分</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">SERVERCHAN_KEY </code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Server酱的 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">SCKEY</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">WEBHOOK_URL</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">自定义 webhook 服务的完整 url</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">BARK_URL</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Bark 服务的完整 url, 路径需要包含 DeviceKey</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">TELEGRAM_BOT_TOKEN</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Telegram Bot Token</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">TELEGRAM_CHAT_IDS</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">Telegram Bot 需要发送给的 chat 列表，使用 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">,</code> 分割</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">SOURCES</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">启用哪些漏洞信息源，逗号分隔, 可选 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">avd</code>, <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">ti</code>, <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">oscs</code>, <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">seebug</code>,<code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">threatbook</code>,<code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">struts2</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">avd,ti,oscs,threatbook,seebug,struts2</code></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">INTERVAL</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">检查周期，支持秒 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">60s</code>, 分钟 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">10m</code>, 小时 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">1h</code>, 最低 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">1m</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">30m</code></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">ENABLE_CVE_FILTER</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">启用 CVE 过滤，开启后多个数据源的统一 CVE 将只推送一次</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">true</code></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">NO_FILTER</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">禁用上述推送过滤策略，所有新发现的漏洞都会被推送</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">false</code></td></tr><tr style="background-color: var(--bgColor-muted, var(--color-canvas-subtle));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">NO_START_MESSAGE</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">禁用服务启动的提示信息</td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">false</code></td></tr><tr style="background-color: var(--bgColor-default, var(--color-canvas-default));border-top: 1px solid var(--borderColor-muted, var(--color-border-muted));"><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">HTTPS_PROXY</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; ">给所有请求配置代理, 支持 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">socks5://xxxx</code> 或者 <code style="font-family: ui-monospace, SFMono-Regular, &#34;SF Mono&#34;, Menlo, Consolas, &#34;Liberation Mono&#34;, monospace;font-size: 13.6px;padding: 0.2em 0.4em;white-space-collapse: break-spaces;background-color: var(--bgColor-neutral-muted, var(--color-neutral-muted));border-radius: 6px;">http(s)://xxkx</code></td><td style=" padding: 6px 13px ; ; ; ; ; ; ; ; ; ; ; "><br/></td></tr></tbody></table>  
比如使用钉钉机器人  
```
docker run --restart always -d \
  -e DINGDING_ACCESS_TOKEN=xxxx \
  -e DINGDING_SECRET=xxxx \
  -e INTERVAL=30m \
  -e ENABLE_CVE_FILTER=true \

zemal/watchvuln:latest
```  
  
当然，你可以  
仓  
靠使用本仓库的   
docker  
-compose.yaml  
 文件，使用   
docker-compose  
 来启动容器。  
  
每次更新记得重新拉镜像:  
```
docker pull zemal/watchvuln:latest
```  
使用飞书机器人使用企业微信机器人使用Telegram 机器人使用自定义 Bark 服务使用自定义 Webhook 服务使用server酱机器人使用多种服务  
  
初次运行会在本地建立全量数据库，大约需要 1 分钟，可以使用 docker logs -f [containerId] 来查看进度, 完成后会在群内收到一个提示消息，表示服务已经在正常运行了。  
### 使用二进制  
  
  
前往 Release 下载对应平台的二进制，然后在命令行执行。命令行参数请参考 Docker 环境变量部分的说明，可以一一对应。  
```
USAGE:
   watchvuln [global options] command [command options] [arguments...]

GLOBAL OPTIONS:
   [Push Options]

   --bark-url value, --bark value             your bark server url, ex: http://127.0.0.1:1111/DeviceKey
   --dingding-access-token value, --dt value  webhook access token of dingding bot
   --dingding-sign-secret value, --ds value   sign secret of dingding bot
   --lark-access-token value, --lt value      webhook access token of lark
   --lark-sign-secret value, --ls value       sign secret of lark
   --serverchan-key value, --sk value         send key for server chan
   --telegram-bot-token value, --tgtk value   telegram bot token, ex: 123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11
   --telegram-chat-ids value, --tgids value   chat ids want to send on telegram, ex: 123456,4312341,123123
   --webhook-url value, --webhook value       your webhook server url, ex: http://127.0.0.1:1111/webhook
   --wechatwork-key value, --wk value         webhook key of wechat work

   [Launch Options]

   --db-conn value, --db value  database connection string (default: "sqlite3://vuln_v3.sqlite3")
   --enable-cve-filter          enable a filter that vulns from multiple sources with same cve id will be sent only once (default: true)
   --interval value, -i value   checking every [interval], supported format like 30s, 30m, 1h (default: "30m")
   --no-filter, --nf            ignore the valuable filter and push all discovered vulns (default: false)
   --no-github-search, --ng     don't search github repos and pull requests for every cve vuln (default: false)
   --no-start-message, --nm     disable the hello message when server starts (default: false)
   --proxy value, -x value      set request proxy, support socks5://xxx or http(s)://
   --sources value, -s value    set vuln sources (default: "avd,nox,oscs,threatbook,seebug,struts2")

   [Other Options]

   --debug, -d    set log level to debug, print more details (default: false)
   --help, -h     show help (default: false)
   --version, -v  print the version (default: false)
```  
  
在参数中指定相关 Token 即可, 比如使用钉钉机器人  
```
$ ./watchvuln --dt DINGDING_ACCESS_TOKEN --ds DINGDING_SECRET -i 30m
```  
```
```  
使用飞书机器人使用企业微信机器人使用server酱机器人使用Telegram 机器人使用自定义 Bark 服务使用自定义 Webhook 服务使用多种服务  
## 数据库连接  
  
  
默认使用 sqlite3 作为数据库，数据库文件为 vuln_v3.sqlite3，如果需要使用其他数据库，可以通过 --db 参数或是环境变量 DB_CONN 指定连接字符串，当前支持的数据库有:  
- sqlite3://filename  
  
- mysql://user:pass@host:port/dbname  
  
- postgres://user:pass@host:port/dbname  
  
注意：该项目不做数据向后兼容保证，版本升级可能存在数据不兼容的情况，如果报错需要删库重来。  
## 配置代理  
  
  
watchvuln 支持配置上游代理来绕过网络限制，支持两种方式:  
- 环境变量 HTTPS_PROXY  
  
- 命令行参数 --proxy/-x  
  
支持 socks5://xxxx 或者 http(s)://xxkx 两种代理形式。  
  
  

								  

									  

										  

											  
往期推荐  

										  

									  

									  

								[ ThinkPHP5.x远程命令执行（getshell）测试工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944902&idx=1&sn=cc70e3b181483f7e2ba62b073dd32c6f&chksm=8bac7979bcdbf06f1ba45e8fad8dfaed9e3dd7e58e21919b9eb5346026dd60a89acbe3d1ce97&scene=21#wechat_redirect)  

							  
  

								[ CVE-2021-32760漏洞分析与复现 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944841&idx=1&sn=d9d61c725139a1ce0a7c953aa7ac8cfb&chksm=8bac79b6bcdbf0a05e0b223e12cdcb0320dd4d5aaec2ded9cb36b38284a285d4d2dc62d32ade&scene=21#wechat_redirect)  

							  
  

								[ 红队手册[2]——心脏滴血(Heartbleed) ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944784&idx=1&sn=f5df0b72769cd097d852edb970cd2373&chksm=8bac79efbcdbf0f96e5d46e1f6f48b358250d6501cd42a9747d47107426bf1978080fb45972a&scene=21#wechat_redirect)  

							  
  

								[ 记一次违法网站的渗透经历-漏洞挖掘 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944699&idx=1&sn=8dcc3b7d96688b7e8ff2ad8af429d688&chksm=8bac7844bcdbf15293ce55899daf5463101147c8acf3467e493d42ad3ed0cd1791cfe433cb4a&scene=21#wechat_redirect)  

							  
  

								[ 金融类IOS APP端渗透测试实战分享 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944611&idx=1&sn=4024ecd8f4ef1afc65975b985a856e90&chksm=8bac789cbcdbf18a17289a027118b4296c7eb4d97674bd10dca5bbf41460f4af755705df04ba&scene=21#wechat_redirect)  

							  
  

								[ 若依最新定时任务SQL注入可导致RCE漏洞的一键利用工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944539&idx=1&sn=b0f794cc6243bdf77a543e3862e2ac99&chksm=8bac78e4bcdbf1f2e7fbf8e81e20c980d61839b0ceb0f31b4a9655017fffb1c3dffc8798377d&scene=21#wechat_redirect)  

							  
  

								[ Kali linux无线网络渗透详解笔记 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944463&idx=1&sn=b2352957352511682d73525b5ad9990d&chksm=8bac7f30bcdbf6265c6d59cf135cf0a7c2f5717833e13c6140b6801068fda1e85da124557f29&scene=21#wechat_redirect)  

							  
  

								[ 涉及13万个域名，揭露大规模安全威胁活动ApateWeb ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944372&idx=1&sn=5b5d38183efe1f5bbf3f3f68fc2ffbff&chksm=8bac7f8bbcdbf69d8c3ca78833ad94add34782b604361e4b714fbeb70e05aa8efcc45a560e85&scene=21#wechat_redirect)  

							  
  

								[ 分享一款好用的XSS扫描工具 ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944203&idx=1&sn=1ce69724b5a1520fb6a66de062fb3328&chksm=8bac7e34bcdbf722623963dfe4f7a07d6965a1f33e198eeebcb05f53babbfe885f654ef595eb&scene=21#wechat_redirect)  

							  
  

								[ ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944089&idx=1&sn=2e95782fd7bdd1429902fce4c47acdc5&chksm=8bac7ea6bcdbf7b0fb441de185959ca2d12031b05108c9ffaba11ea449f01a30ca016f9f4dd3&scene=21#wechat_redirect)  
  
[ ](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944089&idx=1&sn=2e95782fd7bdd1429902fce4c47acdc5&chksm=8bac7ea6bcdbf7b0fb441de185959ca2d12031b05108c9ffaba11ea449f01a30ca016f9f4dd3&scene=21#wechat_redirect)  
  
[CVE-2024-23897 Jenkins 未授权任意文件读取漏洞分析](http://mp.weixin.qq.com/s?__biz=MzA5MzYzMzkzNg==&mid=2650944089&idx=1&sn=2e95782fd7bdd1429902fce4c47acdc5&chksm=8bac7ea6bcdbf7b0fb441de185959ca2d12031b05108c9ffaba11ea449f01a30ca016f9f4dd3&scene=21#wechat_redirect)  
  
  
******下载地址**  
  
**点击下方名片进入公众号**  
  
**回复关键字【0313****】获取**  
**下载链接**  
  
  
  
声明：本公众号所分享内容仅用于网安爱好者之间的技术讨论，禁止用于违法途径，**所有渗透都需获取授权**  
！否则需自行承担，本公众号及原作者不承担相应的后果  
```
```  
  
