#  fastjson < 1.2.66 正则表达式拒绝服务漏洞REDOS   
 长风实验室   2024-11-18 12:54  
  
**1.****JSONPath类**  
  
（  
1  
）  
路径查询：  
  
通过路径表达式 $.store.book[0].title   
可以直接访问嵌套   
JSON   
中的   
title   
属性。  
  
（  
2  
）  
动态提取数据：  
  
可以根据条件从 JSON   
中提取符合条件的数据，支持过滤条件，例如选择价格大于某个值的书籍。  
  
（  
3  
）  
支持布尔表达式和条件语句，可以进行动态查询。例如，$..book[?(@.price > 10)]   
可以筛选价格高于   
10   
的书。  
  
（  
4  
）  
总结：  
  
	  
JSONPath   
类的作用是提供了一种高效、简洁的方式来查询和操作   
JSON   
数据  
。  
**例子：**  
  
使用 JSONPath   
来查询   
JSON   
数据结构中的特定值。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rgibzd5gib8S2I4z1OIp7DiajQDmIBWlaAQ6ubVO2OFb5iafagh6rJqQgyA/640?wx_fmt=png&from=appmsg "")  
  
**代码解释：******  
  
JSON   
数据结构：  
"{\"root\":{\"item1\":\"blue\"}}"   
是一个   
JSON   
字符串，表示的内容是：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rWkbD8MIFojEolvk6VG2REn9aWzFNRpkdiathZW8hL1KzsqsQSYw7SPQ/640?wx_fmt=png&from=appmsg "")  
  
**JSONPath 表达式：******  
  
"$.root['item1']"   
是一个   
JSONPath   
表达式，用于指定   
JSON   
数据中的路径。  
  
（  
1  
）$   
表示   
JSON   
数据的根对象。  
  
（  
2  
）root   
指向根对象下的   
root   
键。  
  
（  
3  
）['item1']   
则表示   
root   
对象中的键   
item1  
。  
  
（  
4  
）这个表达式的作用是获取 item1   
的值，即   
"blue"  
。  
  
**eval 方法：**  
  
（  
1  
）  
eval   
方法执行   
JSONPath   
表达式并从指定   
JSON   
字符串中提取数据。  
  
（  
2  
）  
new  
    
JSONPath("$.root['item1']").eval("{\"root\":{\"item1\":\"blue\"}}");  
  
将 JSONPath   
表达式应用到给定的   
JSON   
数据上，并返回结果。  
  
（3）  
JSONPath.eval("{\"root\":{\"item1\":\"blue\"}}", "$.root['item1']");   
是另一种等效写法，直接调用静态方法来进行相同的操作。  
  
**结果：**  
  
上述代码将 JSON   
数据   
{"root":{"item1":"blue"}}   
中的路径   
$.root['item1']   
所指向的值（即   
"blue"  
）提取出来并赋值给   
result   
变量。  
  
所以，执行完成后，result   
的值是   
"blue"  
。  
  
**最终结果：**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rDiaAqP0Mux7u7icBLGmzrBsNuP8F1EJHV4j0K7t38GAM1zQQkhhvkX5A/640?wx_fmt=png&from=appmsg "")  
  
**总结**  
  
这段代码的作用是使用   
JSONPath 表达式来从 JSON 数据结构中提取特定字段的值。在这里，它提取了 "root" 下 "item1" 的值 "blue"。  
  
**漏洞产生**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r7qSKabR3xzQIpmoACqribaib9N0Wgy9YZQJRp1KP6oICy6dqekzIru6Q/640?wx_fmt=png&from=appmsg "")  
  
this.init();   
是一种初始化方法的调用方式，通常用于在对象创建或特定操作时进行状态或配置的初始设置。通过调用   
init()   
方法，可以集中管理初始化逻辑，使代码更具可读性和维护性。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rpWJYGrVgiaNCR4OHaiaRSe0ic9N12qicNIFibqwQianlrC1XicicTJRcNicjiauw/640?wx_fmt=png&from=appmsg "")  
  
**逐步解释**  
  
**1. segment 对象：**  
  
（  
1  
）segment   
是一个对象，可能是某个类的实例，具有   
eval   
方法。  
  
（  
2  
）在类似 JSONPath   
或表达式评估的框架中，  
segment   
通常代表路径的一个部分或一个表达式片段，用于对对象进行评估。  
  
**2. eval 方法：******  
  
（  
1  
）eval   
方法的作用是对传入的对象进行某种评估或操作，返回一个新的结果。  
  
（  
2  
）该方法可能会使用传入的 this  
、  
rootObject   
和   
currentObject   
参数来进行操作或计算。  
  
（  
3  
）在 JSONPath   
处理或表达式求值的上下文中，  
eval   
方法通常用于导航、提取或修改对象中的数据。  
  
**3. 参数解释：**  
  
（  
1  
）  
this  
：当前实例对象，可能包含了一些必要的上下文信息或方法，供   
eval   
使用。  
  
（  
2  
）  
rootObject  
：表示   
JSON   
或对象树的根对象，通常是操作的起点，用于在   
eval   
中提供全局上下文。  
  
（  
3  
）  
currentObject  
：当前的对象或节点，是   
eval   
方法的评估起点，通常代表   
JSON   
路径中的一个中间结果或部分结构。  
  
**4. 返回结果赋值：**  
  
（  
1  
）  
segment.eval(this, rootObject, currentObject)   
执行后，返回的结果被赋值给   
currentObject  
，这意味着   
eval   
方法的执行结果会成为新的   
currentObject  
。  
  
（  
2  
）这种赋值方式通常用于迭代或递归地处理数据结构。例如，在遍历   
JSON   
路径时，逐步更新   
currentObject   
以便深入嵌套结构。  
  
**典型应用场景**  
  
假设这是在一个   
JSONPath   
或类似的解析框架中，每次   
eval   
调用都对   
currentObject   
进行一步路径解析或数据提取，最终返回整个路径所指向的对象或值。例如：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r6CM4icZlhp9H9rb7r6ZrAicaqqLEYibXAgwAhh6J2V2t3Bvh7u10hnVKQ/640?wx_fmt=png&from=appmsg "")  
  
在这个例子中，每个   
segment   
代表路径的一部分，通过逐步调用   
eval  
，  
currentObject   
会一步步深入到   
JSON   
结构的目标节点或值。  
  
**总结******  
  
这行代码的作用是调用   
segment   
的   
eval   
方法，对   
currentObject   
进行某种操作或评估，可能是数据提取或路径导航，并将评估结果重新赋值给   
currentObject  
。这样可以逐步或递归地处理对象结构，使   
currentObject   
最终指向所需的目标数据。  
  
**跟进init方法**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rm5mhoLmFanjI7H7QXIycjUqyicWs55bBBJ7PNlfGWjM31ockPvwvAhw/640?wx_fmt=png&from=appmsg "")  
  
**主要解释******  
  
this.segments = parser.explain();  
  
（  
1  
）  
JSONPathParser parser = new JSONPathParser(this.path);  
：首先创建一个   
JSONPathParser   
对象，用于解析   
path   
字符串。  
path   
是   
JSON   
路径的字符串表示，例如   
$.store.book[0]  
。  
  
（  
2  
）  
this.segments = parser.explain();  
：调用   
parser.explain()   
方法，将解析结果赋值给   
segments   
属性。  
  
（  
3  
）  
parser.explain()   
方法会解析   
path   
字符串，将其拆解为多个部分，每部分对应一个   
Segment   
对象。  
  
（  
4  
）每个   
Segment   
对象表示   
JSONPath   
中的一个路径片段，用于逐步解析   
JSON   
结构。例如，如果   
path   
是   
$.store.book[0]  
，  
segments   
将包含三个   
Segment  
：  
store  
、  
book   
和   
[0]  
。  
  
（  
5  
）  
segments   
数组的生成使得整个   
JSONPath   
的解析过程可以分步骤进行，每个   
Segment   
逐步深入   
JSON   
结构，直到定位到目标节点。  
  
（  
6  
）  
this.hasRefSegment = parser.hasRefSegment;  
：记录解析过程中是否包含引用片段（如   
JSONPath   
中的引用操作）。这在后续解析时可以用于特定处理。  
  
**总结******  
  
this.segments = parser.explain();   
的作用是通过解析   
path   
字符串，将其转换成多个   
Segment   
对象。这些   
Segment   
对象组成的数组   
segments   
能够逐步导航   
JSON   
结构，从而实现对   
JSON   
数据的路径定位和解析。  
  
**继续跟进JSONPath.JSONPathParserexplain**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86ruGId6eBLfibYNWicJ75ET8XpsAn6EzJ24q2Vgdf32Xylcs57Qw5xzF6Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86reaPibrnQS0QTQJice99JXglj38B83kD9YwyNe4YZaMFIvxAnAALEXXZQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r3VkpIyJabTJkhceJNhTiaKB4oD9fx1ywgR5eSOb7yW0ohj3pibdIxHEw/640?wx_fmt=png&from=appmsg "")  
  
**主要解释 segment = this.readSegement();**  
  
（  
1  
）  
segment = this.readSegement();  
：此行代码调用了   
readSegement()   
方法，解析   
path   
中的下一个片段，并返回一个   
Segment   
对象。它逐步解析整个路径的各个部分，逐次生成   
Segment  
，直到   
path   
的结尾。  
  
（  
2  
）  
Segment   
是一个抽象的路径片段，可能表示   
JSONPath   
中的某个节点、属性或其他操作。  
  
（  
3  
）  
readSegement()   
方法会读取   
path   
的下一个片段并解析成   
Segment   
对象，这些   
Segment   
对象将被存储在   
segments   
数组中。  
  
返回值   
segment   
的类型：  
  
（  
4  
）每次调用   
readSegement()  
，都将从   
path   
中读取一个片段，并将其解析为一个具体的   
Segment   
对象（如   
PropertySegment  
、  
ArraySegment   
等）。  
  
（  
5  
）如果   
path   
已被完全解析，  
readSegement()   
会返回   
null  
，表示已到达路径结尾。  
  
**逐步解析路径片段：******  
  
（  
1  
）  
explain   
方法通过   
readSegement()   
分片解析   
JSONPath   
中的每一个路径部分。  
  
（  
2  
）例如，对于   
$.store.book[0]  
，  
readSegement()   
会逐次返回表示   
store  
、  
book   
和   
[0]   
的   
Segment   
对象。  
  
**总结**  
  
在   
explain()   
方法中，  
segment = this.readSegement();   
的作用是从   
path   
中读取并解析下一个路径片段，并将其转换为   
Segment   
对象。这一步使得   
explain   
方法能够逐步构建整个   
JSONPath   
的   
Segment   
数组，为后续路径解析和导航提供结构化的路径片段。  
  
**继续跟进JSONPath.JSONPathParserreadSegement**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86ry1hqn5d2ywzfdiadSk7QDhdlOwDqEAJMiaQgiczfBYadKFHvklhRl11sQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rehVc3Z3Y8ygDnYicNHVDUIZBLq48WvW3c5GHER0CibDp1rpQryy0dgag/640?wx_fmt=png&from=appmsg "")  
  
**重点解释 return this.parseArrayAccess(true);**  
  
**parseArrayAccess(true)：******  
  
（  
1  
）这里调用了   
parseArrayAccess(true)   
方法，用于解析当前的数组访问片段。例如，在路径字符串   
$.store.book[0]   
中，当遇到字符   
[   
时，会调用   
parseArrayAccess(true)   
来解析   
[0]  
。  
  
（  
2  
）  
parseArrayAccess(true)   
方法解析   
[index]   
或   
[key]   
形式的数组访问，并将其转换为一个   
ArrayAccessSegment   
对象，表示   
JSONPath   
中的数组访问操作。  
  
**true 参数的含义：******  
  
（  
1  
）  
parseArrayAccess   
方法接收一个布尔参数。在   
JSONPath   
解析库中，传递   
true   
可能表示这是一个标准的数组访问（例如   
[0]  
），需要严格按照数组访问的方式进行解析。  
  
（  
2  
）这个参数的具体含义可能与解析模式、容错机制等有关，根据实现，可能决定是否支持多种数组访问模式。  
  
**return 语句：******  
  
（  
1  
）  
return this.parseArrayAccess(true);   
直接返回   
parseArrayAccess   
方法的结果，即一个   
ArrayAccessSegment   
对象。  
  
（  
2  
）  
ArrayAccessSegment   
表示   
JSON   
路径中的数组访问操作片段。在   
JSONPath   
中，这样的   
Segment   
用于定位   
JSON   
数组中的特定元素，例如   
book[0]   
表示访问   
book   
数组的第一个元素。  
  
**总结******  
  
return this.parseArrayAccess(true);   
的作用是在解析   
JSONPath   
时，当遇到   
[   
字符时调用   
parseArrayAccess(true)  
，以解析数组访问操作，并返回一个   
ArrayAccessSegment   
对象。这个   
Segment   
表示路径中的数组访问片段，使得解析器能够识别和处理数组元素的访问。  
  
**这里当前读到的字符等于[就进入到JSONPath.JSONPathParserparseArrayAccess**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rGzEjBpr7IcXdecGe3rWAdGFPNHfMtWG1RwZo7x3SicBo2ria1GLBH7mg/640?wx_fmt=png&from=appmsg "")  
  
**主要解释 : 和 ? 的作用**  
  
**三元运算符 ? :******  
  
（  
1  
）  
? :   
是   
Java   
的三元条件运算符，形式为   
condition ? expr1 : expr2  
。  
  
（  
2  
）其中   
condition   
是一个布尔表达式，  
expr1   
是条件为   
true   
时执行的表达式，  
expr2   
是条件为   
false   
时执行的表达式。  
  
（  
3  
）在这段代码中，条件   
object instanceof JSONPath.Segment   
用于判断   
object   
是否为   
JSONPath.Segment   
类型。  
  
（  
4  
）如果条件为   
true  
（即   
object   
是   
JSONPath.Segment   
类型），则执行   
(JSONPath.Segment)object  
，直接将   
object   
转换为   
Segment   
类型并返回。  
  
（  
5  
）如果条件为   
false  
（即   
object   
不是   
Segment   
类型），则执行   
new JSONPath.FilterSegment((JSONPath.Filter)object)  
，将   
object   
视为   
Filter   
类型，并用它创建一个新的   
FilterSegment   
对象。  
  
**代码的具体作用**  
  
**1. 解析数组访问或过滤条件：******  
  
（  
1  
）通过调用   
this.parseArrayAccessFilter(acceptBracket);   
方法，解析   
JSONPath   
中的数组访问或过滤条件。  
  
（  
2  
）  
parseArrayAccessFilter   
方法返回的   
object   
可以是   
Segment  
（表示普通的数组访问）或   
Filter  
（表示条件过滤）的实例。  
  
**2. 判断并返回合适的对象：******  
  
（  
1  
）  
object instanceof JSONPath.Segment   
检查   
object   
是否为   
Segment   
类型。  
  
（  
2  
）如果是   
Segment  
，则直接将   
object   
转换为   
Segment   
并返回，表示这是一个普通的数组访问。  
  
（  
3  
）如果不是   
Segment  
，则将   
object   
视为   
Filter  
，并创建   
FilterSegment   
对象，将过滤条件封装在   
FilterSegment   
中。  
  
**3. 返回类型：******  
  
（  
1  
）返回类型是   
JSONPath.Segment  
，它可以是普通的   
Segment   
或   
FilterSegment  
。  
  
（  
2  
）这样，在解析   
JSONPath   
的过程中，可以处理数组访问   
[0]   
以及基于条件的过滤表达式   
[?(@.price > 10)]  
。  
  
**总结******  
  
在这段代码中，  
? :   
三元运算符用于判断   
object   
的类型，并决定返回   
Segment   
或   
FilterSegment  
。这确保了   
parseArrayAccess   
方法既能处理普通数组访问，也能处理条件过滤的情况，为   
JSONPath   
提供灵活的解析能力。  
  
JSONPath  
第  
3117  
行处当读取到的操作符为   
RLIKE   
或   
NOT_RLIKE   
时就会返回一个   
JSONPath.RlikeSegement   
对象  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rwE0SKvibUriaMnkibZVCwwQd0U2H52oicSdhVD50tDEm6icGEu5gHzdneIw/640?wx_fmt=png&from=appmsg "")  
  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r2WY4iaE01NJ8Mxew5OGYgpU7blaIkp6WJxt4MLJSjw2MlNSKfIsMguA/640?wx_fmt=png&from=appmsg "")  
  
****  
**代码的作用******  
  
**1. 操作符检查：******  
  
（  
1  
）  
op   
是一个   
JSONPath.Operator   
类型的枚举值，用于表示   
JSONPath   
操作符。  
  
（  
2  
）  
JSONPath.Operator.RLIKE   
表示正则表达式匹配操作（类似   
SQL   
中的   
RLIKE  
）。  
  
（  
3  
）  
JSONPath.Operator.NOT_RLIKE   
表示正则表达式非匹配操作（类似   
SQL   
中的   
NOT RLIKE  
）。  
  
**2. 根据操作符创建不同的 RlikeSegment 对象：******  
  
（  
1  
）如果   
op   
是   
RLIKE  
，则创建一个   
RlikeSegment   
对象，用于匹配   
propertyName   
属性值与   
name   
正则表达式的条件。  
  
（  
2  
）如果   
op   
是   
NOT_RLIKE  
，则创建一个   
RlikeSegment   
对象，但用于非匹配条件。  
  
**3. RlikeSegment 构造函数的参数：******  
  
（  
1  
）  
propertyName  
：要匹配的属性名称。  
  
（  
2  
）  
name  
：正则表达式，用于匹配属性的值。  
  
（  
3  
）  
false   
或   
true  
：布尔值，表示是否为非匹配模式。  
  
（  
4  
）  
false   
表示匹配模式（  
RLIKE  
），即属性值应与正则表达式匹配。  
  
（  
5  
）  
true   
表示非匹配模式（  
NOT_RLIKE  
），即属性值不应与正则表达式匹配。  
  
**总结**  
  
这段代码的作用是根据操作符   
op   
的值，创建不同的   
RlikeSegment   
对象，以表示   
JSONPath   
中的正则表达式匹配或非匹配条件。  
RlikeSegment   
用于实现属性值与正则表达式之间的匹配条件筛选，使得   
JSONPath   
可以支持基于正则表达式的查询。  
  
**比如[var rlike 'regex'] propertyName=var , name=regex**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rtfAsQ8BGBcXpmhOMU53N3XdG0MhvJiaaDhsWfQYobnibPsLriaB72qyTw/640?wx_fmt=png&from=appmsg "")  
  
返回到  
init()  
方法  
this.segments  
最终得到了一个内嵌  
RlikeSegement  
对象的  
FilterSegment  
数组。  
  
再跳回到最开始的   
eval   
方法，  
  
当初始化完成后开始对   
segments   
数组遍历，调用它们的  
eval(this, rootObject, currentObject)  
方法  
  
前面提到过，数组里有一个  
FilterSegment  
对象，所以应该跟进到  
FilterSegmenteval  
方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rbwABbS88oZtI9Lh8qklwYymRkEz9DQbiav7uCTH5wXQzzWDl3kicD80Q/640?wx_fmt=png&from=appmsg "")  
  
filter   
是   
RlikeSegement   
对象，所以应跟到  
JSONPath.RlikeSegementapply  
。  
  
后面就是从   
currentObject   
中取   
propertyName   
然后和正则匹配。  
  
漏洞就出现在这个地方，当正则表达式可控时，就会造成  
“  
REDOS  
”正则表达式拒绝服务。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rouUsolzL58bYTFVxUlcuArn9me90nSw15ibL6icRsmAnu3Ap5PiaIjCYw/640?wx_fmt=png&from=appmsg "")  
  
**整体的漏洞触发思路******  
  
**梳理出以下执行流程：**  
  
1.   
初始化阶段   
(init   
方法  
)  
：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r8pHF2vXGJQtyVeR7zxjdCAaRGyuTe3PJaV3BW4d9t02vhG00XFE9mw/640?wx_fmt=png&from=appmsg "")  
  
在   
init   
方法中，  
this.segments   
被初始化为一个包含   
FilterSegment   
对象的数组，而   
FilterSegment   
内部嵌套了一个   
RlikeSegment   
对象。  
  
RlikeSegment   
用于实现正则表达式匹配或非匹配操作   
(RLIKE   
或   
NOT RLIKE)  
。  
  
2.  
eval   
方法的调用：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rjSHiabHYQnCag6JYCC2FV5ufHrAeUoN99UDeJeiaWMNKxNLqBJNgdo1g/640?wx_fmt=png&from=appmsg "")  
  
初始化完成后，程序开始在   
eval   
方法中遍历   
segments   
数组。  
  
每个   
Segment   
对象（包括   
FilterSegment  
）都会调用其   
eval(this, rootObject, currentObject)   
方法。  
  
进入   
FilterSegmenteval   
方法：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rgLbhkJC5Adqmic5dxULia5XttqCVL2ia1HJqHgGkoy6hnSpHQgPu9PMNA/640?wx_fmt=png&from=appmsg "")  
  
在   
segments   
数组中包含了一个   
FilterSegment   
对象，因此程序会进入   
FilterSegment   
的   
eval   
方法。  
  
FilterSegmenteval   
方法的核心操作是调用其内部的   
filter.apply()   
方法。  
  
正是第三步的关键部分。在这一段代码中，  
FilterSegment   
会对集合中的每个元素（  
item  
）应用过滤条件，决定是否将该元素添加到结果列表   
items   
中。****  
  
**第三步的详细说明**  
  
1.   
遍历   
currentObject   
中的每个元素：  
  
（  
1  
）  
FilterSegment   
的   
eval   
方法通常用于处理数组或集合类型的   
currentObject  
。  
  
（  
2  
）对于每个元素   
item  
，代码会调用   
this.filter.apply(...)  
，将   
path  
、  
rootObject  
、  
currentObject   
和   
item   
作为参数传递给   
apply   
方法。  
  
2.   
调用   
this.filter.apply(...)  
：  
  
（  
1  
）  
this.filter   
是   
FilterSegment   
内部的过滤条件对象，它通常是一个   
RlikeSegment   
或其他类型的   
Segment  
。  
  
（  
2  
）  
apply   
方法会根据过滤条件对   
item   
进行判断。  
  
（  
3  
）如果   
filter   
是   
RlikeSegment  
，  
apply   
方法会使用正则表达式检查   
item   
中的某个属性是否符合指定的模式。  
  
（  
4  
）  
apply   
方法返回一个布尔值   
true   
或   
false  
，用于表示   
item   
是否满足条件。  
  
3.   
条件判断和添加到结果列表：  
  
（  
1  
）  
if (this.filter.apply(...))   
判断   
item   
是否满足过滤条件。  
  
（  
2  
）如果   
apply   
方法返回   
true  
，表示   
item   
满足条件，则将该   
item   
添加到   
items   
列表中。  
  
（  
3  
）最终，  
items   
列表中包含了所有满足过滤条件的元素，作为   
FilterSegment   
的过滤结果。****  
  
**关键部分总结**  
  
（  
1  
）  
apply   
方法的核心作用：  
apply   
方法用于执行过滤逻辑，决定   
item   
是否符合过滤条件。  
  
（  
2  
）  
REDOS   
风险：如果   
apply   
方法中的过滤条件是正则表达式，并且设计不当或输入不受控制，可能会导致正则表达式拒绝服务（  
REDOS  
）的风险。  
  
**代码执行流程总结**  
  
（  
1  
）第一步：  
init   
方法初始化   
segments   
数组。  
  
（  
2  
）第二步：在   
eval   
方法中遍历   
segments  
，逐步解析   
JSONPath   
表达式。  
  
（  
3  
）第三步：当   
FilterSegment   
遇到集合类型的   
currentObject   
时，对每个元素   
item   
应用   
filter.apply(...)  
，并将符合条件的   
item   
添加到   
items   
列表中。  
  
（  
4  
）  
filter.apply   
方法的执行：  
  
FilterSegment   
中的   
filter   
属性是一个   
RlikeSegment   
对象，所以调用   
filter.apply()   
实际上调用的是   
RlikeSegmentapply   
方法。  
  
apply   
方法从   
currentObject   
中提取出指定的属性值，并使用正则表达式进行匹配或非匹配操作。  
  
（  
5  
）正则表达式匹配风险（  
REDOS  
）：  
  
如果正则表达式存在设计缺陷或输入不受控制，则在匹配时可能引发   
正则表达式拒绝服务攻击（  
REDOS  
）。  
  
图中的示例展示了一个复杂的正则表达式   
"[azAZ]+(([azAZ ])?[azAZ]*)*$"  
，这种表达式在处理长字符串时可能导致大量的回溯，从而占用大量   
CPU   
资源，导致线程阻塞。  
  
**图中代码示例的 REDOS 风险******  
  
示例代码：  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r423Emvs6JGKZh4GMIeGLMOmDmvXNIV1rbbXb80ZK9aOc2PaJ70jXCA/640?wx_fmt=png&from=appmsg "")  
  
（  
1  
）这个代码片段展示了通过   
JSONPath   
语法使用   
rlike   
来进行正则匹配。  
  
（  
2  
）正则表达式   
^[azAZ]+(([azAZ ])?[azAZ]*)*$   
是一个复杂的正则表达式，当输入字符串非常长时（如   
"aaaaaaaaaaaaaaaaaaaaaaaaaaaa!"  
），会引起大量回溯，导致程序运行缓慢，  
CPU   
占用高。  
  
（  
3  
）这种情况可能被恶意利用，导致服务陷入拒绝服务状态。  
  
**总结**  
  
整个流程展示了如何通过   
JSONPath   
表达式使用   
RlikeSegment   
进行正则表达式匹配。然而，当正则表达式设计不当或输入不可控时，可能会导致   
REDOS   
攻击的风险。为避免这种情况，应在使用正则表达式时进行以下优化：  
  
简化正则表达式，避免使用可能引起大量回溯的模式。  
  
对输入的长度和格式进行严格限制，以防止恶意输入导致高   
CPU   
占用。  
  
**通过一个简单的测试证明是否真的存在REDOS**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86raicjGCcRfLvnEfHOx3kicuUEHfMJKpJD40lEymtWaFN7rBHRzSxNwapA/640?wx_fmt=png&from=appmsg "")  
  
这是正常的进程耗费  
CPU  
的情况  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rf4X3kjOZhSQ3dfQrmKDBeU6gmQkVS19q9b9jhzjia5vxPBHBT71jNjw/640?wx_fmt=png&from=appmsg "")  
  
这是代码运行后  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rD5u68jM1QenNUQcmXQJf30ghvMwiaTCsobPglfgUibGMIWbcF5kXMriaQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rbDwu1gVX4WZDxeuBeemrS7JwkfaG5brv3icgjZhe2XCWibKWwOmg2MLA/640?wx_fmt=png&from=appmsg "")  
  
但是由于在实际环境中能够控制  
JSONPATH  
的情况基本没有 ，所以我们就要尝试找到可控的位置  
  
**JSON $ref******  
  
先来看常见的解析   
json   
对象用的静态方法  
JSON.parse  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rvHUGaeTzNQEJ1ibvS4fgzUMYe8sJenibbAgWCARya170JLrJH5IjQibFA/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rjlXhqic1HhE6KrGbvZD1D6jwlhnuQS4BUAkibLeibzgUYkE5xOWyjYWKA/640?wx_fmt=png&from=appmsg "")  
  
****  
**总结**  
  
这段代码通过   
DefaultJSONParser   
创建解析器对象，解析   
JSON   
字符串并生成   
Java   
对象。  
  
handleResovleTask   
方法用于处理   
JSON   
中的   
$ref   
引用，确保引用指向正确的数据。  
  
跳过一些无用步骤，直接到  
DefaultJSONParserparseObject  
。  
  
首先要让  
key  
等于  
$ref  
满足  
if  
条件。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r4m0htJcKjCq0ZMkZDsW3Itd71Gh8rMc4uu5wNhyFVuePulibRDCLxzw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rlONo7mRMROlMnOiaryJaYDGUw0qfJRqITjSyRZpo51emPVFVIjK9IEw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r1yibRORd7Q5ByZ0m7szmeDd4iclMbQp1kIS3gtXYic9w8GlAEto5KG8Ew/640?wx_fmt=png&from=appmsg "")  
  
然后让   
$ref   
的值不要等于   
@   
和   
..   
和   
$   
就会进入   
else   
代码块调用   
addResolveTask   
方法，这个方法的作用就是给  
this.resolveTaskList  
集合添加一个  
ResolveTask  
对象。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rPjhL1WgYYlIx0JNBvgUdRwbG9ygSoMicKvwE1S4rrMCcibia5tTRH664w/640?wx_fmt=png&from=appmsg "")  
  
再返回到  
JSONparse  
，  
JSON  
解析部分结束  
  
进入漏洞触发点  
DefaultJSONParserhandleResovleTask  
方法。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rc8VDv4PpK9VClSAOiaMGfc5XS3ehWiasZckyibuljI6kH0muf3f73VaNQ/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86r02AfxDLCsun9qVkx6xQGFTdxH1z3yb7jBmqH6MVCfNyrHVLHEYibeGw/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rMYh05icNQOEE3OZlJ8NjyoKmEGDfBSVjQlOboaaELQ7bGIB2ymImwzg/640?wx_fmt=png&from=appmsg "")  
  
最终在   
1508   
行调用了  
JSONPath.eval(value, ref);   
触发漏洞。  
  
**POC代码**  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rfWGkXOThpWmoJhOPngDn0tl3QlK30sDEXEB9cBwgMVyle6Obv93DibQ/640?wx_fmt=png&from=appmsg "")  
  
另外除了  
RlikeSegement  
类以外还有一个  
RegMatchSegement  
类，同样存在  
REDOS  
漏洞，过程基本上一样所以直接放上  
POC  
。  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/twRRNxG1MqzZszboiaSTILZUr2rzicQ86rnSSnBSx0fEJ8R3Eic1tmuFWYZCAnIGr2boqMIEXxNR1gD1HYHLSM3Yw/640?wx_fmt=png&from=appmsg "")  
  
  
