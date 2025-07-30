#  【Pikachu】PHP反序列化RCE实战   
原创 儒道易行  儒道易行   2024-11-15 18:00  
  
**痛是你活着的证明**  
## 1.PHP反序列化概述  
  
在理解 PHP 中 serialize() 和 unserialize() 这两个函数的工作原理之前，我们需要先了解它们各自的功能及其潜在的安全隐患。接下来，我会对相关概念做更详细的扩展解释。  
### 1. 序列化 serialize()  
  
序列化（serialization）是指将一个对象或数据结构转换为字符串的过程，使其能够被存储、传输或存取。通俗来说，序列化就是将一个复杂的对象（如类实例）转换成一种可以存储或传输的形式（例如字符串或二进制数据）。这使得对象数据可以在网络上传输，或者保存在文件中，以后再还原成原来的对象。  
  
假设有一个 PHP 类如下：  
```
```  
  
现在，我们调用 serialize($s) 来将该对象转换为字符串：  
```
```  
  
这时，$serialized 的内容将是：  
```
```  
  
解释：  
- O: 表示这是一个对象。  
  
- 1: 表示该对象的类名长度为 1。  
  
- "S" 是该对象的类名。  
  
- 1: 表示该对象包含一个属性。  
  
- {s:4:"test";s:7:"皮卡丘";} 是该对象属性的描述：  
  
- s:4:"test"; 表示属性名称为 test，长度为 4 字符。  
  
- s:7:"皮卡丘"; 表示属性值为 "皮卡丘"，长度为 7 字符。  
  
序列化后的字符串可以被安全地存储或传输。然后在需要时，通过 unserialize() 函数将其还原为原来的对象。  
### 2. 反序列化 unserialize()  
  
反序列化（unserialization）是将一个经过序列化的字符串重新转换为原始对象的过程。unserialize() 函数接收一个序列化的字符串作为输入，并将其转换为一个对象，使得我们可以继续在代码中使用这个对象。  
  
示例代码：  
```
```  
  
通过 unserialize()，我们将序列化的字符串还原为对象 $unserialized，然后可以像操作普通对象一样使用它。上面的例子中，输出结果是 皮卡丘，因为这是对象的 test 属性值。  
### 3. 安全隐患：当反序列化的数据是用户可控的  
  
序列化和反序列化本身是非常常见且有用的操作，但它们带来的一大安全风险就是反序列化不安全的数据。特别是当反序列化的内容是由用户控制时，如果不进行严格的验证和过滤，可能会导致 **PHP 漏洞** 的产生。这类漏洞通常是通过反序列化数据触发的 **对象注入攻击**（Object Injection Attack），并且通过精心构造的序列化数据，攻击者可能执行恶意代码，导致系统被攻陷。  
### 4. PHP 魔法方法（Magic Methods）  
  
在 PHP 中，魔法方法是类中的特殊方法，这些方法可以自动触发某些特定操作。常见的魔法方法包括：  
- __construct()：当对象创建时被调用。  
  
- __destruct()：当对象销毁时被调用。  
  
- __toString()：当对象被当作字符串使用时被调用。  
  
- __sleep()：在对象序列化之前调用。  
  
- __wakeup()：在对象反序列化之后调用。  
  
其中，__destruct()、__sleep() 和 __wakeup() 可能会在反序列化过程中被触发，如果这些方法的行为没有得到适当的保护，就可能被攻击者利用。  
### 5. 反序列化漏洞的利用  
  
让我们看一个具体的例子，展示如何通过反序列化漏洞执行恶意代码。假设有以下代码：  
```
```  
#### 攻击者构造的 payload：  
  
假设攻击者通过 HTTP 请求传入以下序列化数据：  
```
```  
  
当 PHP 反序列化该字符串时，__destruct() 方法会被调用，并输出 $test 属性的值。如果 $test 属性为空，攻击者可以利用这种方式在销毁对象时执行一些其他的操作（如输出敏感信息、执行恶意代码等）。  
#### 潜在的安全问题：  
  
如果攻击者能够控制 $test 属性的值或通过其他方式修改对象的状态，他们可能会触发恶意代码执行。比如，他们可能在 __destruct() 方法中放入恶意的 PHP 代码，导致服务器被攻陷。  
### 6. 防范措施  
  
要避免反序列化漏洞带来的风险，应该采取以下防范措施：  
- **严格验证输入数据**：永远不要直接反序列化来自用户输入的数据。如果必须反序列化用户提供的数据，先进行严格的验证，确保其格式和来源是可信的。  
  
- **禁用不必要的魔法方法**：如果不需要某些魔法方法（如 __wakeup()、__destruct()），可以禁用它们，或者确保它们不会执行不安全的操作。  
  
- **使用 JSON 代替序列化**：如果数据格式允许，使用 json_encode() 和 json_decode() 替代 serialize() 和 unserialize()，因为 JSON 不会触发对象的魔法方法，降低了潜在的安全风险。  
  
- **限制****unserialize()****的类**：可以通过 allowed_classes 参数限制 unserialize() 函数可反序列化的类，防止恶意对象注入。  
  
### 结语  
  
PHP 的 serialize() 和 unserialize() 功能为开发者提供了强大的数据持久化和传输能力，但如果不小心使用或缺乏适当的安全措施，可能会成为攻击者利用的漏洞源。通过理解这些函数的工作原理，以及它们在实际应用中的潜在安全风险，开发者可以采取更有效的防护措施，确保应用的安全性。     
  
## 2.PHP反序列化漏洞实战  
  
根据序列化的原理  
  
首先我们在本地写一个serialize.php文件，进行序列化  
  
代码如下  
```
```  
  
在本地程序执行，得到序列化的结果  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwy3McqicwlMmiaiawwJcOXxYllDnbqt7aE6EJCarr519K1jAAcYAtLUeZb2YFAKbPGribTaHKWFCcmdw/640?wx_fmt=png&from=appmsg "")  
  
将这一结果填入到具有反序列化漏洞的网站中，成功触发xss漏洞  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpwy3McqicwlMmiaiawwJcOXxYlmibjicaic3g6ibMibso1ryTaB7X5GMdsVprupSS3fXjAez5uhrsdljYPadQ/640?wx_fmt=png&from=appmsg "")  
  
文笔生疏，措辞浅薄，望各位大佬不吝赐教，万分感谢。  
  
免责声明：由于传播或利用此文所提供的信息、技术或方法而造成的任何直接或间接的后果及损失，均由使用者本人负责， 文章作者不为此承担任何责任。  
  
转载声明：儒道易行 拥有对此文章的修改和解释权，如欲转载或传播此文章，必须保证此文章的完整性，包括版权声明等全部内容。未经作者允许，不得任意修改或者增减此文章的内容，不得以任何方式将其用于商业目的。  
```
```  
  
![](https://mmbiz.qpic.cn/mmbiz_png/v94hWOZcBpyMdKEOOAGO3VfwurmMZUeU9gP8wMvqnC0U9gJdnO4ZCVDmZQ85UEgndHiaov5prsYo3HQjWIcbR8Q/640?wx_fmt=png&from=appmsg "")  
  
![](https://mmbiz.qpic.cn/mmbiz_jpg/v94hWOZcBpz3P8UiajyHSibiaK8uwXhGicias4ibzTbQ0bHSlA1XULM8glWxQJVw2CH2Kvt7LXj3cjHa35zHiakUmEmlA/640?wx_fmt=jpeg&from=appmsg "")  
  
  
