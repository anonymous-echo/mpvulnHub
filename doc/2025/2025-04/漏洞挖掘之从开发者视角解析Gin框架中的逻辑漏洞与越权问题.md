#  漏洞挖掘之从开发者视角解析Gin框架中的逻辑漏洞与越权问题   
 黑白之道   2025-04-05 21:41  
  
![](https://mmbiz.qpic.cn/mmbiz_gif/3xxicXNlTXLicwgPqvK8QgwnCr09iaSllrsXJLMkThiaHibEntZKkJiaicEd4ibWQxyn3gtAWbyGqtHVb0qqsHFC9jW3oQ/640?wx_fmt=gif "")  
  
原文首发在：奇安信攻防社区  
  
https://forum.butian.net/share/4164  
  
以go的gin后端框架为例子，详细剖析了各种逻辑越权漏洞的成因已经对应防范手段，也为白帽子提供挖掘思路  
## 并发漏洞  
### 原理  
  
例如这是一段简单的go商城的示例代码  
```
package handlersimport (    "go2shop/internal/database"    "go2shop/internal/models"    "net/http"    "github.com/gin-gonic/gin")...funcBuyProduct(c *gin.Context) {    var req struct {        Username  string`json:"username" binding:"required"`        ProductID uint   `json:"product_id" binding:"required"`        Quantity  int    `json:"quantity" binding:"required,gt=0"`    }    if err := c.ShouldBindJSON(&req); err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})        return    }    // 查找用户    var user models.User    if err := database.DB.Preload("Inventory").Where("username = ?", req.Username).First(&user).Error; err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})        return    }    // 查找商品    var product models.Product    if err := database.DB.First(&product, req.ProductID).Error; err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": "Product not found"})        return    }    // 检查库存和余额    totalPrice := float64(req.Quantity) * product.Price    if user.Balance < totalPrice {        c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient balance"})        return    }    if product.Stock < req.Quantity {        c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient stock"})        return    }    // 更新用户余额和商品库存    user.Balance -= totalPrice    product.Stock -= req.Quantity    // 更新用户的库存    var inventoryItem models.InventoryItem    if err := database.DB.Where("user_id = ? AND product_id = ?", user.ID, product.ID).First(&inventoryItem).Error; err == nil {        inventoryItem.Quantity += req.Quantity        database.DB.Save(&inventoryItem)    } else {        newInventoryItem := models.InventoryItem{            UserID:    user.ID,            ProductID: product.ID,            Quantity:  req.Quantity,        }        database.DB.Create(&newInventoryItem)    }    database.DB.Save(&user)    database.DB.Save(&product)    c.JSON(http.StatusOK, gin.H{"message": "Purchase successful"})}...
```  
  
main.go中:  
```
...r.POST("/buy", handlers.BuyProduct)
```  
  
乍看之下没有任何问题，但其实由于Gin框架是多线程架构，就存在条件竞争的漏洞。也就是说，假设用户同时发送了两个一样的请求到服务器，多线程的Gin框架会同时进行：if user.Balance < totalPrice {  
的条件判断，这个时候就会两个请求都会认为库存足够（10 >= 10）。然后两个请求分别扣减库存，最终商品库存会变为 -10，而实际上应该拒绝第二次购买。  
  
然后两个线程会同时执行数据库的UPDATE的操作，  
```
if err := database.DB.Where("user_id = ? AND product_id = ?", user.ID, product.ID).First(&inventoryItem).Error; err == nil {    inventoryItem.Quantity += req.Quantity    database.DB.Save(&inventoryItem)} else {    newInventoryItem := models.InventoryItem{        UserID:    user.ID,        ProductID: product.ID,        Quantity:  req.Quantity,    }    database.DB.Create(&newInventoryItem)}
```  
  
就会导致只付了一碗粉的钱却吃了商家两碗粉。  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqeeWuE30PtXkw7Y3skMCvGWEX4jJIUFAtHAuyHicvs94pbJBTKicS5PYTc25ViafKSIyv6NkL8P30ew/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
这个红色部分就是造成漏洞的过程，可以看到库存被更新了两次  
### 如何利用？  
  
我这里使用的是BurpSuite的代理插件 Turbo  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqeeWuE30PtXkw7Y3skMCvG5liatP6Nyr79KUlPj2lVgBAGIso0aU1VJt8OiaVz59WGq5K7VWDaGbsQ/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
使用如下并发脚本:  
```
defqueueRequests(target, wordlists):    global BATCH_SIZE    BATCH_SIZE = 60    engine = RequestEngine(endpoint='http://172.16.0.96:8888',                           concurrentConnections=BATCH_SIZE,                           requestsPerConnection=100,                           engine=Engine.THREADED,                           pipeline=False,                           maxQueueSize=BATCH_SIZE                           )    req = '''POST /buy HTTP/1.1Host: 172.16.0.96:8888Connection: keep-aliveContent-Length: 51User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090c11) XWEB/11581 FlueContent-Type: application/jsonAccept: */*Origin: http://172.16.0.96:8888Referer: http://172.16.0.96:8888/Accept-Encoding: gzip, deflate, brAccept-Language: zh-CN,zh;q=0.9x:%s{"username":"testuser","product_id":1,"quantity":1}'''    for i inrange(10):        gate_id = str(i)        for x inrange(BATCH_SIZE):            engine.queue(req, '0.000', gate=gate_id)        engine.openGate(gate_id)        time.sleep(0.5)defhandleResponse(req, interesting):    xtime= req.response.split('\r\n\r\n')[1]    req.label = xtime    table.add(req)defcompleted(reqsFromTable):    diffs = []    time.sleep(1)    printlen(reqsFromTable)    for i inrange(len(reqsFromTable)):        if i % BATCH_SIZE != 0:            continue        entries = []        for x inrange(BATCH_SIZE):            entries.append(float(reqsFromTable[i+x].label))        entries.sort()        diffs.append(entries[-1] - entries[0])    diffs.sort()    print('Best: '+str(min(diffs)))    print('Mean: '+str(mean(diffs)))    print('Stddev: '+str(stddev(diffs)))    print('Median: '+str(diffs[len(diffs)/2]))    print('Range: '+str(max(diffs)-min(diffs)))    handler.setMessage(str(sum(diffs)/len(diffs)))
```  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqeeWuE30PtXkw7Y3skMCvGOr4pJW1mX6tEpnLjRia8rFUwiaeBLWBgwY622VpQfUhibZGSWtFicHRK7g/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
  
  
这里就出现了不止一次的成功响应  
  
那作为开发者该如何防止这种情况的发生呢？  
### 线程锁  
  
线程锁就是在同时只允许一个线程删改数据，具体实现机制分为读写锁和互斥锁，这两种锁的区别在于:  
- 读写锁就是你在一个图书馆，有很多人来借阅书籍。当有人仅仅是阅读书籍（不修改），那么多个读者可以同时进行，不会互相干扰。但如果有人想要修改或整理书籍（写操作），那么在这段时间内，所有的读者和其他写作者都必须等待。  
  
- 互斥锁就是你去上厕所，你拉完擦完屁股出来后后了别人才能拉。  
  
所以说可以看出来了吗？读写锁更加试用于读操作>>写操作，互斥锁更加适用于写操作≈读操作  
  
这里我们应该采用互斥锁来保证安全:  
```
funcBuyProduct(c *gin.Context) {    var req struct {        ProductID uint`json:"product_id" binding:"required"`        Quantity  int`json:"quantity" binding:"required,gt=0"`    }    if err := c.ShouldBindJSON(&req); err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})        return    }    // 从 JWT 中获取用户名    username, exists := c.Get("username")    if !exists {        c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})        return    }    // 查找用户    userMutex.Lock() // 加锁保护用户资源    var user models.User    if err := database.DB.Preload("Inventory").Where("username = ?", username.(string)).First(&user).Error; err != nil {        userMutex.Unlock()        c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})        return    }    // 查找商品    productMutex.Lock() // 加锁保护商品资源    var product models.Product    if err := database.DB.First(&product, req.ProductID).Error; err != nil {        productMutex.Unlock()        userMutex.Unlock()        c.JSON(http.StatusBadRequest, gin.H{"error": "Product not found"})        return    }    // 检查库存和余额    totalPrice := float64(req.Quantity) * product.Price    if user.Balance < totalPrice {        productMutex.Unlock()        userMutex.Unlock()        c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient balance"})        return    }    if product.Stock < req.Quantity {        productMutex.Unlock()        userMutex.Unlock()        c.JSON(http.StatusBadRequest, gin.H{"error": "Insufficient stock"})        return    }    // 更新用户余额和商品库存    user.Balance -= totalPrice    product.Stock -= req.Quantity    // 更新用户的库存    var inventoryItem models.InventoryItem    if err := database.DB.Where("user_id = ? AND product_id = ?", user.ID, product.ID).First(&inventoryItem).Error; err == nil {        inventoryItem.Quantity += req.Quantity        database.DB.Save(&inventoryItem)    } else {        newInventoryItem := models.InventoryItem{            UserID:    user.ID,            ProductID: product.ID,            Quantity:  req.Quantity,        }        database.DB.Create(&newInventoryItem)    }    // 保存更改    database.DB.Save(&user)    database.DB.Save(&product)    productMutex.Unlock() // 解锁商品资源    userMutex.Unlock()    // 解锁用户资源    c.JSON(http.StatusOK, gin.H{"message": "Purchase successful"})}
```  
  
具体流程图:  
  
![image.png](https://mmbiz.qpic.cn/mmbiz_png/iar31WKQlTTqeeWuE30PtXkw7Y3skMCvGqaZgSKuDSrB7dvYhcp6Tb7WGmib4yiaGlX2y99yNRYwdUAwibQkhPC4dg/640?wx_fmt=png&from=appmsg&tp=wxpic&wxfrom=5&wx_lazy=1&wx_co=1 "")  
## 传参式越权漏洞  
  
这个就很好理解了，就是鉴权不充分嘛  
  
例如有的新手开发者（比如我）就会直接从用户传参中获取username从而判断具体是那个用户来操作:  
  
还是回到刚刚buyProducts  
的hanlder的例子:  
```
funcBuyProduct(c *gin.Context) {    var req struct {        Username  string`json:"username" binding:"required"`        ProductID uint   `json:"product_id" binding:"required"`        Quantity  int    `json:"quantity" binding:"required,gt=0"`    }    var user models.User    if err := database.DB.Preload("Inventory").Where("username = ?", req.Username).First(&user).Error; err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})        return    }
```  
  
这里就是通过用户传参来判断是那个用户来购买了那样东西，所以假设A用户传参了如下payload:  
```
{"username":"B","product_id":1,"quantity":1}
```  
  
他就会帮助B用户买id为1的商品了，还有一个更有危害的例子,比如返回个人信息的接口是通过用户传参来判断的话，那是否可以通过遍历用户id从而获取到所有人的身份信息呢？答案是肯定的  
### 如何解决  
  
这个问题的核心是太过信任用户的传参了，常见的解决方式是通过校验的cookie,比如jwt（json web token  
）来实现身份的判定，比如我这里创建一个用于校验的中间件:  
```
package middlewareimport (    "go2shop/internal/models"    "net/http"    "os"    "strings"    "github.com/gin-gonic/gin"    "github.com/golang-jwt/jwt/v4")// 定义全局变量 jwtKeyvar jwtKey []byte// 初始化函数，用于从环境变量中加载 JWT 密钥funcinit() {    jwtSecret := os.Getenv("JWT_SECRET")    if jwtSecret == "" {        jwtSecret = "test-key"    }    jwtKey = []byte(jwtSecret)}// AuthMiddleware 是一个 Gin 的中间件，用于验证 JWTfuncAuthMiddleware()gin.HandlerFunc {    returnfunc(c *gin.Context) {        // 从请求头中获取 Authorization 字段        authHeader := c.GetHeader("Authorization")        if authHeader == "" {            c.JSON(http.StatusUnauthorized, gin.H{"error": "Authorization header missing"})            c.Redirect(http.StatusFound, "/login")            c.Abort()            return        }        parts := strings.Split(authHeader, " ")        iflen(parts) != 2 || parts[0] != "Bearer" {            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid Authorization header format"})            c.Redirect(http.StatusFound, "/login")            c.Abort()            return        }        // 提取 token        tokenStr := parts[1]        claims := &models.Claims{}        // 解析 JWT        token, err := jwt.ParseWithClaims(tokenStr, claims, func(token *jwt.Token)(interface{}, error) {            // 验证签名算法是否为 HS256            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {                returnnil, jwt.ErrInvalidKeyType            }            return jwtKey, nil        })        // 检查解析是否成功以及 token 是否有效        if err != nil || !token.Valid {            c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})            c.Redirect(http.StatusFound, "/login")            c.Abort()            return        }        // 将用户信息存入上下文，供后续处理使用        c.Set("username", claims.Username)        c.Next()    }}
```  
  
然后在main.go中使用它:  
```
funcmain() {    // 初始化数据库    database.InitDatabase()    // 初始化 Gin 引擎    r := gin.Default()    r.LoadHTMLGlob("templates/*")    // 路由    r.POST("/register", handlers.RegisterUser)    r.GET("/register", func(c *gin.Context) {        c.HTML(http.StatusOK, "register.html", gin.H{            "title": "用户注册",        })    })    r.POST("/login", handlers.LoginUser)    r.GET("/login", func(c *gin.Context) {        c.HTML(http.StatusOK, "login.html", gin.H{            "title": "用户登录",        })    })    auth := r.Group("/store")    auth.Use(middleware.AuthMiddleware())    {        r.GET("/products", handlers.GetProducts)        r.POST("/buy", handlers.BuyProduct)        r.POST("/sell", handlers.SellProduct)        r.POST("/getflag", handlers.GetFlag)        r.POST("/getbalance", handlers.GetUserBalance)        r.POST("/getinventory", handlers.GetUserInventory)        r.GET("/", func(c *gin.Context) {            c.HTML(http.StatusOK, "store.html", gin.H{                "title": "商城",            })        })    }    // 启动服务器    r.Run(":8080")}
```  
  
这里像是在store后面的路由就是受到保护的路由。  
  
但是你以为这就完了？  
## 目录穿越式的越权漏洞  
  
虽然go的gin框架没有这个漏洞，但是这个洞还是挺有意思的（没想到吧，目录穿越不止可以用来读取文件）。  
  
就比如早期版本的apache shiro:  
  
奇安信攻防社区-浅谈Apache shiro 权限绕过漏洞（CVE-2023-34478）  
  
大致原理就是规范路由在鉴权之后，导致鉴权失效。比如:  
```
GET /login/../admin/dashboard
```  
  
在鉴权中间件看来：/login  
开头，嗯，是普通路由，过。  
  
但是规范后：  
```
GET /admin/dashboard
```  
  
就是后台地址了，这样就绕过鉴权了  
## 鉴权不完全式越权  
  
这其中就包括水平越权和垂直越权，其实二者是一回事,就是后端鉴权不充分的，也就是鉴了但是没有完全鉴，俗称后端开发有点鉴，我来举个例子:  
  
例如这里有个专门重置密码的api:  
```
funcUpdatePassword(c *gin.Context) {    var req struct {        Username    string`json:"username" binding:"required"`     // 用户名        NewPassword string`json:"new_password" binding:"required"`// 新密码    }    // 绑定 JSON 数据    if err := c.ShouldBindJSON(&req); err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})        return    }    // 查找用户    var user models.User    if err := database.DB.Where("username = ?", req.Username).First(&user).Error; err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": "User not found"})        return    }    // 对新密码进行哈希处理    hashedPassword := req.NewPassword    // 更新用户密码    user.Password = hashedPassword    if err := database.DB.Save(&user).Error; err != nil {        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update password"})        return    }    c.JSON(http.StatusOK, gin.H{"message": "Password updated successfully"})}
```  
  
在主函数中做了鉴权处理:  
```
package main ...auth.Use(middleware.AuthMiddleware()) { r.POST("/resetpwd", handlers.UpdatePassword) }
```  
  
看上去很好对吧，在重置密码前先检查是否有登录，其实这里犯了安全中的大忌。  
  
假设我是用户A，我觊觎用户B的用户，我这里首先用自己的cookie过middleware.AuthMiddleware  
的鉴权，所以我能够成功访问/resetpwd  
路由，但注意我实际上可以通过  
```
Username    string`json:"username" binding:"required"`
```  
  
这里直接传参B就能修改B的密码了，但要主要不是所有不同cookie的返回相同数据接口都是水平越权，还是得结合具体的业务，比如：  
```
funcGetProducts(c *gin.Context) {    var products []models.Product    if err := database.DB.Find(&products).Error; err != nil {        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to fetch products"})        return    }    c.JSON(http.StatusOK, products)}
```  
  
你看，这个就是列出所有的商品接口，但其实是个人来买东西都是需要看的，所以这里就不构成越权。  
**那具体是该如何解决呢？**  
  
你会发现上面的从jwt  
中提取用户名是能够很好的防止篡改，因为攻击者无法在没有key伪造jwt，换言之，每次修改密码，我都会间接的通过jwt再次鉴权一次，这就是提高了鉴权的颗粒度。但是这个操作只能够防止黑客通过传参冒充其他用户，阻止不了在后端访问数据库。  
### 后端权限错配式越权  
  
比如这里有个上架商品的路由：  
```
funcAddProduct(c *gin.Context) {    var req struct {        Name  string`json:"name" binding:"required"`        Price float64`json:"price" binding:"required"`        Stock int     `json:"stock" binding:"required,gt=0"`    }    if err := c.ShouldBindJSON(&req); err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})        return    }    product := &models.Product{        Name:  req.Name,        Price: req.Price,        Stock: req.Stock,    }    if err := database.DB.Create(product).Error; err != nil {        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create product"})        return    }    c.JSON(http.StatusOK, product)}
```  
  
在主函数中也是进过了鉴权:  
```
auth := r.Group("/store")auth.Use(middleware.AuthMiddleware()){r.POST("/addproduct", handlers.AddProduct)}
```  
  
但是这里没有做任何校验该用户是否能够访问数据库，就能够导致任意的用户添加商品。比如我给自己添加一个价格为-1000  
元的商品然后嘎嘎买，每次买我的余额都会+1000  
，实现刷钱。那作为开发者该如何防范？  
### RBAC开发原则  
  
最简单的，我在每次执行该业务的时候都去添加这样一条  
```
...if currentuser=="admin" {    //业务逻辑}
```  
  
这种写死的方式固然安全，但是在实际业务中，我们经常会涉及到一个业务的权限的动态变更，所以更好的方式是用一个专门的数据库来存  
  
我最基础的用户类型设计如下：  
```
package modelsimport"gorm.io/gorm"// InventoryItem 用户库存中的商品type InventoryItem struct {    gorm.Model    UserID    uint`json:"user_id"`    // 外键，关联 User 表    ProductID uint`json:"product_id"`// 外键，关联 Product 表    Quantity  int`json:"quantity"`   // 商品数量}// User 用户模型type User struct {    ID        uint            `gorm:"primaryKey" json:"id"`    Username  string          `gorm:"unique;not null" json:"username"`    Password  string          `json:"-"`    Balance   float64         `json:"balance"`    Inventory []InventoryItem `gorm:"foreignKey:UserID" json:"inventory"`// 用户库存，持久化字段}
```  
  
我可以在其中添加一条专门用于记录权限的数据类型并且与用户类型关联，并且通过Role来链接:  
```
package modelsimport"gorm.io/gorm"// Role 角色模型type Role struct {    gorm.Model    Name        string       `gorm:"unique;not null" json:"name"`// 角色名称，例如 "Admin", "User"    Description string       `json:"description"`                // 角色描述    Users       []User       `gorm:"many2many:user_roles;" json:"users"`// 与用户的多对多关系    Permissions []Permission `gorm:"many2many:role_permissions;" json:"permissions"`// 与权限的多对多关系}// Permission 权限模型type Permission struct {    gorm.Model    Name        string`gorm:"unique;not null" json:"name"`// 权限名称，例如 "ManageUsers", "ViewProducts"    Description string`json:"description"`                // 权限描述    Roles       []Role `gorm:"many2many:role_permissions;" json:"roles"`// 与角色的多对多关系}// User 用户模型type User struct {    gorm.Model    Username  string          `gorm:"unique;not null" json:"username"`    Password  string          `json:"-"`    Balance   float64         `json:"balance"`    Inventory []InventoryItem `gorm:"foreignKey:UserID" json:"inventory"`// 用户库存    Roles     []Role          `gorm:"many2many:user_roles;" json:"roles"`// 与角色的多对多关系}// InventoryItem 用户库存中的商品type InventoryItem struct {    gorm.Model    UserID    uint`json:"user_id"`    // 外键，关联 User 表    ProductID uint`json:"product_id"`// 外键，关联 Product 表    Quantity  int`json:"quantity"`   // 商品数量}
```  
  
而在处理具体的业务比如addproduct  
的时候  
  
添加这样代码:  
```
user := currentUser.(*models.User)    hasPermission := checkUserPermission(user, "AddProduct")    if !hasPermission {        c.JSON(http.StatusForbidden, gin.H{"error": "You do not have permission to perform this action"})        return    }
```  
  
这个checkUserPermission  
函数具体操作为去数据库中先检查一边是否有对应的权限：  
```
funccheckUserPermission(user *models.User, permissionName string)bool {    // 预加载用户的角色和角色的权限    var dbUser models.User    err := database.DB.Preload("Roles.Permissions").First(&dbUser, user.ID).Error    if err != nil {        returnfalse    }    for _, role := range dbUser.Roles {        for _, permission := range role.Permissions {            if permission.Name == permissionName {                returntrue            }        }    }    returnfalse}
```  
  
这个就是RBAC原则了，即**Role-Based Access Control**  
，基于角色的访问控制。它通过将权限分配给角色，并将用户与角色关联，从而实现对系统资源的访问控制。RBAC 的核心思想是 **“用户 -> 角色 -> 权限”**  
，即用户不直接拥有权限，而是通过角色间接获得权限。这样就可以灵活简洁的预防越权的产生  
## 数值相关漏洞  
  
从最简单的倒卖漏洞入手  
### 倒买漏洞  
  
如果商家没有校验购买数量，那我就可以买-1个苹果，这样商家反而会倒贴我钱。这时候有的开发者就说了，那不简单，我只要限制用户输入必须为正数不就好了吗？  
  
白帽子微微一笑，事情并没那么简单  
### 整数溢出  
  
故名思意，就是在数据转化的过程中出现了漏洞,这其实是所有强类型语言的通病。例如在2023年的0xGame新生赛中，有道题目Goshop的一部分：  
```
funcBuyHandler(c *gin.Context) {    s := sessions.Default(c)    user := users[s.Get("id").(string)]    data := make(map[string]interface{})    c.ShouldBindJSON(&data)    var product *Product    for _, v := range products {        if data["name"] == v.Name {            product = v            break        }    }    if product == nil {        c.JSON(200, gin.H{            "message": "No such product",        })        return    }    n, _ := strconv.Atoi(data["num"].(string))    if n < 0 {        c.JSON(200, gin.H{            "message": "Product num can't be negative",        })        return    }    if user.Money >= product.Price*int64(n) {        user.Money -= product.Price * int64(n)        user.Items[product.Name] += int64(n)        c.JSON(200, gin.H{            "message": fmt.Sprintf("Buy %v * %v success", product.Name, n),        })    } else {        c.JSON(200, gin.H{            "message": "You don't have enough money",        })    }}
```  
  
其中:  
```
if user.Money >= product.Price*int64(n)
```  
  
这里虽然检查商品数量不能够为负数，但是并没有限制商品数量最多有多大就直接把用户的传参n  
转化为int64，所以当我输入一个比2^64-1还大的整数比如：n=9223372036854775808  
就会在后续的处理中由正数变负数。到这里user.Money -= product.Price * int64(n)  
就会余额增加。还是被攻破了。  
  
开发者：好好好，这么玩是吧？那我每个数据都做类型校验，总没有漏洞了把？  
### 叠加式数据溢出漏洞  
  
比如一个打赏机制:  
```
package mainimport (    "net/http"    "github.com/gin-gonic/gin")type OrderRequest struct {    ProductID uint32`json:"product_id" binding:"required"`    Price     uint32`json:"price" binding:"required"`    Tip       uint32`json:"tip"`}type Order struct {    OrderID     uint32`json:"order_id"`    ProductID   uint32`json:"product_id"`    Price       uint32`json:"price"`    Tip         uint32`json:"tip"`    TotalAmount uint32`json:"total_amount"`}var orderCounter uint32 = 0// CreateOrder 创建订单的处理函数funcCreateOrder(c *gin.Context) {    var req OrderRequest    if err := c.ShouldBindJSON(&req); err != nil {        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})        return    }    // 计算总金额（潜在的溢出风险）    total := req.Price + req.Tip    orderCounter++    order := Order{        OrderID:     orderCounter,        ProductID:   req.ProductID,        Price:       req.Price,        Tip:         req.Tip,        TotalAmount: total,    }    c.JSON(http.StatusOK, order)}funcmain() {    r := gin.Default()    r.POST("/create_order", CreateOrder)    r.Run(":8080")}
```  
  
这会我们的开发同志可算长了个心眼，处处都对用户传参做了校验：我们再去使用超级大的整数传参的时候就直接报了错：  
```
┌──(technerd㉿LAPTOP-0A5TQ0RL)-[~]└─$ curl -X POST http://localhost:8080/create_order -H "Content-Type: application/json" -d '{"product_id": 2, "price":3000, "tip": 4294967296}'{"error":"json: cannot unmarshal number 4294967296 into Go struct field OrderRequest.tip of type uint32"}
```  
  
でも，这个生成订单的时候可是没有判断生成总金额是否是符合规范的最终造成了溢出，  
```
┌──(technerd㉿LAPTOP-0A5TQ0RL)-[~]└─$ curl -X POST http://localhost:8080/create_order -H "Content-Type: application/json" -d '{"product_id": 2, "price":3000, "tip": 4294964297}'{"order_id":4,"product_id":2,"price":3000,"tip":4294964297,"total_amount":1}┌──(technerd㉿LAPTOP-0A5TQ0RL)-[~]└─$
```  
  
一块钱，给主播打赏42亿元.jpg  
  
这个其实是类似于sql注入中二次注入的思路，在业务执行过程中出现了漏洞，不得不让人感慨安全的开发属实不容易啊  
  
  
黑白之道发布、转载的文章中所涉及的技术、思路和工具仅供以安全为目的的学习交流使用，任何人不得将其用于非法用途及盈利等目的，否则后果自行承担！  
  
如侵权请私聊我们删文  
  
  
**END**  
  
  
