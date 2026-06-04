export interface FixTemplate {
  type: string;
  vulnerable_pattern: string;
  fixed_pattern: string;
  steps: string[];
  oz_import: string;
  oz_link: string;
}

export const fixTemplates: FixTemplate[] = [
  {
    type: 'reentrancy',
    vulnerable_pattern: `// VULNERABLE: state updated after external call
function withdraw(uint amount) external {
    require(balances[msg.sender] >= amount);
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount; // too late
}`,
    fixed_pattern: `// FIXED: CEI pattern + ReentrancyGuard
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw(uint amount) external nonReentrant {
        require(balances[msg.sender] >= amount);
        balances[msg.sender] -= amount; // effects first
        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok);
    }
}`,
    steps: [
      'Apply Checks-Effects-Interactions: update state before the external call',
      'Add nonReentrant modifier from OpenZeppelin ReentrancyGuard',
      'Verify all withdrawal paths follow CEI order',
    ],
    oz_import: "@openzeppelin/contracts/security/ReentrancyGuard.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/utils#ReentrancyGuard',
  },
  {
    type: 'tx-origin',
    vulnerable_pattern: `// VULNERABLE: tx.origin for auth
function transfer(address to, uint amount) external {
    require(tx.origin == owner); // phishing bypass
    balances[to] += amount;
}`,
    fixed_pattern: `// FIXED: use msg.sender
import "@openzeppelin/contracts/access/Ownable.sol";
contract Safe is Ownable {
    function transfer(address to, uint amount) external onlyOwner {
        balances[to] += amount;
    }
}`,
    steps: [
      'Replace tx.origin with msg.sender for all authentication checks',
      'Use OpenZeppelin Ownable or AccessControl for role management',
      'Never use tx.origin to determine transaction authorization',
    ],
    oz_import: "@openzeppelin/contracts/access/Ownable.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/access#Ownable',
  },
  {
    type: 'unprotected-selfdestruct',
    vulnerable_pattern: `// VULNERABLE: anyone can destroy
function kill() external {
    selfdestruct(payable(msg.sender));
}`,
    fixed_pattern: `// FIXED: restrict with onlyOwner
import "@openzeppelin/contracts/access/Ownable.sol";
contract Safe is Ownable {
    function kill() external onlyOwner {
        selfdestruct(payable(owner()));
    }
}`,
    steps: [
      'Add onlyOwner or access control modifier to any selfdestruct function',
      'Consider removing selfdestruct entirely (deprecated in EIP-6049)',
      'Use Ownable from OpenZeppelin to manage privileged operations',
    ],
    oz_import: "@openzeppelin/contracts/access/Ownable.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/access#Ownable',
  },
  {
    type: 'unsafe-delegatecall',
    vulnerable_pattern: `// VULNERABLE: user-controlled target
function exec(address impl, bytes calldata data) external {
    impl.delegatecall(data); // attacker controls impl
}`,
    fixed_pattern: `// FIXED: whitelist trusted implementations
mapping(address => bool) public trustedImpls;
function exec(address impl, bytes calldata data) external onlyOwner {
    require(trustedImpls[impl], "Untrusted impl");
    impl.delegatecall(data);
}`,
    steps: [
      'Never delegatecall to user-supplied addresses',
      'Maintain an explicit whitelist of trusted implementation contracts',
      'Use OpenZeppelin UUPS or Transparent Proxy for upgradeable patterns',
    ],
    oz_import: "@openzeppelin/contracts/proxy/utils/UUPSUpgradeable.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/proxy#UUPSUpgradeable',
  },
  {
    type: 'integer-overflow',
    vulnerable_pattern: `// VULNERABLE: Solidity <0.8, no SafeMath
function deposit(uint amount) external {
    balances[msg.sender] += amount; // can overflow
}`,
    fixed_pattern: `// FIXED: Solidity 0.8+ (auto-revert) or SafeMath
// Option A: upgrade to Solidity ^0.8.0 (overflow reverts automatically)
// Option B: use SafeMath for legacy contracts
import "@openzeppelin/contracts/utils/math/SafeMath.sol";
using SafeMath for uint256;
function deposit(uint amount) external {
    balances[msg.sender] = balances[msg.sender].add(amount);
}`,
    steps: [
      'Upgrade to Solidity 0.8+ where overflow/underflow revert automatically',
      'For legacy code, wrap all arithmetic with OpenZeppelin SafeMath',
      'Avoid unchecked{} blocks unless the overflow is intentional and documented',
    ],
    oz_import: "@openzeppelin/contracts/utils/math/SafeMath.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/4.x/api/utils#SafeMath',
  },
  {
    type: 'access-control',
    vulnerable_pattern: `// VULNERABLE: no access restriction
function setPrice(uint newPrice) external {
    price = newPrice; // anyone can call
}`,
    fixed_pattern: `// FIXED: role-based access control
import "@openzeppelin/contracts/access/AccessControl.sol";
contract Safe is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
    function setPrice(uint newPrice) external onlyRole(ADMIN_ROLE) {
        price = newPrice;
    }
}`,
    steps: [
      'Add onlyOwner or role-based modifier to all privileged functions',
      'Use OpenZeppelin AccessControl for granular role management',
      'Audit all external/public functions for missing access restrictions',
    ],
    oz_import: "@openzeppelin/contracts/access/AccessControl.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/access#AccessControl',
  },
  {
    type: 'unchecked-call',
    vulnerable_pattern: `// VULNERABLE: return value ignored
function sendFunds(address to, uint amount) external {
    to.call{value: amount}(""); // failure silently ignored
}`,
    fixed_pattern: `// FIXED: check return value or use Address.sendValue
import "@openzeppelin/contracts/utils/Address.sol";
using Address for address payable;
function sendFunds(address payable to, uint amount) external {
    to.sendValue(amount); // reverts on failure
}`,
    steps: [
      'Always check the bool return value of low-level call()',
      'Prefer Address.sendValue() from OpenZeppelin which reverts automatically',
      'Use transfer() for simple ETH sends (reverts on failure, 2300 gas limit)',
    ],
    oz_import: "@openzeppelin/contracts/utils/Address.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/utils#Address-sendValue-address-payable-uint256-',
  },
  {
    type: 'arbitrary-send',
    vulnerable_pattern: `// VULNERABLE: attacker-controlled recipient
function refund(address payable to) external {
    to.transfer(balance); // to is user-supplied
}`,
    fixed_pattern: `// FIXED: pull-payment pattern
import "@openzeppelin/contracts/security/PullPayment.sol";
contract Safe is PullPayment {
    function requestRefund() external {
        _asyncTransfer(msg.sender, balances[msg.sender]);
        balances[msg.sender] = 0;
    }
}`,
    steps: [
      'Use pull-payment pattern: let users withdraw their own funds',
      'Never transfer ETH to arbitrary user-supplied addresses directly',
      'OpenZeppelin PullPayment handles this pattern securely',
    ],
    oz_import: "@openzeppelin/contracts/security/PullPayment.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/security#PullPayment',
  },
  {
    type: 'timestamp-dependence',
    vulnerable_pattern: `// VULNERABLE: timestamp as randomness
function pickWinner() external {
    uint rand = uint(keccak256(abi.encode(block.timestamp)));
    winner = players[rand % players.length];
}`,
    fixed_pattern: `// FIXED: use Chainlink VRF for randomness
// For time locks: accept ±15 minute tolerance
// For randomness: integrate Chainlink VRF v2
import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";`,
    steps: [
      'Never use block.timestamp or block.number as a source of randomness',
      'For time-gated logic, allow a minimum 15-minute window to avoid manipulation',
      'Use Chainlink VRF v2 for verifiable on-chain randomness',
    ],
    oz_import: "Chainlink VRFConsumerBaseV2",
    oz_link: 'https://docs.chain.link/vrf/v2/introduction',
  },
  {
    type: 'denial-of-service',
    vulnerable_pattern: `// VULNERABLE: unbounded loop
function distributeRewards() external {
    for (uint i = 0; i < recipients.length; i++) {
        recipients[i].transfer(reward); // gas grows unboundedly
    }
}`,
    fixed_pattern: `// FIXED: pull-payment pattern
import "@openzeppelin/contracts/security/PullPayment.sol";
contract Safe is PullPayment {
    function queueReward(address payee) internal {
        _asyncTransfer(payee, reward); // each user pulls their own reward
    }
}`,
    steps: [
      'Replace push-payment loops with pull-payment pattern',
      'If iteration is needed, implement pagination with a cursor and batch size limit',
      'Use OpenZeppelin PullPayment to let users claim their own rewards',
    ],
    oz_import: "@openzeppelin/contracts/security/PullPayment.sol",
    oz_link: 'https://docs.openzeppelin.com/contracts/5.x/api/security#PullPayment',
  },
];

export function getFixTemplate(vulnType: string): FixTemplate | undefined {
  return fixTemplates.find(t => t.type === vulnType);
}
