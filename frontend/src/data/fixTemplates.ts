export interface TieredFix {
  tier: 'SIMPLE' | 'STANDARD' | 'ENTERPRISE';
  description: string;
  steps: string[];
  code_snippet?: string;
  estimated_effort: string;
}

export interface FixTemplate {
  type: string;
  vulnerable_pattern: string;
  fixed_pattern: string;
  steps: string[];
  oz_import: string;
  oz_link: string;
  tiered_fixes: TieredFix[];
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Reorder state update before the external call (CEI pattern)',
        steps: [
          'Move balances[msg.sender] -= amount above the .call()',
          'Verify every exit path updates state before transferring ETH',
        ],
        code_snippet: `balances[msg.sender] -= amount; // effects first
(bool ok,) = msg.sender.call{value: amount}(""); // interactions last
require(ok);`,
        estimated_effort: '< 30 min',
      },
      {
        tier: 'STANDARD',
        description: 'Add OpenZeppelin ReentrancyGuard nonReentrant modifier',
        steps: [
          'Import ReentrancyGuard from OpenZeppelin',
          'Inherit ReentrancyGuard in your contract',
          'Add nonReentrant modifier to all withdrawal functions',
        ],
        code_snippet: `import "@openzeppelin/contracts/security/ReentrancyGuard.sol";
contract Safe is ReentrancyGuard {
    function withdraw(uint amount) external nonReentrant { ... }
}`,
        estimated_effort: '1–2 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Pull-payment architecture with per-user escrow and audit trail',
        steps: [
          'Refactor to pull-payment pattern using OpenZeppelin PullPayment',
          'Add withdrawal delay with time-lock for large amounts',
          'Emit events for all balance changes and enforce invariant checks',
          'Add integration tests covering reentrant attack scenarios',
        ],
        estimated_effort: '1–2 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Replace tx.origin with msg.sender in each require statement',
        steps: [
          'Find all require(tx.origin == ...) and change to require(msg.sender == ...)',
          'Re-test that legitimate callers can still invoke the function',
        ],
        code_snippet: `require(msg.sender == owner, "Not owner");`,
        estimated_effort: '< 15 min',
      },
      {
        tier: 'STANDARD',
        description: 'Use OpenZeppelin Ownable with onlyOwner modifier',
        steps: [
          'Import and inherit Ownable from OpenZeppelin',
          'Replace manual owner checks with onlyOwner modifier',
          'Transfer ownership via transferOwnership() in constructor',
        ],
        code_snippet: `import "@openzeppelin/contracts/access/Ownable.sol";
contract Safe is Ownable {
    function privileged() external onlyOwner { ... }
}`,
        estimated_effort: '1 hour',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Role-based access control with multi-sig governance',
        steps: [
          'Implement OpenZeppelin AccessControl with granular roles',
          'Add multi-sig requirement for critical admin operations',
          'Integrate time-locked governance (TimelockController)',
          'Emit RoleGranted/RoleRevoked events for full audit trail',
        ],
        estimated_effort: '2–3 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Add require(msg.sender == owner) guard to selfdestruct function',
        steps: [
          'Add require(msg.sender == owner, "Not owner") before selfdestruct',
          'Ensure owner is set to a trusted address in constructor',
        ],
        code_snippet: `function kill() external {
    require(msg.sender == owner, "Not owner");
    selfdestruct(payable(owner));
}`,
        estimated_effort: '< 15 min',
      },
      {
        tier: 'STANDARD',
        description: 'Remove selfdestruct and use fund-recovery alternative',
        steps: [
          'Remove selfdestruct entirely per EIP-6049 deprecation',
          'Add emergencyWithdraw() with onlyOwner that transfers all ETH to owner',
          'Use OpenZeppelin Ownable for access control',
        ],
        code_snippet: `function emergencyWithdraw() external onlyOwner {
    (bool ok,) = owner().call{value: address(this).balance}("");
    require(ok);
}`,
        estimated_effort: '2–4 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Upgradeable proxy pattern with time-locked emergency shutdown',
        steps: [
          'Migrate to UUPS upgradeable proxy (selfdestruct not needed)',
          'Add pausable functionality with onlyOwner pause/unpause',
          'Implement time-locked emergency withdrawal with multi-sig approval',
          'Deploy circuit-breaker pattern for automatic fund protection',
        ],
        estimated_effort: '3–5 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Add implementation whitelist with admin-only registration',
        steps: [
          'Create mapping(address => bool) trustedImpls',
          'Add require(trustedImpls[impl]) before delegatecall',
          'Add onlyOwner function to register trusted implementations',
        ],
        code_snippet: `mapping(address => bool) public trustedImpls;
function exec(address impl, bytes calldata data) external {
    require(trustedImpls[impl], "Untrusted impl");
    impl.delegatecall(data);
}`,
        estimated_effort: '1 hour',
      },
      {
        tier: 'STANDARD',
        description: 'Migrate to OpenZeppelin UUPS upgradeable proxy pattern',
        steps: [
          'Import and inherit UUPSUpgradeable + OwnableUpgradeable',
          'Implement _authorizeUpgrade() with onlyOwner',
          'Remove manual delegatecall — proxy handles upgrades securely',
          'Deploy using hardhat-upgrades or foundry upgrade scripts',
        ],
        code_snippet: `import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
contract Safe is UUPSUpgradeable, OwnableUpgradeable {
    function _authorizeUpgrade(address) internal override onlyOwner {}
}`,
        estimated_effort: '1–2 days',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Transparent proxy with time-locked upgrade governance',
        steps: [
          'Use OpenZeppelin TransparentUpgradeableProxy with ProxyAdmin',
          'Gate upgrades behind TimelockController with 48-hour delay',
          'Require multi-sig (Gnosis Safe) approval for implementation changes',
          'Add pre/post-upgrade invariant checks and formal verification',
        ],
        estimated_effort: '1–2 weeks',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Upgrade pragma to Solidity 0.8.x for built-in overflow protection',
        steps: [
          'Change pragma solidity to ^0.8.0 or higher',
          'Recompile and fix any breaking changes (e.g., SafeMath no longer needed)',
          'Test all arithmetic paths to verify revert on overflow',
        ],
        code_snippet: `pragma solidity ^0.8.0;
// Overflow now reverts automatically — no SafeMath needed`,
        estimated_effort: '2–4 hours',
      },
      {
        tier: 'STANDARD',
        description: 'Wrap all arithmetic with OpenZeppelin SafeMath (for legacy 0.7.x)',
        steps: [
          'Import SafeMath and attach to uint256 with using SafeMath for uint256',
          'Replace +, -, *, / with .add(), .sub(), .mul(), .div()',
          'Add input validation with require() for edge cases',
        ],
        code_snippet: `using SafeMath for uint256;
balances[msg.sender] = balances[msg.sender].add(amount);`,
        estimated_effort: '4–8 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Formal verification of arithmetic invariants with full test suite',
        steps: [
          'Migrate to Solidity 0.8+ with typed arithmetic',
          'Add uint256 bounds checking for all external inputs',
          'Write Foundry fuzz tests covering arithmetic boundary conditions',
          'Run formal verification (Certora / Halmos) on arithmetic invariants',
        ],
        estimated_effort: '3–5 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Add require(msg.sender == owner) to each unprotected function',
        steps: [
          'Add owner state variable set in constructor',
          'Add require(msg.sender == owner) to each privileged function',
        ],
        code_snippet: `address public owner;
constructor() { owner = msg.sender; }
modifier onlyOwner() { require(msg.sender == owner); _; }`,
        estimated_effort: '< 1 hour',
      },
      {
        tier: 'STANDARD',
        description: 'Use OpenZeppelin Ownable for single-owner or AccessControl for roles',
        steps: [
          'Inherit Ownable for simple ownership or AccessControl for multi-role',
          'Define role constants with keccak256("ROLE_NAME")',
          'Apply onlyOwner / onlyRole modifiers to all privileged functions',
        ],
        code_snippet: `import "@openzeppelin/contracts/access/AccessControl.sol";
bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");
function setPrice(uint p) external onlyRole(ADMIN_ROLE) { price = p; }`,
        estimated_effort: '2–4 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Multi-sig governance with role hierarchy and audit logging',
        steps: [
          'Implement hierarchical roles: DEFAULT_ADMIN > OPERATOR > USER',
          'Gate role assignments behind multi-sig (Gnosis Safe)',
          'Add time-locked role revocation with 24-hour delay',
          'Emit role-change events and integrate with off-chain monitoring',
        ],
        estimated_effort: '3–5 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Capture and require the bool return value of call()',
        steps: [
          'Change to: (bool ok,) = to.call{value: amount}("")',
          'Add require(ok, "Transfer failed") immediately after',
        ],
        code_snippet: `(bool ok,) = to.call{value: amount}("");
require(ok, "Transfer failed");`,
        estimated_effort: '< 15 min',
      },
      {
        tier: 'STANDARD',
        description: 'Use OpenZeppelin Address.sendValue which reverts on failure',
        steps: [
          'Import Address.sol and attach with using Address for address payable',
          'Replace .call{value:}("") with .sendValue(amount)',
        ],
        code_snippet: `import "@openzeppelin/contracts/utils/Address.sol";
using Address for address payable;
payable(to).sendValue(amount);`,
        estimated_effort: '1 hour',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Pull-payment pattern with per-user claim and retry protection',
        steps: [
          'Replace push payments with OpenZeppelin PullPayment',
          'Record owed amounts in _asyncTransfer — users pull their own funds',
          'Add rate limiting on claims to prevent gas-griefing attacks',
          'Monitor failed claims off-chain and alert on anomalies',
        ],
        estimated_effort: '1–2 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Lock recipient to msg.sender — never accept user-supplied addresses',
        steps: [
          'Remove the address parameter from the function',
          'Always send to msg.sender (the caller proves they control the address)',
        ],
        code_snippet: `function refund() external {
    uint amount = balances[msg.sender];
    balances[msg.sender] = 0;
    payable(msg.sender).transfer(amount);
}`,
        estimated_effort: '< 30 min',
      },
      {
        tier: 'STANDARD',
        description: 'Use OpenZeppelin PullPayment pull model',
        steps: [
          'Import and inherit PullPayment',
          'Queue payouts with _asyncTransfer(msg.sender, amount)',
          'Let users call withdrawPayments(payable(msg.sender))',
        ],
        code_snippet: `import "@openzeppelin/contracts/security/PullPayment.sol";
_asyncTransfer(msg.sender, balances[msg.sender]);
balances[msg.sender] = 0;`,
        estimated_effort: '2–4 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Token-based settlement with batch processing and off-chain signature',
        steps: [
          'Replace ETH transfers with ERC-20 token settlement',
          'Use EIP-2612 permit for gas-free approvals',
          'Add withdrawal whitelist with off-chain KYC verification hook',
          'Implement batched settlement with merkle-proof claim mechanism',
        ],
        estimated_effort: '1–2 weeks',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Add ±15 minute tolerance to time-locked conditions',
        steps: [
          'Replace exact timestamp comparisons with a 15-minute buffer',
          'Document why precision is not required for this use case',
        ],
        code_snippet: `uint constant TOLERANCE = 15 minutes;
require(block.timestamp >= deadline - TOLERANCE, "Too early");`,
        estimated_effort: '< 30 min',
      },
      {
        tier: 'STANDARD',
        description: 'Use Chainlink VRF v2 for verifiable randomness',
        steps: [
          'Subscribe to Chainlink VRF and fund with LINK',
          'Inherit VRFConsumerBaseV2 and implement fulfillRandomWords()',
          'Store the randomness result and use it in next transaction',
        ],
        code_snippet: `import "@chainlink/contracts/src/v0.8/VRFConsumerBaseV2.sol";
function fulfillRandomWords(uint256, uint256[] memory words) internal override {
    winner = players[words[0] % players.length];
}`,
        estimated_effort: '4–8 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Commit-reveal scheme with VRF fallback and multi-party entropy',
        steps: [
          'Phase 1: players submit keccak256(secret + salt) commitments',
          'Phase 2: players reveal secrets; contract XORs all entropy',
          'Fallback to Chainlink VRF if reveal phase times out',
          'Add dispute resolution window with off-chain audit trail',
        ],
        estimated_effort: '3–5 days',
      },
    ],
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
    tiered_fixes: [
      {
        tier: 'SIMPLE',
        description: 'Add a batch size cap to prevent single-call gas exhaustion',
        steps: [
          'Add uint constant MAX_BATCH = 50 (or appropriate limit)',
          'Process only MAX_BATCH entries per call; track cursor offset',
        ],
        code_snippet: `uint constant MAX_BATCH = 50;
function distribute(uint offset) external {
    uint end = Math.min(offset + MAX_BATCH, recipients.length);
    for (uint i = offset; i < end; i++) { ... }
}`,
        estimated_effort: '1–2 hours',
      },
      {
        tier: 'STANDARD',
        description: 'Switch to pull-payment: users claim their own rewards',
        steps: [
          'Use OpenZeppelin PullPayment — queue with _asyncTransfer()',
          'Remove the push loop entirely',
          'Users call withdrawPayments() to claim their reward',
        ],
        code_snippet: `import "@openzeppelin/contracts/security/PullPayment.sol";
// Queue instead of push:
_asyncTransfer(payee, reward);`,
        estimated_effort: '4–8 hours',
      },
      {
        tier: 'ENTERPRISE',
        description: 'Off-chain merkle distribution with on-chain claim verification',
        steps: [
          'Compute reward merkle tree off-chain (e.g., with merkle-distributor)',
          'Store only the merkle root on-chain',
          'Users submit merkle proof to claim; contract verifies and pays once',
          'Track claimed status with bitmap to prevent double-claim at O(1) cost',
        ],
        estimated_effort: '1–2 weeks',
      },
    ],
  },
];

export function getFixTemplate(vulnType: string): FixTemplate | undefined {
  return fixTemplates.find(t => t.type === vulnType);
}
