import { DefenseRecommendation, Vulnerability } from '../types';

interface DefenseTemplate {
  issue: (fn: string) => string;
  strategy: string;
  codeExample: string;
}

const defenseTemplates: Record<string, DefenseTemplate> = {
  reentrancy: {
    issue: (fn: string) => `Reentrancy in ${fn}()`,
    strategy:
      'Apply the Checks-Effects-Interactions (CEI) pattern: always update state variables BEFORE making external calls. Additionally, add OpenZeppelin ReentrancyGuard for defense-in-depth.',
    codeExample: `// SECURE: Checks-Effects-Interactions pattern
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract SecureBank is ReentrancyGuard {
    mapping(address => uint256) public balances;

    function withdraw(uint256 amount) public nonReentrant {
        require(balances[msg.sender] >= amount, "Insufficient balance");

        // EFFECT: Update state BEFORE external call
        balances[msg.sender] -= amount;

        // INTERACTION: External call is now safe
        (bool success, ) = msg.sender.call{value: amount}("");
        require(success, "Transfer failed");
    }
}`,
  },
  'tx-origin': {
    issue: (fn: string) => `tx.origin Authentication in ${fn}()`,
    strategy:
      'Replace all tx.origin checks with msg.sender. Use OpenZeppelin Ownable for ownership patterns. Never use tx.origin for authentication in any production contract.',
    codeExample: `// SECURE: Use msg.sender instead of tx.origin
import "@openzeppelin/contracts/access/Ownable.sol";

contract SecureContract is Ownable {
    constructor() Ownable(msg.sender) {}

    // SECURE: onlyOwner modifier uses msg.sender internally
    function emergencyAction() public onlyOwner {
        // Safe - uses msg.sender, not tx.origin
        payable(owner()).transfer(address(this).balance);
    }
}`,
  },
  'unprotected-selfdestruct': {
    issue: (fn: string) => `Unprotected selfdestruct in ${fn}()`,
    strategy:
      'Remove selfdestruct entirely if possible — it is deprecated in Solidity 0.8.18+ (EIP-6049). If required, gate it behind a multi-signature timelock with at least a 48-hour delay. Never combine with tx.origin auth.',
    codeExample: `// SECURE: Remove selfdestruct, use upgradeable pattern instead
import "@openzeppelin/contracts/access/AccessControl.sol";

contract SecureContract is AccessControl {
    bytes32 public constant ADMIN_ROLE = keccak256("ADMIN_ROLE");

    constructor() {
        _grantRole(DEFAULT_ADMIN_ROLE, msg.sender);
        _grantRole(ADMIN_ROLE, msg.sender);
    }

    // SECURE: Pause instead of destroy, with role-based access
    bool public paused;

    function emergencyPause() public onlyRole(ADMIN_ROLE) {
        paused = true;
        emit ContractPaused(msg.sender);
    }

    // If withdrawal is needed: withdraw to owner, don't destroy
    function emergencyWithdraw() public onlyRole(ADMIN_ROLE) {
        uint256 balance = address(this).balance;
        payable(msg.sender).transfer(balance);
    }
}`,
  },
  'unsafe-delegatecall': {
    issue: (fn: string) => `Unsafe delegatecall in ${fn}()`,
    strategy:
      'Never delegatecall to untrusted or user-supplied addresses. Use OpenZeppelin\'s transparent or UUPS proxy pattern which isolates storage layouts and validates implementation addresses.',
    codeExample: `// SECURE: Use OpenZeppelin UUPS Proxy pattern
import "@openzeppelin/contracts-upgradeable/proxy/utils/UUPSUpgradeable.sol";
import "@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";

contract SecureUpgradeable is UUPSUpgradeable, OwnableUpgradeable {
    function initialize() public initializer {
        __Ownable_init(msg.sender);
        __UUPSUpgradeable_init();
    }

    // Only owner can upgrade — no arbitrary delegatecall
    function _authorizeUpgrade(address newImplementation)
        internal
        override
        onlyOwner
    {}
}`,
  },
  'integer-overflow': {
    issue: (fn: string) => `Integer Overflow/Underflow in ${fn}()`,
    strategy:
      'Upgrade to Solidity ^0.8.0 which has built-in overflow protection. For legacy code, use OpenZeppelin SafeMath. For custom math, add explicit bounds checking with require() statements.',
    codeExample: `// SECURE: Solidity 0.8+ with built-in overflow protection
pragma solidity ^0.8.0;

contract SecureArithmetic {
    mapping(address => uint256) public balances;

    function deposit() public payable {
        // Safe in 0.8+: will revert on overflow
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) public {
        // Safe in 0.8+: will revert on underflow
        require(balances[msg.sender] >= amount, "Insufficient");
        balances[msg.sender] -= amount;
        payable(msg.sender).transfer(amount);
    }
}`,
  },
};

export function generateDefenseRecommendations(
  vulnerabilities: Vulnerability[]
): DefenseRecommendation[] {
  const seen = new Set<string>();
  const recommendations: DefenseRecommendation[] = [];

  for (const vuln of vulnerabilities) {
    if (seen.has(vuln.type)) continue;
    seen.add(vuln.type);

    const template = defenseTemplates[vuln.type];
    if (template) {
      recommendations.push({
        issue: template.issue(vuln.function),
        strategy: template.strategy,
        codeExample: template.codeExample,
      });
    } else {
      recommendations.push({
        issue: `Security issue in ${vuln.function}()`,
        strategy:
          'Review this function for missing access controls, input validation, and state management. Apply principle of least privilege and fail-safe defaults.',
        codeExample: `// General security pattern
modifier onlyAuthorized() {
    require(msg.sender == authorizedAddress, "Not authorized");
    _;
}

function sensitiveOperation() public onlyAuthorized {
    // Validate inputs
    // Update state
    // Then interact with external contracts
}`,
      });
    }
  }

  if (recommendations.length === 0) {
    recommendations.push({
      issue: 'No critical vulnerabilities detected',
      strategy:
        'Your contract follows secure patterns. Continue to use OpenZeppelin libraries, write comprehensive tests, and conduct regular audits.',
      codeExample: `// Best practices checklist:
// ✅ Use OpenZeppelin contracts for standard patterns
// ✅ Follow Checks-Effects-Interactions
// ✅ Emit events for all state changes
// ✅ Use msg.sender not tx.origin
// ✅ Solidity 0.8+ for overflow protection
// ✅ Apply nonReentrant where needed`,
    });
  }

  return recommendations;
}
