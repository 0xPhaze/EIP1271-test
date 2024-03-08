// SPDX-License-Identifier: UNLICENSED
pragma solidity ^0.8.0;

import "forge-std/Test.sol";
import "solmate/test/utils/mocks/MockERC20.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/SignatureChecker.sol";
import "openzeppelin-contracts/contracts/utils/cryptography/EIP712.sol";

contract SimpleStableSwap {
    MockERC20 token0;
    MockERC20 token1;

    constructor(MockERC20 token0_, MockERC20 token1_) {
        token0 = token0_;
        token1 = token1_;
    }

    /// This function is always authorized by `msg.sender`.
    /// This function requires previous token0 spending allowances by `msg.sender`.
    function swap(uint256 amount) public {
        address from = msg.sender;
        address to = msg.sender;

        token0.transferFrom(from, address(this), amount);
        token1.transfer(to, amount);
    }
}

contract StableSwap is SimpleStableSwap, EIP712("StableSwap", "1") {
    constructor(MockERC20 token0_, MockERC20 token1_) SimpleStableSwap(token0_, token1_) {}

    struct SwapData {
        address to;
        uint256 amount;
        uint256 nonce;
        uint256 deadline;
    }

    mapping(address signer => uint256 nonce) public nonces;

    function hashSwapData(SwapData memory swapData) public view returns (bytes32) {
        return _hashTypedDataV4(
            keccak256(
                abi.encode(keccak256("SwapData(address to,uint256 amount,uint256 nonce,uint256 deadline)"), swapData)
            )
        );
    }

    /// Verify that `from` has authorized this swap.
    modifier requireValidSignature(address from, bytes32 hash, bytes memory sig) {
        require(SignatureChecker.isValidSignatureNow(from, hash, sig), "Invalid authorization");
        _;
    }

    /// This function requires a check for authorization by `from`.
    /// This function requires previous token0 spending allowances by `from`.
    function swapWithAuthorization(address from, SwapData memory swapData, bytes calldata sig)
        public
        virtual
        requireValidSignature(from, hashSwapData(swapData), sig)
    {
        // Validate swap requirements.
        require(block.timestamp < swapData.deadline, "Deadline passed");
        require(++nonces[from] == swapData.nonce, "Invalid nonce");

        // Do the swap.
        token0.transferFrom(from, address(this), swapData.amount);
        token1.transfer(swapData.to, swapData.amount);
    }
}

contract BuggyStableSwap is StableSwap {
    constructor(MockERC20 token0_, MockERC20 token1_) StableSwap(token0_, token1_) {}

    /// This function is missing a valid signature authentication.
    function swapWithAuthorization(address from, SwapData memory swapData, bytes32 swapDataHash, bytes calldata sig)
        public
        // Note: Because we don't produce the `hash` ourselves and let
        // `msg.sender` provide the hash—`swapDataHash` can be correctly signed,
        // but contain a entirely unrelated hash value.
        requireValidSignature(from, swapDataHash, sig)
    {
        // Validate swap requirements.
        require(block.timestamp < swapData.deadline, "Deadline passed");
        require(++nonces[from] == swapData.nonce, "Invalid nonce");

        // Do the swap.
        token0.transferFrom(from, address(this), swapData.amount);
        token1.transfer(swapData.to, swapData.amount);
    }
}

contract SmartWallet is EIP712("SmartWallet", "1") {
    address manager;

    constructor(address manager_) {
        manager = manager_;
    }

    function isValidSignature(bytes32 hash, bytes calldata sig) public view returns (bytes4) {
        // Note: to distinguish between signatures that authorize a swap from `manager` directly,
        // vs. a swap where the manager signals that a swap is authorized by this smart wallet,
        // the hash should be wrapped again to contain `address(this)`.
        // e.g: `hash = _hashTypedDataV4(hash);`
        return SignatureChecker.isValidSignatureNow(manager, hash, sig) ? IERC1271.isValidSignature.selector : bytes4(0);
    }
}

contract ContractTest is Test {
    MockERC20 token0;
    MockERC20 token1;
    StableSwap dex;
    SmartWallet wallet;
    address manager;
    uint256 managerPk;

    function setUp() public {
        (manager, managerPk) = makeAddrAndKey("Manager");
        token0 = new MockERC20("TKN0", "TKN0", 18);
        token1 = new MockERC20("TKN0", "TKN0", 18);
        dex = new StableSwap(token0, token1);
        wallet = new SmartWallet(manager);

        token0.mint(address(dex), 1e9 ether);
        token1.mint(address(dex), 1e9 ether);
        token0.mint(address(wallet), 1e3 ether);
        token0.mint(address(wallet), 1e3 ether);
    }

    uint256 amount = 10 ether;

    function testSwap() public {
        // Mock calls from `wallet`.
        vm.startPrank(address(wallet));

        // This swap will fail, because `wallet` has
        // never given token approvals to the protocol.
        vm.expectRevert();
        dex.swap(amount);

        // Now it works.
        token0.approve(address(dex), type(uint256).max);
        dex.swap(amount);
    }

    function getSignedSwapData(StableSwap dex_, uint256 pk)
        internal
        view
        returns (StableSwap.SwapData memory swapData, bytes memory sig)
    {
        swapData =
            StableSwap.SwapData({to: address(0xa11ce), amount: amount, nonce: 1, deadline: block.timestamp + 1 days});
        bytes32 hash = dex_.hashSwapData(swapData);
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(pk, hash);
        sig = abi.encodePacked(r, s, v);
    }

    function testSwapWithAuthorization() public {
        // Prepare `SwapData` and sign using `manager`'s private key.
        (StableSwap.SwapData memory swapData, bytes memory sig) = getSignedSwapData(dex, managerPk);

        // Even though the signature is valid, the call will fail:
        // `wallet` hasn't given `token0` authorization.
        vm.expectRevert(stdError.arithmeticError);
        dex.swapWithAuthorization(address(wallet), swapData, sig);

        // `wallet` gives `token0` approval.
        vm.prank(address(wallet));
        token0.approve(address(dex), type(uint256).max);

        // Now the swap will succeed.
        dex.swapWithAuthorization(address(wallet), swapData, sig);
    }

    function testSwapWithAuthorization_revert() public {
        // Prepare `SwapData` and sign using `manager`'s private key.
        (StableSwap.SwapData memory swapData, bytes memory sig) = getSignedSwapData(dex, managerPk);

        // Note: We can include a `msg.sender` check inside `SmartWallet`.
        // It doesn't hurt. However, any other protocol trying to move tokens
        // from `wallet` will require token approvals first.

        // Try letting another Dex `dex2` execute a swap.
        StableSwap dex2 = new StableSwap(token0, token1);
        token0.mint(address(dex2), 1e9 ether);
        token1.mint(address(dex2), 1e9 ether);

        // Call will fail due to a mismatch in the signed `hash`
        // value returned by `dex2.hashSwapData`. It contains `dex2`
        // as the `verifyingContract` parameter.
        vm.expectRevert("Invalid authorization");
        dex2.swapWithAuthorization(address(wallet), swapData, sig);
        // The hashes to sign differ.
        assertTrue(dex.hashSwapData(swapData) != dex2.hashSwapData(swapData));

        // Try letting a buggy Dex `dex3` execute a swap.
        // This Dex incorrectly validates signatures.
        BuggyStableSwap dex3 = new BuggyStableSwap(token0, token1);
        token0.mint(address(dex3), 1e9 ether);
        token1.mint(address(dex3), 1e9 ether);

        // We are providing a valid signature meant for another Dex `dex`, but not `dex3`.
        bytes32 swapDataHash = dex.hashSwapData(swapData);
        // Even though the signature is valid, the swap fails because `wallet` has never authorized `dex3`
        vm.expectRevert(stdError.arithmeticError);
        dex3.swapWithAuthorization(address(wallet), swapData, swapDataHash, sig);

        // Only after `wallet`'s explicit token spending approval to `dex3`
        // would this call to a buggy dex work.
        vm.prank(address(wallet));
        token0.approve(address(dex3), type(uint256).max);
        dex3.swapWithAuthorization(address(wallet), swapData, dex.hashSwapData(swapData), sig);
    }
}
