// SPDX-License-Identifier: GPL-3.0
pragma solidity ^0.8.23;
/* solhint-disable avoid-low-level-calls */
/* solhint-disable no-inline-assembly */

import "../interfaces/IAccount.sol";
import "../interfaces/IAccountExecute.sol";
import "../interfaces/IPaymaster.sol";
import "../interfaces/IEntryPoint.sol";

import "../utils/Exec.sol";
import "./StakeManager.sol";
import "./SenderCreator.sol";
import "./Helpers.sol";
import "./NonceManager.sol";
import "./UserOperationLib.sol";

import "@openzeppelin/contracts/utils/introspection/ERC165.sol";
import "@openzeppelin/contracts/utils/ReentrancyGuard.sol";

/*
 * Account-Abstraction (EIP-4337) singleton EntryPoint implementation.
 * Only one instance required on each chain.
 */

/// @custom:security-contact https://bounty.ethereum.org
contract EntryPoint is IEntryPoint, StakeManager, NonceManager, ReentrancyGuard, ERC165 {
    using UserOperationLib for PackedUserOperation;

    SenderCreator private immutable _senderCreator = new SenderCreator();

    function senderCreator() internal view virtual returns (SenderCreator) {
        return _senderCreator;
    }

    //compensate for innerHandleOps' emit message and deposit refund.
    // allow some slack for future gas price changes.
    uint256 private constant INNER_GAS_OVERHEAD = 10000;

    // Marker for inner call revert on out of gas
    bytes32 private constant INNER_OUT_OF_GAS = hex"deaddead";
    bytes32 private constant INNER_REVERT_LOW_PREFUND = hex"deadaa51";

    uint256 private constant REVERT_REASON_MAX_LEN = 2048;
    uint256 private constant PENALTY_PERCENT = 10;

    /// @inheritdoc IERC165
    function supportsInterface(bytes4 interfaceId) public view virtual override returns (bool) {
        // note: solidity "type(IEntryPoint).interfaceId" is without inherited methods but we want to check everything
        return interfaceId
            == (type(IEntryPoint).interfaceId ^ type(IStakeManager).interfaceId ^ type(INonceManager).interfaceId)
            || interfaceId == type(IEntryPoint).interfaceId || interfaceId == type(IStakeManager).interfaceId
            || interfaceId == type(INonceManager).interfaceId || super.supportsInterface(interfaceId);
    }

    /**
     * Compensate the caller's beneficiary address with the collected fees of all UserOperations.
     * @param beneficiary - The address to receive the fees.
     * @param amount      - Amount to transfer.
     */
    function _compensate(address payable beneficiary, uint256 amount) internal {
        require(beneficiary != address(0), "AA90 invalid beneficiary");
        (bool success,) = beneficiary.call{value: amount}("");
        require(success, "AA91 failed send to beneficiary");
    }

    /**
     * Okay, so this is going to actually execute the user operation... (like increment a counter)
     * @param opIndex    - Index into the opInfo array.
     * @param userOp     - The userOp to execute.
     * @param opInfo     - The opInfo filled by validatePrepayment for this userOp.
     * @return collected - The total amount this userOp paid -- QUESTION: gas?
     */
    function _executeUserOp(uint256 opIndex, PackedUserOperation calldata userOp, UserOpInfo memory opInfo)
        internal
        returns (uint256 collected)
    {
        // 1. get the amount of gas we have left for the transaction
        uint256 preGas = gasleft();

        bytes memory context = getMemoryBytesFromOffset(opInfo.contextOffset);
        bool success;
        {
            uint256 saveFreePtr;
            assembly ("memory-safe") {
                saveFreePtr := mload(0x40)
            }
            bytes calldata callData = userOp.callData;
            bytes memory innerCall;
            bytes4 methodSig;
            assembly {
                let len := callData.length
                // NOTE: if the call data is greater thatn 3, load the method signature
                if gt(len, 3) { methodSig := calldataload(callData.offset) }
            }
            // If the intended method signature is executeUserOp, encode with user op
            if (methodSig == IAccountExecute.executeUserOp.selector) {
                // encode the call with the parameters
                // NOTE: user op has been validated by this point
                // NOTE: the userOp hash is a hash of the userOp

                // NOTE: encode the destination contract's function -- get the bytes
                bytes memory executeUserOp = abi.encodeCall(IAccountExecute.executeUserOp, (userOp, opInfo.userOpHash));

                // NOTE: encode that by calling the innerHandleOp function
                innerCall = abi.encodeCall(this.innerHandleOp, (executeUserOp, opInfo, context));
            } else {
                // NOTE: The intended method sig is not executeUserOp --> so we just pass in call data --> userOp is not passed in
                // QUESTION: it seems to be a question of does the account need the userOp? If not, no need to implement executeUserOp
                // QUESTION: why would it not be execute user op?
                innerCall = abi.encodeCall(this.innerHandleOp, (callData, opInfo, context));
            }
            assembly ("memory-safe") {
                // NOTE: either way, we call inner call (with userOp, or just raw call data)
                success := call(gas(), address(), 0, add(innerCall, 0x20), mload(innerCall), 0, 32)
                collected := mload(0)
                mstore(0x40, saveFreePtr)
            }
        }
        if (!success) {
            bytes32 innerRevertCode;
            assembly ("memory-safe") {
                let len := returndatasize()
                if eq(32, len) {
                    returndatacopy(0, 0, 32)
                    innerRevertCode := mload(0)
                }
            }
            if (innerRevertCode == INNER_OUT_OF_GAS) {
                // handleOps was called with gas limit too low. abort entire bundle.
                //can only be caused by bundler (leaving not enough gas for inner call)
                revert FailedOp(opIndex, "AA95 out of gas");
            } else if (innerRevertCode == INNER_REVERT_LOW_PREFUND) {
                // innerCall reverted on prefund too low. treat entire prefund as "gas cost"
                uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
                uint256 actualGasCost = opInfo.prefund;
                emitPrefundTooLow(opInfo);
                emitUserOperationEvent(opInfo, false, actualGasCost, actualGas);
                collected = actualGasCost;
            } else {
                emit PostOpRevertReason(
                    opInfo.userOpHash,
                    opInfo.mUserOp.sender,
                    opInfo.mUserOp.nonce,
                    Exec.getReturnData(REVERT_REASON_MAX_LEN)
                );

                uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
                collected = _postExecution(IPaymaster.PostOpMode.postOpReverted, opInfo, context, actualGas);

                // NOTE: collected is the total amount of ETH paid for gas
            }
        }
    }

    function emitUserOperationEvent(UserOpInfo memory opInfo, bool success, uint256 actualGasCost, uint256 actualGas)
        internal
        virtual
    {
        emit UserOperationEvent(
            opInfo.userOpHash,
            opInfo.mUserOp.sender,
            opInfo.mUserOp.paymaster,
            opInfo.mUserOp.nonce,
            success,
            actualGasCost,
            actualGas
        );
    }

    function emitPrefundTooLow(UserOpInfo memory opInfo) internal virtual {
        emit UserOperationPrefundTooLow(opInfo.userOpHash, opInfo.mUserOp.sender, opInfo.mUserOp.nonce);
    }

    /// @inheritdoc IEntryPoint
    /// @param ops         - The user operations to execute.
    /// @param beneficiary - The address to receive the fees (the bundler)
    function handleOps(PackedUserOperation[] calldata ops, address payable beneficiary) public nonReentrant {
        // NOTE: see what the length is of the opeations
        uint256 opslen = ops.length;

        // NOTE: creating an array of empty structs to ostensibly fill with data
        UserOpInfo[] memory opInfos = new UserOpInfo[](opslen);

        // NOTE: Validate all users ops sent in.
        // QUESTION: How does this interface with the aggregated signatures?
        unchecked {
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[i];

                // NOTE: send actual op sent in by user and along with an object to collect some data with (like gas used)
                // NOTE: here we are validating the payments for both account and paymaster
                (uint256 validationData, uint256 pmValidationData) = _validatePrepayment(i, ops[i], opInfo);

                // NOTE: ensures the validation data from both the account and the paymaster are not "stale".
                _validateAccountAndPaymasterValidationData(i, validationData, pmValidationData, address(0));
            }

            uint256 collected = 0;
            emit BeforeExecution();

            // NOTE: execute all of the user ops (after all are validated)
            for (uint256 i = 0; i < opslen; i++) {
                // NOTE: 1. execute transaction
                // NOTE: 2. increment the account or paymaster's deposit with the refund
                collected += _executeUserOp(i, ops[i], opInfos[i]);
            }

            // NOTE: pay the executor (bundler) for submitting the transactions
            _compensate(beneficiary, collected);
        }
    }

    /// @inheritdoc IEntryPoint
    function handleAggregatedOps(UserOpsPerAggregator[] calldata opsPerAggregator, address payable beneficiary)
        public
        nonReentrant
    {
        uint256 opasLen = opsPerAggregator.length;
        uint256 totalOps = 0;
        for (uint256 i = 0; i < opasLen; i++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[i];
            PackedUserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            //address(1) is special marker of "signature error"
            require(address(aggregator) != address(1), "AA96 invalid aggregator");

            if (address(aggregator) != address(0)) {
                // solhint-disable-next-line no-empty-blocks
                try aggregator.validateSignatures(ops, opa.signature) {}
                catch {
                    revert SignatureValidationFailed(address(aggregator));
                }
            }

            totalOps += ops.length;
        }

        UserOpInfo[] memory opInfos = new UserOpInfo[](totalOps);

        uint256 opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            PackedUserOperation[] calldata ops = opa.userOps;
            IAggregator aggregator = opa.aggregator;

            uint256 opslen = ops.length;
            for (uint256 i = 0; i < opslen; i++) {
                UserOpInfo memory opInfo = opInfos[opIndex];
                (uint256 validationData, uint256 paymasterValidationData) = _validatePrepayment(opIndex, ops[i], opInfo);
                _validateAccountAndPaymasterValidationData(
                    i, validationData, paymasterValidationData, address(aggregator)
                );
                opIndex++;
            }
        }

        emit BeforeExecution();

        uint256 collected = 0;
        opIndex = 0;
        for (uint256 a = 0; a < opasLen; a++) {
            UserOpsPerAggregator calldata opa = opsPerAggregator[a];
            emit SignatureAggregatorChanged(address(opa.aggregator));
            PackedUserOperation[] calldata ops = opa.userOps;
            uint256 opslen = ops.length;

            for (uint256 i = 0; i < opslen; i++) {
                collected += _executeUserOp(opIndex, ops[i], opInfos[opIndex]);
                opIndex++;
            }
        }
        emit SignatureAggregatorChanged(address(0));

        _compensate(beneficiary, collected);
    }

    /**
     * A memory copy of UserOp static fields only.
     * Excluding: callData, initCode and signature. Replacing paymasterAndData with paymaster.
     */
    struct MemoryUserOp {
        address sender;
        uint256 nonce;
        uint256 verificationGasLimit;
        uint256 callGasLimit;
        uint256 paymasterVerificationGasLimit;
        uint256 paymasterPostOpGasLimit;
        uint256 preVerificationGas;
        address paymaster;
        uint256 maxFeePerGas;
        uint256 maxPriorityFeePerGas;
    }

    struct UserOpInfo {
        MemoryUserOp mUserOp;
        bytes32 userOpHash;
        uint256 prefund;
        uint256 contextOffset;
        uint256 preOpGas;
    }

    /**
     * Inner function to handle a UserOperation.
     * Must be declared "external" to open a call context, but it can only be called by handleOps. // NOTE: important
     * @param callData - The callData to execute.
     * @param opInfo   - The UserOpInfo struct.
     * @param context  - The context bytes.
     * @return actualGasCost - the actual cost in eth this UserOperation paid for gas
     *
     *  // NOTE: calldata is sent in here. It's being called on the account contract.
     *  // NOTE: this means that the account contract must have a function that can handle this call data.
     *  // NOTE: this means that executeUserOp must be implemented to, say, increment a counter.
     *  // NOTE: cases where executeUserOp is not implement are those where the destination contract is the account contract itself.
     */
    function innerHandleOp(bytes memory callData, UserOpInfo memory opInfo, bytes calldata context)
        external
        returns (uint256 actualGasCost)
    {
        uint256 preGas = gasleft();

        // NOTE: require can only be called by itself
        require(msg.sender == address(this), "AA92 internal call only");
        MemoryUserOp memory mUserOp = opInfo.mUserOp;

        uint256 callGasLimit = mUserOp.callGasLimit;
        unchecked {
            // handleOps was called with gas limit too low. abort entire bundle.
            if (gasleft() * 63 / 64 < callGasLimit + mUserOp.paymasterPostOpGasLimit + INNER_GAS_OVERHEAD) {
                assembly ("memory-safe") {
                    mstore(0, INNER_OUT_OF_GAS)
                    revert(0, 32)
                }
            }
        }

        IPaymaster.PostOpMode mode = IPaymaster.PostOpMode.opSucceeded;
        if (callData.length > 0) {
            // NOTE: calls the function on the sender by passing the call data
            bool success = Exec.call(mUserOp.sender, 0, callData, callGasLimit);

            if (!success) {
                bytes memory result = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                if (result.length > 0) {
                    emit UserOperationRevertReason(opInfo.userOpHash, mUserOp.sender, mUserOp.nonce, result);
                }
                mode = IPaymaster.PostOpMode.opReverted;
            }
        }

        unchecked {
            uint256 actualGas = preGas - gasleft() + opInfo.preOpGas;
            return _postExecution(mode, opInfo, context, actualGas);
        }
    }

    /// @inheritdoc IEntryPoint
    function getUserOpHash(PackedUserOperation calldata userOp) public view returns (bytes32) {
        // NOTE: .hash() is a function in the user operation lib
        // NOTE: it simiply hashes the user operation, hashed_op
        // NOTE the returned hash hashes (hashed_op, this adderss, and the chain_id) to prevent replay attacks
        return keccak256(abi.encode(userOp.hash(), address(this), block.chainid));
    }

    /**
     * Copy general fields from userOp into the memory opInfo structure.
     * @param userOp  - The user operation.
     * @param mUserOp - The memory user operation.
     */
    function _copyUserOpToMemory(PackedUserOperation calldata userOp, MemoryUserOp memory mUserOp) internal pure {
        mUserOp.sender = userOp.sender;
        mUserOp.nonce = userOp.nonce;

        (mUserOp.verificationGasLimit, mUserOp.callGasLimit) = UserOperationLib.unpackUints(userOp.accountGasLimits);
        mUserOp.preVerificationGas = userOp.preVerificationGas;
        (mUserOp.maxPriorityFeePerGas, mUserOp.maxFeePerGas) = UserOperationLib.unpackUints(userOp.gasFees);
        bytes calldata paymasterAndData = userOp.paymasterAndData;
        if (paymasterAndData.length > 0) {
            require(paymasterAndData.length >= UserOperationLib.PAYMASTER_DATA_OFFSET, "AA93 invalid paymasterAndData");
            (mUserOp.paymaster, mUserOp.paymasterVerificationGasLimit, mUserOp.paymasterPostOpGasLimit) =
                UserOperationLib.unpackPaymasterStaticFields(paymasterAndData);
        } else {
            mUserOp.paymaster = address(0);
            mUserOp.paymasterVerificationGasLimit = 0;
            mUserOp.paymasterPostOpGasLimit = 0;
        }
    }

    /**
     * Get the required prefunded gas fee amount for an operation.
     * @param mUserOp - The user operation in memory.
     */
    function _getRequiredPrefund(MemoryUserOp memory mUserOp) internal pure returns (uint256 requiredPrefund) {
        unchecked {
            // NOTE: add up the max amounts of all gas units
            // NOTE: multiple that sum by the max price that the user is willing to pay
            // NOTE: this product gives you the max fee, which we'll require to save us from worst cast scenarios.
            uint256 requiredGas = mUserOp.verificationGasLimit + mUserOp.callGasLimit
                + mUserOp.paymasterVerificationGasLimit + mUserOp.paymasterPostOpGasLimit + mUserOp.preVerificationGas;

            requiredPrefund = requiredGas * mUserOp.maxFeePerGas;
        }
    }

    /**
     * Create sender smart contract account if init code is provided.
     * @param opIndex  - The operation index.
     * @param opInfo   - The operation info.
     * @param initCode - The init code for the smart contract account.
     */
    function _createSenderIfNeeded(uint256 opIndex, UserOpInfo memory opInfo, bytes calldata initCode) internal {
        if (initCode.length != 0) {
            address sender = opInfo.mUserOp.sender;
            if (sender.code.length != 0) {
                revert FailedOp(opIndex, "AA10 sender already constructed");
            }
            address sender1 = senderCreator().createSender{gas: opInfo.mUserOp.verificationGasLimit}(initCode);
            if (sender1 == address(0)) {
                revert FailedOp(opIndex, "AA13 initCode failed or OOG");
            }
            if (sender1 != sender) {
                revert FailedOp(opIndex, "AA14 initCode must return sender");
            }
            if (sender1.code.length == 0) {
                revert FailedOp(opIndex, "AA15 initCode must create sender");
            }
            address factory = address(bytes20(initCode[0:20]));
            emit AccountDeployed(opInfo.userOpHash, sender, factory, opInfo.mUserOp.paymaster);
        }
    }

    /// @inheritdoc IEntryPoint
    function getSenderAddress(bytes calldata initCode) public {
        address sender = senderCreator().createSender(initCode);
        revert SenderAddressResult(sender);
    }

    /**
     * Call account.validateUserOp.
     * Revert (with FailedOp) in case validateUserOp reverts, or account didn't send required prefund.
     * Decrement account's deposit if needed.
     * @param opIndex         - The operation index.
     * @param op              - The user operation.
     * @param opInfo          - The operation info.
     * @param requiredPrefund - The required prefund amount.
     *
     *  1. Create account if needbe
     *  2. Validate user op
     *  3. Ask account for missing funds if there are any
     *  4. Require that the account actually sent enough funds to cover gas
     *  5. With newly "topped off" deposit, decrement gas amount from that deposit
     */
    function _validateAccountPrepayment(
        uint256 opIndex,
        PackedUserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPrefund, // NOTE: so we're requiring the account sends in max gas
        uint256 verificationGasLimit
    ) internal returns (uint256 validationData) {
        unchecked {
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            address sender = mUserOp.sender;

            // 1. If init code is provided, use factory to create sender smart account
            _createSenderIfNeeded(opIndex, opInfo, op.initCode);
            address paymaster = mUserOp.paymaster;
            uint256 missingAccountFunds = 0;

            // 2. If there is no paymaster, do the following:
            //      NOTE: validate op (could revert)
            //      NOTE: trigger the sending of the remaining funds (if balance is less than required gas)
            if (paymaster == address(0)) {
                uint256 bal = balanceOf(sender);
                missingAccountFunds = bal > requiredPrefund // QUESTION: what's required pre-fund: ANSWER: the max gas * max fee
                    ? 0
                    : requiredPrefund - bal;
            }

            // NOTE: if there is no paymaster, missingAccountFunds will be 0
            // NOTE: --> we still verify the user op, but no funds will be transferred, as account is not paying for gas.
            try IAccount(sender)
                // NOTE: didn't know you could specific gas here.
                // NOTE: this will revert if there aren't enough founds on the account.
                // NOTE: this will cause simulation to fail.
                .validateUserOp{gas: verificationGasLimit}(op, opInfo.userOpHash, missingAccountFunds) returns (
                uint256 _validationData
            ) {
                validationData = _validationData;
            } catch {
                revert FailedOpWithRevert(opIndex, "AA23 reverted", Exec.getReturnData(REVERT_REASON_MAX_LEN));
            }

            // 3. If there is no paymaster,
            //      NOTE: require that the account actually sent enough funds to cover required prefund (revert otherwise).
            if (paymaster == address(0)) {
                DepositInfo storage senderInfo = deposits[sender];
                uint256 deposit = senderInfo.deposit;
                if (requiredPrefund > deposit) {
                    revert FailedOp(opIndex, "AA21 didn't pay prefund");
                }
                //  NOTE: decrement deposit by the amount required for gas.
                //  QUESTION: presumably, the deposit was incremented in a receive somewhere?
                //  ANSWER: yes, receive is in stake manager. It "deposits" to the account balance.
                senderInfo.deposit = deposit - requiredPrefund;
            }
        }
    }

    /**
     * In case the request has a paymaster:
     *  - Validate paymaster has enough deposit.
     *  - Call paymaster.validatePaymasterUserOp.
     *  - Revert with proper FailedOp in case paymaster reverts.
     *  - Decrement paymaster's deposit.
     * @param opIndex                            - The operation index.
     * @param op                                 - The user operation.
     * @param opInfo                             - The operation info.
     * @param requiredPreFund                    - The required prefund amount.
     */
    function _validatePaymasterPrepayment(
        uint256 opIndex,
        PackedUserOperation calldata op,
        UserOpInfo memory opInfo,
        uint256 requiredPreFund
    ) internal returns (bytes memory context, uint256 validationData) {
        unchecked {
            uint256 preGas = gasleft();
            MemoryUserOp memory mUserOp = opInfo.mUserOp;

            // 1. Get the paymaster
            address paymaster = mUserOp.paymaster;

            // 2. Check it's deposit (it's basically replacing the smart account)
            DepositInfo storage paymasterInfo = deposits[paymaster];
            uint256 deposit = paymasterInfo.deposit;

            // 3. Revert if paymaster's deposit is not enough
            //    NOTE: so it doesn't "reach out" for funds if deposit is not enough?
            if (deposit < requiredPreFund) {
                revert FailedOp(opIndex, "AA31 paymaster deposit too low");
            }

            // 4. Decrement deposit as though it uses all the gas
            paymasterInfo.deposit = deposit - requiredPreFund;

            // 5. validate the user op with the paymaster (it can decide what it will and will not pay for)
            uint256 pmVerificationGasLimit = mUserOp.paymasterVerificationGasLimit;
            try IPaymaster(paymaster).validatePaymasterUserOp{gas: pmVerificationGasLimit}(
                op, opInfo.userOpHash, requiredPreFund
            ) returns (bytes memory _context, uint256 _validationData) {
                context = _context;
                validationData = _validationData;
            } catch {
                revert FailedOpWithRevert(opIndex, "AA33 reverted", Exec.getReturnData(REVERT_REASON_MAX_LEN));
            }

            // 6. Revert if the verification proccess used more gas than the user specified.
            if (preGas - gasleft() > pmVerificationGasLimit) {
                revert FailedOp(opIndex, "AA36 over paymasterVerificationGasLimit");
            }
        }
    }

    /**
     * Revert if either account validationData or paymaster validationData is expired.
     * @param opIndex                 - The operation index.
     * @param validationData          - The account validationData.
     * @param paymasterValidationData - The paymaster validationData.
     * @param expectedAggregator      - The expected aggregator.
     *
     * NOTE: ensure that the validation data returned from the account and paymaster is valid.
     * NOTE: this protects against a malicious bundler "waiting too long" to submit the transaction.
     */
    function _validateAccountAndPaymasterValidationData(
        uint256 opIndex,
        uint256 validationData,
        uint256 paymasterValidationData,
        address expectedAggregator
    ) internal view {
        // NOTE: first validate validation data for account
        (address aggregator, bool outOfTimeRange) = _getValidationData(validationData);
        if (expectedAggregator != aggregator) {
            revert FailedOp(opIndex, "AA24 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA22 expired or not due");
        }
        // pmAggregator is not a real signature aggregator: we don't have logic to handle it as address.
        // Non-zero address means that the paymaster fails due to some signature check (which is ok only during estimation).
        address pmAggregator;
        (pmAggregator, outOfTimeRange) = _getValidationData(paymasterValidationData);
        if (pmAggregator != address(0)) {
            revert FailedOp(opIndex, "AA34 signature error");
        }
        if (outOfTimeRange) {
            revert FailedOp(opIndex, "AA32 paymaster expired or not due");
        }
    }

    /**
     * Parse validationData into its components.
     * @param validationData - The packed validation data (sigFailed, validAfter, validUntil).
     * @return aggregator the aggregator of the validationData
     * @return outOfTimeRange true if current time is outside the time range of this validationData.
     */
    function _getValidationData(uint256 validationData)
        internal
        view
        returns (address aggregator, bool outOfTimeRange)
    {
        if (validationData == 0) {
            return (address(0), false);
        }
        ValidationData memory data = _parseValidationData(validationData);
        // solhint-disable-next-line not-rely-on-time

        // NOTE: bool as to wheather the data is valid or not, based on time
        outOfTimeRange = block.timestamp > data.validUntil || block.timestamp < data.validAfter;
        aggregator = data.aggregator;
    }

    /**
     * Validate account and paymaster (if defined) and
     * also make sure total validation doesn't exceed verificationGasLimit.
     * This method is called off-chain (simulateValidation()) and on-chain (from handleOps)
     * @param opIndex - The index of this userOp into the "opInfos" array.
     * @param userOp  - The userOp to validate.
     *
     *  1. Esnure numbers in user op can be safely operated over
     *  2. Get total max gas required
     *  3. Validate user up with the account
     *  4. Ensure provided nonce is correct
     *  5. Validate user op with paymaster
     *  6. Update how much gas we used during this step (keeping track of this)
     */
    function _validatePrepayment(uint256 opIndex, PackedUserOperation calldata userOp, UserOpInfo memory outOpInfo)
        internal
        returns (uint256 validationData, uint256 paymasterValidationData)
    {
        uint256 preGas = gasleft();

        // NOTE: get the userOp in memory format instead of calldata
        // QUESTION: Why though?
        MemoryUserOp memory mUserOp = outOpInfo.mUserOp;
        _copyUserOpToMemory(userOp, mUserOp);

        // NOTE: hash the user op and store it in the outOpInfo struct
        outOpInfo.userOpHash = getUserOpHash(userOp);

        // Validate all numeric values in userOp are well below 128 bit, so they can safely be added
        // and multiplied without causing overflow.
        uint256 verificationGasLimit = mUserOp.verificationGasLimit;
        uint256 maxGasValues = mUserOp.preVerificationGas | verificationGasLimit | mUserOp.callGasLimit
            | mUserOp.paymasterVerificationGasLimit | mUserOp.paymasterPostOpGasLimit | mUserOp.maxFeePerGas
            | mUserOp.maxPriorityFeePerGas;
        require(maxGasValues <= type(uint120).max, "AA94 gas values overflow");

        // 1. Get the max amount of gas needed (it's the REQUIRED prefund amount)
        uint256 requiredPreFund = _getRequiredPrefund(mUserOp);

        // 2. Validate account prepayment
        // NOTE: if paymaster is provided, user op still gets verified, but no funds will be taken from the account.
        validationData = _validateAccountPrepayment(opIndex, userOp, outOpInfo, requiredPreFund, verificationGasLimit);

        // 3. Validate provided nonce is correct
        if (!_validateAndUpdateNonce(mUserOp.sender, mUserOp.nonce)) {
            revert FailedOp(opIndex, "AA25 invalid account nonce");
        }

        unchecked {
            if (preGas - gasleft() > verificationGasLimit) {
                revert FailedOp(opIndex, "AA26 over verificationGasLimit");
            }
        }

        // 3. Validate paymaster prepayment if paymaster is non-zero
        bytes memory context;
        if (mUserOp.paymaster != address(0)) {
            (context, paymasterValidationData) =
                _validatePaymasterPrepayment(opIndex, userOp, outOpInfo, requiredPreFund);
        }
        unchecked {
            outOpInfo.prefund = requiredPreFund;
            outOpInfo.contextOffset = getOffsetOfMemoryBytes(context);

            // NOTE: keeping track of how much gas we've used so far
            // NOTE: the amount verification took + amount pre-verification took
            outOpInfo.preOpGas = preGas - gasleft() + userOp.preVerificationGas;
        }
    }

    /**
     * Process post-operation, called just after the callData is executed.
     * If a paymaster is defined and its validation returned a non-empty context, its postOp is called.
     * The excess amount is refunded to the account (or paymaster - if it was used in the request).
     * @param mode      - Whether is called from innerHandleOp, or outside (postOpReverted).
     * @param opInfo    - UserOp fields and info collected during validation.
     * @param context   - The context returned in validatePaymasterUserOp.
     * @param actualGas - The gas used so far by this user operation.
     */
    function _postExecution(
        IPaymaster.PostOpMode mode,
        UserOpInfo memory opInfo,
        bytes memory context,
        uint256 actualGas
    ) private returns (uint256 actualGasCost) {
        uint256 preGas = gasleft();
        unchecked {
            address refundAddress;
            MemoryUserOp memory mUserOp = opInfo.mUserOp;
            uint256 gasPrice = getUserOpGasPrice(mUserOp);

            address paymaster = mUserOp.paymaster;
            if (paymaster == address(0)) {
                refundAddress = mUserOp.sender;
            } else {
                refundAddress = paymaster;
                if (context.length > 0) {
                    actualGasCost = actualGas * gasPrice;
                    if (mode != IPaymaster.PostOpMode.postOpReverted) {
                        try IPaymaster(paymaster).postOp{gas: mUserOp.paymasterPostOpGasLimit}(
                            mode, context, actualGasCost, gasPrice
                        ) {
                            // solhint-disable-next-line no-empty-blocks
                        } catch {
                            bytes memory reason = Exec.getReturnData(REVERT_REASON_MAX_LEN);
                            revert PostOpReverted(reason);
                        }
                    }
                }
            }
            actualGas += preGas - gasleft();

            // Calculating a penalty for unused execution gas
            {
                uint256 executionGasLimit = mUserOp.callGasLimit + mUserOp.paymasterPostOpGasLimit;
                uint256 executionGasUsed = actualGas - opInfo.preOpGas;
                // this check is required for the gas used within EntryPoint and not covered by explicit gas limits
                if (executionGasLimit > executionGasUsed) {
                    uint256 unusedGas = executionGasLimit - executionGasUsed;
                    uint256 unusedGasPenalty = (unusedGas * PENALTY_PERCENT) / 100;
                    actualGas += unusedGasPenalty;
                }
            }

            actualGasCost = actualGas * gasPrice;
            uint256 prefund = opInfo.prefund;
            if (prefund < actualGasCost) {
                if (mode == IPaymaster.PostOpMode.postOpReverted) {
                    actualGasCost = prefund;
                    emitPrefundTooLow(opInfo);
                    emitUserOperationEvent(opInfo, false, actualGasCost, actualGas);
                } else {
                    assembly ("memory-safe") {
                        mstore(0, INNER_REVERT_LOW_PREFUND)
                        revert(0, 32)
                    }
                }
            } else {
                uint256 refund = prefund - actualGasCost;

                // NOTE: Increment deposit with refund here.
                _incrementDeposit(refundAddress, refund);
                bool success = mode == IPaymaster.PostOpMode.opSucceeded;
                emitUserOperationEvent(opInfo, success, actualGasCost, actualGas);
            }
        } // unchecked
    }

    /**
     * The gas price this UserOp agrees to pay.
     * Relayer/block builder might submit the TX with higher priorityFee, but the user should not.
     * @param mUserOp - The userOp to get the gas price from.
     */
    function getUserOpGasPrice(MemoryUserOp memory mUserOp) internal view returns (uint256) {
        unchecked {
            uint256 maxFeePerGas = mUserOp.maxFeePerGas;
            uint256 maxPriorityFeePerGas = mUserOp.maxPriorityFeePerGas;
            if (maxFeePerGas == maxPriorityFeePerGas) {
                //legacy mode (for networks that don't support basefee opcode)
                return maxFeePerGas;
            }
            return min(maxFeePerGas, maxPriorityFeePerGas + block.basefee);
        }
    }

    /**
     * The offset of the given bytes in memory.
     * @param data - The bytes to get the offset of.
     */
    function getOffsetOfMemoryBytes(bytes memory data) internal pure returns (uint256 offset) {
        assembly {
            offset := data
        }
    }

    /**
     * The bytes in memory at the given offset.
     * @param offset - The offset to get the bytes from.
     */
    function getMemoryBytesFromOffset(uint256 offset) internal pure returns (bytes memory data) {
        assembly ("memory-safe") {
            data := offset
        }
    }

    /// @inheritdoc IEntryPoint
    function delegateAndRevert(address target, bytes calldata data) external {
        (bool success, bytes memory ret) = target.delegatecall(data);
        revert DelegateAndRevert(success, ret);
    }
}
