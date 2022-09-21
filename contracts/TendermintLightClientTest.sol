pragma solidity 0.6.4;
pragma experimental ABIEncoderV2;

import "./lib/Memory.sol";
import "./lib/BytesToTypes.sol";
import "./interface/ILightClient.sol";
import "./interface/ISystemReward.sol";
import "./interface/IParamSubscriber.sol";
import "./System.sol";
import "hardhat/console.sol";

contract TendermintLightClient is ILightClient, System, IParamSubscriber {

    struct ConsensusState {
        uint64 preValidatorSetChangeHeight; // 上一个验证者集合变更的高度
        bytes32 appHash; // BC的根哈希
        bytes32 curValidatorSetHash;
        bytes nextValidatorSet;
    }

    mapping(uint64 => ConsensusState) public lightClientConsensusStates;
    mapping(uint64 => address payable) public submitters;
    uint64 public initialHeight; // 初始化高度
    uint64 public latestHeight;
    bytes32 public chainID;

    bytes constant public INIT_CONSENSUS_STATE_BYTES = hex"42696e616e63652d436861696e2d4e696c650000000000000000000000000000000000000000000229eca254b3859bffefaf85f4c95da9fbd26527766b784272789c30ec56b380b6eb96442aaab207bc59978ba3dd477690f5c5872334fc39e627723daa97e441e88ba4515150ec3182bc82593df36f8abb25a619187fcfab7e552b94e64ed2deed000000e8d4a51000";
    uint256 constant public INIT_REWARD_FOR_VALIDATOR_SER_CHANGE = 1e16; // 应该是0.01BNB
    uint256 public rewardForValidatorSetChange;

    event initConsensusState(uint64 initHeight, bytes32 appHash);
    event syncConsensusState(uint64 height, uint64 preValidatorSetChangeHeight, bytes32 appHash, bool validatorChanged);
    event paramChange(string key, bytes value);

    /* solium-disable-next-line */
    constructor() public {}

    // 初始化
    function init() external onlyNotInit {
        uint256 pointer;
        uint256 length;
        (pointer, length) = Memory.fromBytes(INIT_CONSENSUS_STATE_BYTES);
        console.log("1. pointer: %s, length: %s", pointer, length);
        // pointer: 160, length: 144
        /* solium-disable-next-line */
        // sstore: writes a (u)int256 to storage
        // mload：reads a (u)int256 from memory
        // 从pointer位置内存中读取数据，再写入到合约的storage存储中
        assembly {
            sstore(chainID_slot, mload(pointer))
        }

        ConsensusState memory cs;
        uint64 height;
        console.log("2. pointer: %s, length: %s", pointer, length);
        // pointer: 160, length: 144
        (cs, height) = decodeConsensusState(pointer, length, false);
        // 根据指针位置和长度从存储中解码出ConsensusState
        console.log("cs");
        console.log("height: %s", height);
        // height: 2
        cs.preValidatorSetChangeHeight = 0;
        lightClientConsensusStates[height] = cs;

        initialHeight = height;
        latestHeight = height;
        alreadyInit = true;
        rewardForValidatorSetChange = INIT_REWARD_FOR_VALIDATOR_SER_CHANGE;

        emit initConsensusState(initialHeight, cs.appHash);
    }
    // 同步区块头
    // bsc-relayer会调用该方法
    function syncTendermintHeader(bytes calldata header, uint64 height) external onlyRelayer returns (bool) {
        require(submitters[height] == address(0x0), "can't sync duplicated header");
        // 不能同步重复的区块头
        require(height > initialHeight, "can't sync header before initialHeight");
        // 不能同步初始高度之前的区块头,当前同步的区块高度必须大于初始高度

        uint64 preValidatorSetChangeHeight = latestHeight;
        // 上一个验证人集合变更的高度 = 当前最新高度
        ConsensusState memory cs = lightClientConsensusStates[preValidatorSetChangeHeight];
        // cs存储的是上一次的共识状态数据,即上一个验证人集合变更的高度的共识状态数据
        for (; preValidatorSetChangeHeight >= height && preValidatorSetChangeHeight >= initialHeight;) {
            preValidatorSetChangeHeight = cs.preValidatorSetChangeHeight;
            cs = lightClientConsensusStates[preValidatorSetChangeHeight];
        }
        if (cs.nextValidatorSet.length == 0) {
            preValidatorSetChangeHeight = cs.preValidatorSetChangeHeight;
            cs.nextValidatorSet = lightClientConsensusStates[preValidatorSetChangeHeight].nextValidatorSet;
            require(cs.nextValidatorSet.length != 0, "failed to load validator set data");
        }

        // | length   | chainID   | height   | appHash  | curValidatorSetHash | [{validator pubkey, voting power}] |
        // | 32 bytes | 32 bytes   | 8 bytes  | 32 bytes | 32 bytes            | [{32 bytes, 8 bytes}]              |
        //32 + 32 + 8 + 32 + 32 + cs.nextValidatorSet.length;
        uint256 length = 136 + cs.nextValidatorSet.length;
        bytes memory input = new bytes(length + header.length);
        // header.length应该是一个挺长的字节数组
        uint256 ptr = Memory.dataPtr(input);
        // 获取指针位置
        // Returns a memory pointer to the data portion of the provided bytes array.
        require(encodeConsensusState(cs, preValidatorSetChangeHeight, ptr, length), "failed to serialize consensus state");

        // write header to input
        // 往后面写数据,因为保存了多个共识状态，区块高度索引递增
        uint256 src;
        ptr = ptr + length;
        // 移动指针位置
        (src, length) = Memory.fromBytes(header);
        Memory.copy(src, ptr, length);
        // Copy 'len' bytes from memory address 'src', to address 'dest'.

        length = input.length + 32;
        // Maximum validator quantity is 99
        bytes32[128] memory result;
        /* solium-disable-next-line */
        assembly {
        // call validateTendermintHeader precompile contract
        // 调用预编译合约中的方法
        // Contract address: 0x64
        // if iszero(call(gasLimit, contractAddress, value, input, inputLength, output, outputLength)) {
            if iszero(staticcall(not(0), 0x64, input, length, result, 4096)) {
                revert(0, 0)
            }
        }

        // Judge if the validator set is changed
        /* solium-disable-next-line */
        assembly {
            length := mload(add(result, 0))
        }
        // 验证者集合是否发生变化的标志
        bool validatorChanged = false;
        if ((length & (0x01 << 248)) != 0x00) {
            validatorChanged = true;
            // 系统奖励合约的提取奖励函数
            ISystemReward(SYSTEM_REWARD_ADDR).claimRewards(msg.sender, rewardForValidatorSetChange);
        }
        length = length & 0xffffffffffffffff;

        /* solium-disable-next-line */
        assembly {
            ptr := add(result, 32)
        }

        uint64 actualHeaderHeight;
        // 解码共识状态
        // ptr 指针位置、length长度、validatorChanged是否验证者集合发生变化
        (cs, actualHeaderHeight) = decodeConsensusState(ptr, length, !validatorChanged);
        require(actualHeaderHeight == height, "header height doesn't equal to the specified height");
        // 区块头高度必须等于指定的高度

        submitters[height] = msg.sender;
        cs.preValidatorSetChangeHeight = preValidatorSetChangeHeight;
        lightClientConsensusStates[height] = cs;
        if (height > latestHeight) {
            latestHeight = height;
        }

        emit syncConsensusState(height, preValidatorSetChangeHeight, cs.appHash, validatorChanged);

        return true;
    }


    function syncTendermintHeaderTmp(bytes calldata header, uint64 height) external returns (bool) {
        require(submitters[height] == address(0x0), "can't sync duplicated header");
        // 不能同步重复的区块头
        require(height > initialHeight, "can't sync header before initialHeight");
        // 不能同步初始高度之前的区块头,当前同步的区块高度必须大于初始高度

        uint64 preValidatorSetChangeHeight = latestHeight;
        console.log("preValidatorSetChangeHeight: %s", preValidatorSetChangeHeight);
        // preValidatorSetChangeHeight: 2
        // 上一个验证人集合变更的高度 = 当前最新高度
        // 一.查上次的共识状态
        ConsensusState memory cs = lightClientConsensusStates[preValidatorSetChangeHeight];
        // cs存储的是上一次的共识状态数据,即上一个验证人集合变更的高度的共识状态数据
        for (; preValidatorSetChangeHeight >= height && preValidatorSetChangeHeight >= initialHeight;) {
            preValidatorSetChangeHeight = cs.preValidatorSetChangeHeight;
            cs = lightClientConsensusStates[preValidatorSetChangeHeight];
        }
        if (cs.nextValidatorSet.length == 0) {
            preValidatorSetChangeHeight = cs.preValidatorSetChangeHeight;
            cs.nextValidatorSet = lightClientConsensusStates[preValidatorSetChangeHeight].nextValidatorSet;
            require(cs.nextValidatorSet.length != 0, "failed to load validator set data");
        }

        // | length   | chainID   | height   | appHash  | curValidatorSetHash | [{validator pubkey, voting power}] |
        // | 32 bytes | 32 bytes   | 8 bytes  | 32 bytes | 32 bytes            | [{32 bytes, 8 bytes}]              |
        //32 + 32 + 8 + 32 + 32 + cs.nextValidatorSet.length;
        uint256 length = 136 + cs.nextValidatorSet.length;
        // 136+40
        console.log("length: %s", length);
        // length: 176
        console.log("header.length: %s", header.length);
        // header.length: 848
        bytes memory input = new bytes(length + header.length);
        // header.length应该是一个挺长的字节数组
        uint256 ptr = Memory.dataPtr(input);
        // ptr: 1196
        console.log("ptr: %s", ptr);
        // 获取指针位置
        // Returns a memory pointer to the data portion of the provided bytes array.
        // 把
        require(encodeConsensusState(cs, preValidatorSetChangeHeight, ptr, length), "failed to serialize consensus state");
        // preValidatorSetChangeHeight: 2, ptr: 1196, length: 176
        console.log("preValidatorSetChangeHeight: %s", preValidatorSetChangeHeight);
        console.log("ptr: %s", ptr);
        console.log("length: %s", length);
        return true;
    }

    function syncTendermintHeaderTmps(bytes calldata header, uint64 height) external returns (bool) {
        require(submitters[height] == address(0x0), "can't sync duplicated header");
        // 不能同步重复的区块头
        require(height > initialHeight, "can't sync header before initialHeight");
        // 不能同步初始高度之前的区块头,当前同步的区块高度必须大于初始高度

        uint64 preValidatorSetChangeHeight = latestHeight;
        console.log("preValidatorSetChangeHeight: %s", preValidatorSetChangeHeight);
        // 上一个验证人集合变更的高度 = 当前最新高度
        ConsensusState memory cs = lightClientConsensusStates[preValidatorSetChangeHeight];
        // cs存储的是上一次的共识状态数据,即上一个验证人集合变更的高度的共识状态数据
        for (; preValidatorSetChangeHeight >= height && preValidatorSetChangeHeight >= initialHeight;) {
            preValidatorSetChangeHeight = cs.preValidatorSetChangeHeight;
            cs = lightClientConsensusStates[preValidatorSetChangeHeight];
        }
        if (cs.nextValidatorSet.length == 0) {
            preValidatorSetChangeHeight = cs.preValidatorSetChangeHeight;
            cs.nextValidatorSet = lightClientConsensusStates[preValidatorSetChangeHeight].nextValidatorSet;
            require(cs.nextValidatorSet.length != 0, "failed to load validator set data");
        }

        // | length   | chainID   | height   | appHash  | curValidatorSetHash | [{validator pubkey, voting power}] |
        // | 32 bytes | 32 bytes   | 8 bytes  | 32 bytes | 32 bytes            | [{32 bytes, 8 bytes}]              |
        //32 + 32 + 8 + 32 + 32 + cs.nextValidatorSet.length;
        uint256 length = 136 + cs.nextValidatorSet.length;
        console.log("length: %s", length);
        console.log("header.length: %s", header.length);
        bytes memory input = new bytes(length + header.length);
        // header.length应该是一个挺长的字节数组
        uint256 ptr = Memory.dataPtr(input);
        console.log("ptr: %s", ptr);
        // 获取指针位置
        // Returns a memory pointer to the data portion of the provided bytes array.
        require(encodeConsensusState(cs, preValidatorSetChangeHeight, ptr, length), "failed to serialize consensus state");
        console.log("preValidatorSetChangeHeight: %s", preValidatorSetChangeHeight);
        console.log("ptr: %s", ptr);
        console.log("length: %s", length);

        // write header to input 应该是将这次的header数据写到了指定的位置,供预编译合约去调用
        // TODO:???是覆盖原来的数据还是 往后面写入数据
        uint256 src;
        ptr = ptr + length;
        console.log("ptr: %s", ptr); // ptr: 1372
        // 获取指针位置
        (src, length) = Memory.fromBytes(header);
        console.log("src: %s", src); // src: 3392
        console.log("length: %s", length); // 848
        // 内存拷贝到ptr指定的位置
        Memory.copy(src, ptr, length); // Copy 'len' bytes from memory address 'src', to address 'dest'.

        length = input.length + 32;
        console.log("length: %s", length); // 1056
        // Maximum validator quantity is 99
        bytes32[128] memory result;
        /* solium-disable-next-line */
        assembly {
        // call validateTendermintHeader precompile contract
        // 调用预编译合约中的方法,预编译合约应该是读内存中的数据,然后进行验证
        // Contract address: 0x64
        // if iszero(call(gasLimit, contractAddress, value, input, inputLength, output, outputLength)) {
            // STATICCALL: success, memory[retOffset:retOffset+retLength] = address(addr).staticcall.gas(gas)(memory[argsOffset:argsOffset+argsLength]) 给一段内存范围的数据
            if iszero(staticcall(not(0), 0x64, input, length, result, 4096)) { // 找预编译合约会return bool的函数
                revert(0, 0)
            }
        }

        return true;
    }

    function isHeaderSynced(uint64 height) external override view returns (bool) {
        return submitters[height] != address(0x0) || height == initialHeight;
    }

    function getAppHash(uint64 height) external override view returns (bytes32) {
        return lightClientConsensusStates[height].appHash;
    }

    function getSubmitter(uint64 height) external override view returns (address payable) {
        return submitters[height];
    }

    function getChainID() external view returns (string memory) {
        bytes memory chainIDBytes = new bytes(32);
        assembly {
            mstore(add(chainIDBytes, 32), sload(chainID_slot))
        }

        uint8 chainIDLength = 0;
        for (uint8 j = 0; j < 32; j++) {
            if (chainIDBytes[j] != 0) {
                chainIDLength++;
            } else {
                break;
            }
        }

        bytes memory chainIDStr = new bytes(chainIDLength);
        for (uint8 j = 0; j < chainIDLength; j++) {
            chainIDStr[j] = chainIDBytes[j];
        }

        return string(chainIDStr);
    }

    // | length   | chainID   | height   | appHash  | curValidatorSetHash | [{validator pubkey, voting power}] |
    // | 32 bytes | 32 bytes   | 8 bytes  | 32 bytes | 32 bytes            | [{32 bytes, 8 bytes}]              |
    /* solium-disable-next-line */
    function encodeConsensusState(ConsensusState memory cs, uint64 height, uint256 outputPtr, uint256 size) public view returns (bool) {
        outputPtr = outputPtr + size - cs.nextValidatorSet.length;

        uint256 src;
        uint256 length;
        (src, length) = Memory.fromBytes(cs.nextValidatorSet);
        Memory.copy(src, outputPtr, length);
        outputPtr = outputPtr - 32;
        // 不断移动位置指针

        // 数据1: curValidatorSetHash
        bytes32 hash = cs.curValidatorSetHash;
        /* solium-disable-next-line */
        // mstore: writes a (u)int256 to memory 写数据到memory,那只是缓存区
        assembly {
            mstore(outputPtr, hash)
        }
        outputPtr = outputPtr - 32;
        // 数据2: appHash
        hash = cs.appHash;
        /* solium-disable-next-line */
        // hash
        assembly {
            mstore(outputPtr, hash)
        }
        outputPtr = outputPtr - 32;
        // 数据3: height
        /* solium-disable-next-line */
        assembly {
            mstore(outputPtr, height)
        }
        outputPtr = outputPtr - 8;

        /* solium-disable-next-line */
        // reads a (u)int256 from storage
        assembly {
            mstore(outputPtr, sload(chainID_slot))
        }
        outputPtr = outputPtr - 32;

        // size doesn't contain length
        size = size - 32;
        /* solium-disable-next-line */
        assembly {
            mstore(outputPtr, size)
        }

        return true;
    }

    // | chainID  | height   | appHash  | curValidatorSetHash | [{validator pubkey, voting power}] |
    // | 32 bytes  | 8 bytes  | 32 bytes | 32 bytes            | [{32 bytes, 8 bytes}]              |
    /* solium-disable-next-line */
    // @dev decodeConsensusState 给定指针起始位置,数据长度,不断移动指针位置,从storage读取共识状态数据
    // @param ptr 指针位置 例如160
    // @param size 长度 上面注释的总长度之和为144
    // @param leaveOutValidatorSet 是否忽略验证者集合
    function decodeConsensusState(uint256 ptr, uint256 size, bool leaveOutValidatorSet) public returns (ConsensusState memory, uint64) {
        ptr = ptr + 8;
        // 指针移动到height初始位置
        uint64 height;
        /* solium-disable-next-line */
        // mload: reads a (u)int256 from memory 从storage中读取数据
        assembly {
            height := mload(ptr)
        }

        ptr = ptr + 32;
        // 指针移动到appHash初始位置
        bytes32 appHash;
        /* solium-disable-next-line */
        assembly {
            appHash := mload(ptr)
        }

        ptr = ptr + 32;
        // 指针移动到curValidatorSetHash初始位置
        bytes32 curValidatorSetHash;
        /* solium-disable-next-line */
        assembly {
            curValidatorSetHash := mload(ptr)
        }

        ConsensusState memory cs;
        cs.appHash = appHash;
        cs.curValidatorSetHash = curValidatorSetHash;

        if (!leaveOutValidatorSet) {// 考虑验证者集合
            uint256 dest;
            uint256 length;
            cs.nextValidatorSet = new bytes(size - 104);
            // 144-104 = 40 ,应该是appHash的位置
            (dest, length) = Memory.fromBytes(cs.nextValidatorSet);
            // 读取位置和长度
            // 指针移动到 | [{validator pubkey, voting power}] 的初始位置
            Memory.copy(ptr + 32, dest, length);
        }

        return (cs, height);
        // 共识状态数据,区块高度
    }

    function updateParam(string calldata key, bytes calldata value) external override onlyInit onlyGov {
        if (Memory.compareStrings(key, "rewardForValidatorSetChange")) {
            require(value.length == 32, "length of rewardForValidatorSetChange mismatch");
            uint256 newRewardForValidatorSetChange = BytesToTypes.bytesToUint256(32, value);
            require(newRewardForValidatorSetChange > 0 && newRewardForValidatorSetChange <= 1e18, "the newRewardForValidatorSetChange out of range");
            rewardForValidatorSetChange = newRewardForValidatorSetChange;
        } else {
            require(false, "unknown param");
        }
        emit paramChange(key, value);
    }
}