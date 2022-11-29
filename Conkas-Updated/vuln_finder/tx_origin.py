# Analyse TX.ORIGIN vulnerabilities
from z3 import is_false, is_true, Solver, sat, simplify
from z3.z3util import get_vars

from rattle import SSABasicBlock
from sym_exec.trace import Trace
from sym_exec.utils import get_argument_value, is_symbolic
from vuln_finder import vulnerability_finder
from vuln_finder.vulnerability import Vulnerability

TX_ORIGIN_VULN = 'tx.origin'
TX_ORIGIN_INST = 'ORIGIN'
JUMPI_INST = 'JUMPI'


def __find_instruction(block: SSABasicBlock, instruction_name: str):
    instructions = []
    for instruction in block.insns:
        if instruction.insn.name == instruction_name:
            instructions.append(instruction)
    return instructions


def __get_storage_position(info, state):
    if info and 'storage' not in info[0]:
        return
    storage_position = int(info[1])
    is_storage_position_symbolic = info[2] == 'sym'
    if is_storage_position_symbolic:
        storage_position = state.registers.get(storage_position)
    return storage_position


def __get_storage_var(var_name, state, inst):
    info = var_name.split(',')
    storage_position = __get_storage_position(info, state)
    if storage_position is None:
        return
    ssa_store_position = -1
    for sstore in inst:
        idx = get_argument_value(sstore.arguments, 0, state.registers)
        if idx == storage_position:
            ssa_store_position -= 1
    return state.storage.get(storage_position, ssa_store_position)


def __get_solver():
    s = Solver()
    s.set('timeout', vulnerability_finder.Z3_TIMEOUT)
    return s


def __has_vulnerability(constraints):
    s = __get_solver()
    s.add(constraints)
    return s.check() == sat


def __Txorigin_pre_call(analyzed_block, inst, call_value):
    constraints = []
    # Check if guard is not detected
    for constraint in analyzed_block.constraints:
        constraint = simplify(constraint)
        for var in get_vars(constraint):
            var_name = var.decl().name()
            storage_var = __get_storage_var(var_name, analyzed_block.state, inst)
            if storage_var is None:
                continue
            constraints.append(constraint)
            constraints.append(var == storage_var)

    # Check if value of storage is different from 0
    if is_symbolic(call_value):
        if call_value.num_args() != 0:
            constraints.append(True)
            return constraints
        bv_name = str(call_value)
        storage_var = __get_storage_var(bv_name, analyzed_block.state, inst)
        if storage_var is not None:
            constraints.append(storage_var != 0)

    return constraints


# Return AnalyzedBlock object where the constraint happens
def __get_block_with_constraint(constraint, trace):
    found = False
    for block in reversed(trace.analyzed_blocks):
        if found and hash(constraint) != hash(block.constraints[-1]):
            return block
        if not found and len(block.constraints) > 0 and hash(constraint) == hash(block.constraints[-1]):
            found = True


def __Txorigin_pos_call(trace, analyzed_block):
    analyzed_constraints = set(analyzed_block.constraints)
    remaining_constraints = [c for c in trace.constraints if c not in analyzed_constraints]
    for constraint in reversed(remaining_constraints):
        block = __get_block_with_constraint(constraint, trace)
        for var in get_vars(constraint):
            var_name = var.decl().name()
            storage_var = __get_storage_var(var_name, block.state, [])
            if storage_var is None:
                continue

            s = __get_solver()
            s.add(var != storage_var)
            simplified_constraint = simplify(constraint)
            if s.check() != sat:
                if is_false(simplified_constraint):
                    return [False]  # Impossible path
                return []  # No constraints, need to check reentrancy_pre_call
            if is_true(simplified_constraint):
                return [False]  # Protected, no vulnerability
            if is_false(simplified_constraint):
                return [True]  # Non protected, vulnerability
            return [True]  # Could be false positive

    return []


def tx_origin_analyse(traces: [Trace], find_all):
    all_vulns = set()
    analyzed_constraints = False
    exist_constraints = False
    block_analyzed = None
    analyzed_blocks = set()
    offset = None
    instruction_offset = None
    for trace in traces:
        if trace.state.reverted:
            continue
        for analyzed_block in trace.analyzed_blocks:
            if analyzed_block in analyzed_blocks:
                continue
            for instruction in analyzed_block.block.insns:
                instruction_name = instruction.insn.name
                if instruction_name != JUMPI_INST:
                    continue

                analyzed_constraints = True
                block_analyzed = analyzed_block
                offset = instruction.offset
                instruction_offset = instruction.instruction_offset

                constraints = __Txorigin_pos_call(trace, analyzed_block)
                if constraints:
                    exist_constraints = True
                    if __has_vulnerability(constraints):
                        vuln = Vulnerability(TX_ORIGIN_VULN, analyzed_block, offset, instruction_offset)
                        all_vulns.add(vuln)
                        if not find_all:
                            return all_vulns
                    continue

                inst = list(
                    filter(lambda x: x.offset > instruction.offset,
                           __find_instruction(analyzed_block.block, TX_ORIGIN_INST)))
                call_value = get_argument_value(instruction.arguments, 1, analyzed_block.state.registers)
                constraints = __Txorigin_pre_call(analyzed_block, inst, call_value)
                if constraints:
                    exist_constraints = True
                    if __has_vulnerability(constraints):
                        vuln = Vulnerability(TX_ORIGIN_VULN, analyzed_block, offset, instruction_offset)
                        all_vulns.add(vuln)
                        if not find_all:
                            return all_vulns
            analyzed_blocks.add(analyzed_block)

        if analyzed_constraints and not exist_constraints:
            vuln = Vulnerability(TX_ORIGIN_VULN, block_analyzed, offset, instruction_offset)
            all_vulns.add(vuln)
            if not find_all:
                return all_vulns
        analyzed_constraints = False
        exist_constraints = False
        block_analyzed = None
    return all_vulns

# //SPDX-License-Identifier: Unlicense
# pragma solidity ^0.8.0;
#
# import "@openzeppelin/contracts/utils/Address.sol";
#
#
# contract Bank {
#     using/// USing the imported address lib
#      Address for address payable;
#
#     /// @dev mapping to track user's balance
#     mapping(address => uint256) public balanceOf;
#
#     /// @dev function to make deposit to this contract
#     function deposit() external payable {
#         balanceOf[tx.origin] += msg.value;
#     }
#
#     /// @dev this function is not protected from reentracy attack
#     function withdraw() external {
#         uint256 depositedAmount = balanceOf[tx.origin];
#         payable(msg.sender).sendValue(depositedAmount);
#         balanceOf[msg.sender] = 0;
#     }
#
#     /// @dev this function is returning the ether balance of the contract
#     function getContractBalance() public view returns(uint ) {
#       return address(this).balance;
#     }
# }
#
#
# // How to protect yourself from this kind of hack
#
# // 1. Use @openzeppelin non-reentrancy guard contract
# // or
# // 2. Make sure you do all you checks and update balances before making enternal calls
#
#
# {
# 	"functionDebugData": {},
# 	"generatedSources": [],
# 	"linkReferences": {},
# 	"object": "608060405234801561001057600080fd5b506105bf806100206000396000f3fe60806040526004361061003f5760003560e01c80633ccfd60b146100445780636f9fb98a1461005b57806370a0823114610086578063d0e30db0146100c3575b600080fd5b34801561005057600080fd5b506100596100cd565b005b34801561006757600080fd5b50610070610180565b60405161007d91906103fa565b60405180910390f35b34801561009257600080fd5b506100ad60048036038101906100a89190610300565b610188565b6040516100ba91906103fa565b60405180910390f35b6100cb6101a0565b005b60008060003273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050610139813373ffffffffffffffffffffffffffffffffffffffff166101f790919063ffffffff16565b60008060003373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000208190555050565b600047905090565b60006020528060005260406000206000915090505481565b346000803273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008282546101ee9190610431565b92505081905550565b8047101561023a576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401610231906103da565b60405180910390fd5b60008273ffffffffffffffffffffffffffffffffffffffff1682604051610260906103a5565b60006040518083038185875af1925050503d806000811461029d576040519150601f19603f3d011682016040523d82523d6000602084013e6102a2565b606091505b50509050806102e6576040517f08c379a00000000000000000000000000000000000000000000000000000000081526004016102dd906103ba565b60405180910390fd5b505050565b6000813590506102fa81610572565b92915050565b600060208284031215610316576103156104f2565b5b6000610324848285016102eb565b91505092915050565b600061033a603a83610420565b9150610345826104f7565b604082019050919050565b600061035d601d83610420565b915061036882610546565b602082019050919050565b6000610380600083610415565b915061038b8261056f565b600082019050919050565b61039f816104b9565b82525050565b60006103b082610373565b9150819050919050565b600060208201905081810360008301526103d38161032d565b9050919050565b600060208201905081810360008301526103f381610350565b9050919050565b600060208201905061040f6000830184610396565b92915050565b600081905092915050565b600082825260208201905092915050565b600061043c826104b9565b9150610447836104b9565b9250827fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff0382111561047c5761047b6104c3565b5b828201905092915050565b600061049282610499565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600080fd5b7f416464726573733a20756e61626c6520746f2073656e642076616c75652c207260008201527f6563697069656e74206d61792068617665207265766572746564000000000000602082015250565b7f416464726573733a20696e73756666696369656e742062616c616e6365000000600082015250565b50565b61057b81610487565b811461058657600080fd5b5056fea26469706673582212203e6a307bf621355cbca6bfe007ddfd76bc4acc8bbb5c5b09c0c0ea490f142aad64736f6c63430008070033",
# 	"opcodes": "PUSH1 0x80 PUSH1 0x40 MSTORE CALLVALUE DUP1 ISZERO PUSH2 0x10 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x5BF DUP1 PUSH2 0x20 PUSH1 0x0 CODECOPY PUSH1 0x0 RETURN INVALID PUSH1 0x80 PUSH1 0x40 MSTORE PUSH1 0x4 CALLDATASIZE LT PUSH2 0x3F JUMPI PUSH1 0x0 CALLDATALOAD PUSH1 0xE0 SHR DUP1 PUSH4 0x3CCFD60B EQ PUSH2 0x44 JUMPI DUP1 PUSH4 0x6F9FB98A EQ PUSH2 0x5B JUMPI DUP1 PUSH4 0x70A08231 EQ PUSH2 0x86 JUMPI DUP1 PUSH4 0xD0E30DB0 EQ PUSH2 0xC3 JUMPI JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x50 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x59 PUSH2 0xCD JUMP JUMPDEST STOP JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x67 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0x70 PUSH2 0x180 JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0x7D SWAP2 SWAP1 PUSH2 0x3FA JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST CALLVALUE DUP1 ISZERO PUSH2 0x92 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP PUSH2 0xAD PUSH1 0x4 DUP1 CALLDATASIZE SUB DUP2 ADD SWAP1 PUSH2 0xA8 SWAP2 SWAP1 PUSH2 0x300 JUMP JUMPDEST PUSH2 0x188 JUMP JUMPDEST PUSH1 0x40 MLOAD PUSH2 0xBA SWAP2 SWAP1 PUSH2 0x3FA JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 RETURN JUMPDEST PUSH2 0xCB PUSH2 0x1A0 JUMP JUMPDEST STOP JUMPDEST PUSH1 0x0 DUP1 PUSH1 0x0 ORIGIN PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 SLOAD SWAP1 POP PUSH2 0x139 DUP2 CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH2 0x1F7 SWAP1 SWAP2 SWAP1 PUSH4 0xFFFFFFFF AND JUMP JUMPDEST PUSH1 0x0 DUP1 PUSH1 0x0 CALLER PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 DUP2 SWAP1 SSTORE POP POP JUMP JUMPDEST PUSH1 0x0 SELFBALANCE SWAP1 POP SWAP1 JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 MSTORE DUP1 PUSH1 0x0 MSTORE PUSH1 0x40 PUSH1 0x0 KECCAK256 PUSH1 0x0 SWAP2 POP SWAP1 POP SLOAD DUP2 JUMP JUMPDEST CALLVALUE PUSH1 0x0 DUP1 ORIGIN PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP2 MSTORE PUSH1 0x20 ADD SWAP1 DUP2 MSTORE PUSH1 0x20 ADD PUSH1 0x0 KECCAK256 PUSH1 0x0 DUP3 DUP3 SLOAD PUSH2 0x1EE SWAP2 SWAP1 PUSH2 0x431 JUMP JUMPDEST SWAP3 POP POP DUP2 SWAP1 SSTORE POP JUMP JUMPDEST DUP1 SELFBALANCE LT ISZERO PUSH2 0x23A JUMPI PUSH1 0x40 MLOAD PUSH32 0x8C379A000000000000000000000000000000000000000000000000000000000 DUP2 MSTORE PUSH1 0x4 ADD PUSH2 0x231 SWAP1 PUSH2 0x3DA JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 REVERT JUMPDEST PUSH1 0x0 DUP3 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF AND DUP3 PUSH1 0x40 MLOAD PUSH2 0x260 SWAP1 PUSH2 0x3A5 JUMP JUMPDEST PUSH1 0x0 PUSH1 0x40 MLOAD DUP1 DUP4 SUB DUP2 DUP6 DUP8 GAS CALL SWAP3 POP POP POP RETURNDATASIZE DUP1 PUSH1 0x0 DUP2 EQ PUSH2 0x29D JUMPI PUSH1 0x40 MLOAD SWAP2 POP PUSH1 0x1F NOT PUSH1 0x3F RETURNDATASIZE ADD AND DUP3 ADD PUSH1 0x40 MSTORE RETURNDATASIZE DUP3 MSTORE RETURNDATASIZE PUSH1 0x0 PUSH1 0x20 DUP5 ADD RETURNDATACOPY PUSH2 0x2A2 JUMP JUMPDEST PUSH1 0x60 SWAP2 POP JUMPDEST POP POP SWAP1 POP DUP1 PUSH2 0x2E6 JUMPI PUSH1 0x40 MLOAD PUSH32 0x8C379A000000000000000000000000000000000000000000000000000000000 DUP2 MSTORE PUSH1 0x4 ADD PUSH2 0x2DD SWAP1 PUSH2 0x3BA JUMP JUMPDEST PUSH1 0x40 MLOAD DUP1 SWAP2 SUB SWAP1 REVERT JUMPDEST POP POP POP JUMP JUMPDEST PUSH1 0x0 DUP2 CALLDATALOAD SWAP1 POP PUSH2 0x2FA DUP2 PUSH2 0x572 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 DUP5 SUB SLT ISZERO PUSH2 0x316 JUMPI PUSH2 0x315 PUSH2 0x4F2 JUMP JUMPDEST JUMPDEST PUSH1 0x0 PUSH2 0x324 DUP5 DUP3 DUP6 ADD PUSH2 0x2EB JUMP JUMPDEST SWAP2 POP POP SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x33A PUSH1 0x3A DUP4 PUSH2 0x420 JUMP JUMPDEST SWAP2 POP PUSH2 0x345 DUP3 PUSH2 0x4F7 JUMP JUMPDEST PUSH1 0x40 DUP3 ADD SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x35D PUSH1 0x1D DUP4 PUSH2 0x420 JUMP JUMPDEST SWAP2 POP PUSH2 0x368 DUP3 PUSH2 0x546 JUMP JUMPDEST PUSH1 0x20 DUP3 ADD SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x380 PUSH1 0x0 DUP4 PUSH2 0x415 JUMP JUMPDEST SWAP2 POP PUSH2 0x38B DUP3 PUSH2 0x56F JUMP JUMPDEST PUSH1 0x0 DUP3 ADD SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH2 0x39F DUP2 PUSH2 0x4B9 JUMP JUMPDEST DUP3 MSTORE POP POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x3B0 DUP3 PUSH2 0x373 JUMP JUMPDEST SWAP2 POP DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP DUP2 DUP2 SUB PUSH1 0x0 DUP4 ADD MSTORE PUSH2 0x3D3 DUP2 PUSH2 0x32D JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP DUP2 DUP2 SUB PUSH1 0x0 DUP4 ADD MSTORE PUSH2 0x3F3 DUP2 PUSH2 0x350 JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH1 0x20 DUP3 ADD SWAP1 POP PUSH2 0x40F PUSH1 0x0 DUP4 ADD DUP5 PUSH2 0x396 JUMP JUMPDEST SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 DUP3 DUP3 MSTORE PUSH1 0x20 DUP3 ADD SWAP1 POP SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x43C DUP3 PUSH2 0x4B9 JUMP JUMPDEST SWAP2 POP PUSH2 0x447 DUP4 PUSH2 0x4B9 JUMP JUMPDEST SWAP3 POP DUP3 PUSH32 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF SUB DUP3 GT ISZERO PUSH2 0x47C JUMPI PUSH2 0x47B PUSH2 0x4C3 JUMP JUMPDEST JUMPDEST DUP3 DUP3 ADD SWAP1 POP SWAP3 SWAP2 POP POP JUMP JUMPDEST PUSH1 0x0 PUSH2 0x492 DUP3 PUSH2 0x499 JUMP JUMPDEST SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 PUSH20 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF DUP3 AND SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH1 0x0 DUP2 SWAP1 POP SWAP2 SWAP1 POP JUMP JUMPDEST PUSH32 0x4E487B7100000000000000000000000000000000000000000000000000000000 PUSH1 0x0 MSTORE PUSH1 0x11 PUSH1 0x4 MSTORE PUSH1 0x24 PUSH1 0x0 REVERT JUMPDEST PUSH1 0x0 DUP1 REVERT JUMPDEST PUSH32 0x416464726573733A20756E61626C6520746F2073656E642076616C75652C2072 PUSH1 0x0 DUP3 ADD MSTORE PUSH32 0x6563697069656E74206D61792068617665207265766572746564000000000000 PUSH1 0x20 DUP3 ADD MSTORE POP JUMP JUMPDEST PUSH32 0x416464726573733A20696E73756666696369656E742062616C616E6365000000 PUSH1 0x0 DUP3 ADD MSTORE POP JUMP JUMPDEST POP JUMP JUMPDEST PUSH2 0x57B DUP2 PUSH2 0x487 JUMP JUMPDEST DUP2 EQ PUSH2 0x586 JUMPI PUSH1 0x0 DUP1 REVERT JUMPDEST POP JUMP INVALID LOG2 PUSH5 0x6970667358 0x22 SLT KECCAK256 RETURNDATACOPY PUSH11 0x307BF621355CBCA6BFE007 0xDD REVERT PUSH23 0xBC4ACC8BBB5C5B09C0C0EA490F142AAD64736F6C634300 ADDMOD SMOD STOP CALLER ",
# 	"sourceMap": "116:775:1:-:0;;;;;;;;;;;;;;;;;;;"
# }
