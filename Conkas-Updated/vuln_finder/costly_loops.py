from rattle import SSABasicBlock
from sym_exec.trace import Trace
from sym_exec.utils import get_argument_value

from vuln_finder.vulnerability import Vulnerability
from vuln_finder import vulnerability_finder
from sym_exec.utils import MAX_UVALUE

TX_ORIGIN_VULN = "TX.ORIGIN"
TX_ORIGIN_INSTRUCTION = "ORIGIN"
MSG_SENDER_INSTRUCTION = "CALLER"


def __find_instruction(block: SSABasicBlock, instruction_name: str):
    instructions = []
    for instruction in block.insns:
        if instruction.insn.name == instruction_name:
            instructions.append(instruction)
    return instructions


def costly_loops_analyse(traces: [Trace], find_all):
    all_vulns = set()
    analyzed_constraints = False
    exist_constraints = False
    block_analyzed = None
    analyzed_blocks = set()
    offset = None
    instruction_offset = None

    return all_vulns