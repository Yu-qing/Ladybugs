from collections import defaultdict
from slither.core.solidity_types.array_type import ArrayType
from slither.slithir.variables import ReferenceVariable, TemporaryVariable
from slither.slithir.operations import Binary, BinaryType, TypeConversion, Index
from slither.core.solidity_types.elementary_type import ElementaryType, Int, Uint
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification

def is_equal_or_not_equal(ir):
    if isinstance(ir, Binary):
        if ir.type in (BinaryType.EQUAL, BinaryType.NOT_EQUAL):
            return True
    return False

def detect_conversions(nodes):
    f_results = []
    tmps = defaultdict(list)
    condition_nodes = []
    
    for node in nodes:
        for ir in node.irs:
            # uint(a) == a, a[i] == uint(a[i]), ...
            if is_equal_or_not_equal(ir):
                (left, right) = ir.read
                type = []
                type_flag = False

                if isinstance(left, TemporaryVariable) and (left in tmps):
                    (v, t) = tmps[left]
                    left = v
                    type.append(t)
                    type_flag = True
                else:
                    type.append(None)

                if isinstance(right, TemporaryVariable) and(right in tmps):
                    (v, t) = tmps[right]
                    right = v
                    type.append(t)
                    type_flag = True
                else:
                    type.append(None)
                
                if isinstance(left, ReferenceVariable):
                    left = left.points_to_origin
                
                if isinstance(right, ReferenceVariable):
                    right = right.points_to_origin

                if (left == right) and type_flag:
                    if (left, type) not in condition_nodes:
                        condition_nodes += [(left, type)]


            elif isinstance(ir, TypeConversion) and isinstance(ir.type, ElementaryType):
                if node.contains_if() or node.contains_require_or_assert():
                    tmps[ir.lvalue] = (ir.variable, ir.type)

                else:
                    var = ir.variable
                    convert_type = ir.type

                    if isinstance(var, ReferenceVariable):
                        var = var.points_to_origin

                    if (var, convert_type) in condition_nodes:
                        continue
                    
                    else:
                        if (convert_type.name in Uint) or (convert_type.name in Int):
                            var_type = var.type
                            if not isinstance(var_type, (ElementaryType, ArrayType)):
                                continue

                            if isinstance(var_type, ArrayType):
                                var_type = var_type.type

                            if var_type.name in Uint:
                                if var_type.max > convert_type.max:
                                    f_results += [node]

                            elif var_type.name in Int:
                                if var_type.max > convert_type.max:
                                    f_results += [node]
                                elif var_type.min < convert_type.min:
                                    f_results += [node]

    return f_results    


class Truncation(AbstractDetector):
    """
    Documentation
    """

    ARGUMENT = 'truncation' # slither will launch the detector with slither.py --detect mydetector
    HELP = 'Integer truncation'
    IMPACT = DetectorClassification.LOW
    CONFIDENCE = DetectorClassification.HIGH

    # region wiki
    WIKI = 'https://github.com/crytic/slither/wiki/Detector-Documentation#integer_truncation'
    WIKI_TITLE = 'Integer Truncation'
    WIKI_DESCRIPTION = 'In *Solidity*, a loss of accuracy may occur when (1) a longer integer is cast to a shorter one, (2)unsigned integer types are converted to the corresponding signed integer types, (3)signed integer types are converted to the corresponding unsigned integer types.'
    WIKI_EXPLOIT_SCENARIO = """
```solidity
contract Truncation {
   unction receiveEther() public payable{
        //truncation Error
        //In Solidity, a loss of accuracy may occur when a longer integer is cast to a shorter one.
        require(balances[msg.sender] + uint32(msg.value) >= balances[msg.sender]);
        balances[msg.sender] += uint32(msg.value);
    }
}
```
"""
    WIKI_RECOMMENDATION = 'Check the variable type to be converted'
    # endregion wiki

    def _detect(self):
        results = []
        for c in self.contracts:
            conversions = []

            for f in c.functions_declared:

                f_results = detect_conversions(f.nodes)

                if f_results:
                     conversions.append((f, f_results))

            if conversions:
                for (func, nodes) in conversions:
                    info = [
                        func,
                        "It may cause data loss or misinterpretation.\n",
                    ]

                    nodes.sort(key=lambda x: x.node_id)

                    for node in nodes:
                        info += ["\t-", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

        return results
