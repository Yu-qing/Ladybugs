from slither.core.declarations.solidity_variables import SOLIDITY_VARIABLES_COMPOSED 
from slither.core.declarations.structure import Structure
from slither.core.solidity_types.mapping_type import MappingType
from slither.detectors.abstract_detector import AbstractDetector, DetectorClassification
from slither.slithir.operations import Assignment, Binary, BinaryType, Member, Index, TypeConversion
from slither.slithir.variables import Constant, ReferenceVariable, TemporaryVariable
from slither.detectors.arithmetic.temp_and_reference_variables import Handle_TmpandRefer

def check_compare(ir):
    if isinstance(ir, Binary):
        if ir.type in [BinaryType.EQUAL, BinaryType.LESS_EQUAL, BinaryType.LESS, BinaryType.GREATER_EQUAL, BinaryType.GREATER]:
            return True
    return False

def detect(f, state_var):
    tmps = Handle_TmpandRefer()
    var_be_compute = [] #在同一個函式內曾做過計算的state variables
    res_node = []     
    res_var  = {}      #儲存被紀錄到res_node中的state variables

    for n in f.nodes:
        for ir in n.irs:

            temp_vars = tmps.temp
            temp_type = tmps.logtype
            # a[i]
            if isinstance(ir, Index):
                tmps.handle_index(ir)

            # uint(a)
            elif isinstance(ir, TypeConversion):
                tmps.handle_conversion(ir)

            # 取structur內的變數 REF = a.b
            if isinstance(ir, Member):
                tmps.handle_member(ir)
            
            #  a = b
            if isinstance(ir, Assignment):
                left = ir.lvalue

                if isinstance(left, (ReferenceVariable, TemporaryVariable)):
                    tleft = temp_type[left]

                    if tleft == 2:  
                        left = (temp_vars[left][0][0], temp_vars[left][1])
                        while isinstance(left[0], tuple):
                            left[0] = left[0][0]
                        while isinstance(left[1], tuple):
                            left[1] = left[1][0]

                    else:
                        left = temp_vars[left][0]
                        while isinstance(left, tuple):
                            left = left[0]
                        
                    if left in state_var:
                        var_be_compute.append(left)
                    

                elif left in state_var:
                    var_be_compute.append(left)


            # 某些數值（如答案）不能使用明碼存在合約中
            # 其判斷可能會使用 ==, <=, <, >=, >
            if check_compare(ir):
                (left, right) = ir.read
                tleft  = temp_type[left]
                tright = temp_type[right]

                if isinstance(left, (ReferenceVariable, TemporaryVariable)) and left in temp_vars:
                    if tleft == 2: 
                        left = (temp_vars[left][0][0], temp_vars[left][1])
                        while isinstance(left[0], tuple):
                            left[0] = left[0][0]
                        while isinstance(left[1], tuple):
                            left[1] = left[1][0]
                    else:
                        left = temp_vars[left][0]
                        while isinstance(left, tuple):
                            left = left[0]

                if isinstance(right, (ReferenceVariable, TemporaryVariable)) and right in temp_vars:
                    if tright == 2:
                        right = (temp_vars[right][0][0],temp_vars[right][1])
                        while isinstance(right[0], tuple):
                            right[0] = right[0][0]
                        while isinstance(right[1], tuple):
                            right[1] = right[1][0]
                    else:
                        right = temp_vars[right][0]
                        while isinstance(right, tuple):
                            right = right[0]

                if (left in state_var and left not in var_be_compute 
                    and not isinstance(right, (ReferenceVariable, TemporaryVariable))
                    and right not in SOLIDITY_VARIABLES_COMPOSED
                ):
                    res_node.append(n)
                
                if (right in state_var and right not in var_be_compute
                    and not isinstance(left, (ReferenceVariable, TemporaryVariable))
                    and left not in SOLIDITY_VARIABLES_COMPOSED
                ):
                    res_node.append(n)
            
    return res_node

class PublicData(AbstractDetector):
    ARGUMENT = "public-data"
    HELP = "Null"
    IMPACT = DetectorClassification.HIGH
    CONFIDENCE = DetectorClassification.HIGH

    WIKI = "https://github.com/crytic/slither/wiki/Detector-Documentation/#public-data"
    WIKI_TITLE = "Public Data"
    WIKI_DESCRIPTION = "Null"

    # region wiki_exploit_scenario
    WIKI_EXPLOIT_SCENARIO = """
    ```solidity
    //from JiuZhou

    struct Wallet {
        bytes32 password;
        uint balance;
    }
    mapping(uint => Wallet) private wallets;

    function createAnAccount(uint256 _account, bytes32 _password) public{
        wallets[_account].balance = 0;
        wallets[_account].password = _password;
    }

    function withdraw(uint _wallet, bytes32 _password, uint _value) public {
        require(wallets[_wallet].password == _password);
        require(wallets[_wallet].balance >= _value);
        msg.sender.transfer(_value);
    }
    ```"""
    # endregion wiki_exploit_scenario

    WIKI_RECOMMENDATION = "Don't use smart contracts to store passwords or valuable puzzle answers."

    def _detect(self):
        """"""
        nodes = []
        res = []
        results = []

        for c in self.contracts:
            state_var = []
            priv_st   = []

            for v in c.variables:
                if v.visibility not in ["private", "internal"]:
                    continue

                if isinstance(v.type, MappingType):       
                    if isinstance(v.type.type_from.type, Structure):
                        priv_st.append((v, v.type.type_from.type))
                    if isinstance(v.type.type_to.type, Structure):
                        priv_st.append((v, v.type.type_to.type))
                elif isinstance(v.type, Structure):
                    priv_st.append((v,v.type))
                else:
                    state_var += [v]
            
            for (v, st) in priv_st:
                state_var += [(v, i) for i in st.elems if ('balance' not in i) and ('value' not in i)]
            
            
            for f in c.functions_declared:
                if f.name in ["slitherConstructorVariables", "slitherConstructorConstantVariables"]:
                    continue
                if f.visibility not in ["public", "external"]:
                    continue

                nodes += detect(f, state_var)
                if nodes:
                    info = [
                        f,
                        " don't use smart contracts to store sensitive data .\n",
                    ]

                    nodes.sort(key=lambda x: x.node_id)

                    for node in nodes:
                        info += ["\t-", node, "\n"]

                    res = self.generate_result(info)
                    results.append(res)

        return results
