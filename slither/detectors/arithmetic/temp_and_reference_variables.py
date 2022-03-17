from collections import defaultdict
from slither.slithir.variables import Constant, ReferenceVariable, TemporaryVariable

class Handle_TmpandRefer():

    def __init__(self):
        self._temp      = defaultdict(list)
        self._logtype   = defaultdict(int) #1:index 2:member 3:conversion 4:length
        self._constant  = []
        self._index     = []
        self._member    = []
        self._typeconv  = []
        self._length    = []


    #use tuple to store ()
    def handle_index(self, ir):
        (var, index) = ir.read

        if isinstance(var, (ReferenceVariable, TemporaryVariable)) and (var in self._temp):
            var = self._temp[var]
            if len(var) == 1:
                var = var[0]

        if isinstance(index, Constant):
            index = str(index)

        elif (not isinstance(index, Constant) and 
            isinstance(index, (ReferenceVariable, TemporaryVariable)) and 
            index in self._temp
        ):
            index = self._temp[index]
            if len(index) == 1:
                index = index[0]
        
        self._temp[ir.lvalue]    = (var, index)
        self._logtype[ir.lvalue] = 1
        self._index.append(ir.lvalue)


    def handle_member(self, ir):
        (var, member) = ir.read
        
        if isinstance(var, (ReferenceVariable, TemporaryVariable)) and (var in self._temp):
            var = self._temp[var]
            if len(var) == 1:
                var = var[0]

        if (isinstance(member, (ReferenceVariable, TemporaryVariable)) and 
            member in self._temp
        ):
            member = self._temp[member]
            if len(member) == 1:
                member = member[0]
        
        self._temp[ir.lvalue]    = (var, member)
        self._logtype[ir.lvalue] = 2
        self._member.append(ir.lvalue)


    #use list to store
    def handle_conversion(self, ir):
        var = ir.variable
        if isinstance(var, Constant):
            self._constant += [var]
            return
        
        if isinstance(var, (ReferenceVariable, TemporaryVariable)) and (var in self._temp):
            self._temp[ir.lvalue] = self._temp[var]
        else:
            self._temp[ir.lvalue] = [var]

        self._logtype[ir.lvalue] = 3
        self._typeconv.append(ir.lvalue)


    def handle_length(self, ir):
        var = ir.value
        if isinstance(var, (ReferenceVariable, TemporaryVariable)) and (var in self._temp):
            self._temp[ir.lvalue] = self._temp[var]
        else:
            self._temp[ir.lvalue] = [var]
        
        self._logtype[ir.lvalue] = 4   
        self._length.append(ir.lvalue)

    @property
    def temp(self):
        return self._temp

    @property
    def logtype(self):
        return self._logtype

    @property
    def constant(self):
        return self._constant
    
    @property
    def length(self):
        return self._length