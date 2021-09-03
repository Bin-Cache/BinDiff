import json
import os

folder = os.path.dirname(os.path.abspath(__file__))
graphA = json.loads(
    open(os.path.join(folder, 'graphA.json'), 'r').read())
graphB = json.loads(
    open(os.path.join(folder, 'graphB.json'), 'r').read())


for func_addressA in graphA:
    for func_addressB in graphB:
        funcA_peri = graphA[func_addressA][1]
        funcB_peri = graphB[func_addressB][1]
        if len(funcA_peri) == len(funcB_peri) and len(funcA_peri) > 0 and funcA_peri == funcB_peri:
             print("{} in graphA and {} in graphB seem the same".format(func_addressA, func_addressB))
            

