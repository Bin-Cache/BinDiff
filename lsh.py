from datasketch import MinHash
import networkx as nx
import re
import json
import os

graphA = json.loads(open('graphA.json', 'r').read())
graphB = json.loads(open('graphB.json', 'r').read())



def processOpCodes(graph):
    for func in graph:
        graphA[func][2] = process_opcode(graphA[func][2])
       

def process_opcode(opcode_sequence):
    opcode_sequence = re.sub('[\[\]\,]',' ',opcode_sequence)
    opcode_sequence = re.sub('0x[a-fA-F0-9]{8}',' ',opcode_sequence)
    opcode_sequence = re.sub('\s+',' ',opcode_sequence)
    return opcode_sequence

# Check
a = process_opcode(graphA["0x20004a50"][2])
b = process_opcode(graphB["0x20004aa8"][2])
print(a)
print(b)
print(a==b)

a = set(a)
b = set(b)
actual_jaccard = float(len(a.intersection(b)))/float(len(a.union(b)))
print(actual_jaccard)

calledFuncGraphA = dict()
calledFuncGraphB = dict()

for func in graphA:
    calledFuncGraphA[func] = graphA[func][0]
for func in graphB:
    calledFuncGraphB[func] = graphB[func][0]

print(len(graphA))
print(len(graphB))
A = nx.from_dict_of_lists(calledFuncGraphA)
B = nx.from_dict_of_lists(calledFuncGraphB)

nodeA_attr = []
nodeB_attr = []

for func in graphA:
    nodeA_attr.append((func, {"opcode": process_opcode(graphA[func][2])}))
for func in graphB:
    nodeB_attr.append((func, {"opcode": process_opcode(graphB[func][2])}))

A.add_nodes_from(nodeA_attr)
B.add_nodes_from(nodeB_attr)


def node_match(nodeA, nodeB):
    m1, m2 = MinHash(num_perm=64), MinHash(num_perm=64)
    for d in dataA:
        m1.update(d.encode('utf8'))
    for d in dataB:
        m2.update(d.encode('utf8'))
    return m1.jaccard(m2) > 0.5

def node_match2(nodeA, nodeB):
    s1 = set(nodeA["opcode"])
    s2 = set(nodeB["opcode"])
    actual_jaccard = float(len(s1.intersection(s2)))/float(len(s1.union(s2)))
    print(actual_jaccard)
    return actual_jaccard > 0.8

# nx.graph_edit_distance(A, B, node_match=node_match2)

