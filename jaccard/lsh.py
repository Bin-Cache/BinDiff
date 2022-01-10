from datasketch import MinHash
import networkx as nx
import re
import json
import os
from random import shuffle
import tlsh
import matplotlib.pyplot as plt
import seaborn as sns
import numpy as np
import pandas as pd


graphA = json.loads(open('graphA.json', 'r').read())
graphB = json.loads(open('graphB.json', 'r').read())


def jaccard(a, b):
    a = set(a)
    b = set(b)
    return len(a.intersection(b)) / len(a.union(b))


def processOpCodes(graph):
    for func in graph:
        graph[func][2] = process_opcode(graph[func][2])


# none
# normalize
# opcodes
# instruction

proc_format = "none"


def process_opcode(opcode_sequence, proc_format="none"):
    if proc_format == "none":
        opcode_sequence = re.sub('[\[\]\,]', ' ', opcode_sequence)
        opcode_sequence = re.sub('0x[a-fA-F0-9]{8}', ' ', opcode_sequence)
        opcode_sequence = re.sub('\s+', ' ', opcode_sequence)
        return opcode_sequence.strip().split(' ')
    elif proc_format == "normalize":
        pass
    
    elif proc_format == "opcodes":
        pass
    
    elif proc_format == "instruction":
        return opcode_sequence.strip().split(' ')
        pass

    


processOpCodes(graphA)
processOpCodes(graphB)

vocab = []
x_label = []
y_label = []
for func in graphA:
    y_label.append(func)
    opcodes = graphA[func][2]
    vocab.extend(opcodes)
for func in graphB:
    x_label.append(func)
    opcodes = graphB[func][2]
    vocab.extend(opcodes)
vocab = set(vocab)


def create_hash_func(size: int):
    # function for creating the hash vector/function
    hash_ex = list(range(1, len(vocab)+1))
    shuffle(hash_ex)
    return hash_ex


def build_minhash_func(vocab_size: int, nbits: int):
    # function for building multiple minhash vectors
    hashes = []
    for _ in range(nbits):
        hashes.append(create_hash_func(vocab_size))
    return hashes


# we create 20 minhash vectors
minhash_func = build_minhash_func(len(vocab), 20)


def create_sig(vector: list):
    # use this function for creating our signatures (eg the matching)
    signature = []
    for func in minhash_func:
        for i in range(1, len(vocab)+1):
            idx = func.index(i)
            signature_val = vector[idx]
            if signature_val == 1:
                signature.append(idx)
                break
    return signature


def split_vector(signature, b):
    assert len(signature) % b == 0
    r = int(len(signature) / b)
    # code splitting signature in b parts
    subvecs = []
    for i in range(0, len(signature), r):
        subvecs.append(signature[i: i+r])
    return subvecs


def compare_minhashB(nodeA, nodeB):
    # m1, m2 = MinHash(num_perm=64), MinHash(num_perm=64)
    # for d in dataA:
    #     m1.update(d.encode('utf8'))
    # for d in dataB:
    #     m2.update(d.encode('utf8'))
    # return m1.jaccard(m2) > 0.5
    pass


def compare_tlsh(a, b):
    a = str.encode(' '.join(a))
    b = str.encode(' '.join(b))
    try:
        h1 = tlsh.hash(a)
        h2 = tlsh.hash(b)
        return tlsh.diff(h1, h2)
    except:
        return 1000


def compare_jaccard(a, b):
    return round(jaccard(set(a), set(b)), 3)


def split_by_2(op_list):
    return [' '.join([op_list[i], op_list[i+1]]) for i in range(len(op_list)) if i != len(op_list)-1]


def compare_2gram_jaccard(a, b):
    a = split_by_2(a)
    b = split_by_2(b)
    return round(jaccard(a, b), 3)


def compare_minhashA(a, b):
    a_1hot = [1 if x in a else 0 for x in vocab]
    b_1hot = [1 if x in b else 0 for x in vocab]
    a_sig = create_sig(a_1hot)
    b_sig = create_sig(b_1hot)
    return jaccard(a_sig, b_sig)


def compare(a, b):
    return compare_2gram_jaccard(a, b)


# Check nodes we know are similar
a = graphA["0x20004a50"][2]
b = graphB["0x20004aa8"][2]
print("Simple Jaccard", compare_jaccard(a, b))
print("Minhash Score", compare_minhashA(a, b))
print("TLSH score", compare_tlsh(a, b))


aggregation_depth = 0
include_peripheral = False


def getOpCode(aggregation_depth, graph, func):
    opcode = graph[func][2]
    if aggregation_depth > 0:
        for child_func in graph[func][0]:
            opcode += getOpCode(0, graph, child_func)
            if aggregation_depth == 2:
                for child_func2 in graph[child_func][0]:
                    opcode += getOpCode(0, graph, child_func2)

    return opcode


scores = []

for funcA in graphA:
    opcodeA = getOpCode(aggregation_depth, graphA, funcA)
    result = []
    for funcB in graphB:
        opcodeB = getOpCode(aggregation_depth, graphB, funcB)
        result.append(compare(opcodeA, opcodeB))
    scores.append(result)
    break

normalize = False

if(normalize):
    for i in range(len(scores)):
        result = scores[i]
        max_value = max(result)
        scores[i] = [(1 - (x/max_value)) for x in result]


print(scores)
for i in range(len(scores)):
    item = scores[i]
    max_value = max(item)
    max_index = item.index(max_value)
    max_label = x_label[max_index]
    scores[i] = [min(item), sum(item)/len(item), (max_value, max_label)]


[scores[x].append(y_label[x]) for x in range(len(scores))]

sorted_scores = sorted(scores, key=lambda x: x[2])
print(sorted_scores[0:60])

scores_array = np.asarray(sorted_scores)
# pd.set_option("display.max_rows", None)
df = pd.DataFrame(scores_array)

def _color_red_or_green(val):
    color = 'red' if val < 0 else 'green'
    return 'color: %s' % color
df.style.applymap(_color_red_or_green)

print(df)

# sns.lineplot(y_label, [x[2] for x in scores])
# plt.show()
