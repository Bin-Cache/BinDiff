from datasketch import MinHash
import networkx as nx
import re
import json
import os
from random import shuffle
import tlsh
import matplotlib.pyplot as plt
import seaborn as sns


graphA = json.loads(open('graphA.json', 'r').read())
graphB = json.loads(open('graphB.json', 'r').read())


def jaccard(a: set, b: set):
    return len(a.intersection(b)) / len(a.union(b))


def processOpCodes(graph):
    for func in graph:
        graphA[func][2] = process_opcode(graphA[func][2])


def process_opcode(opcode_sequence):
    opcode_sequence = re.sub('[\[\]\,]', ' ', opcode_sequence)
    opcode_sequence = re.sub('0x[a-fA-F0-9]{8}', ' ', opcode_sequence)
    opcode_sequence = re.sub('\s+', ' ', opcode_sequence)
    return opcode_sequence.strip().split(' ')


vocab = []
x_label = []
y_label = []
for func in graphA:
    y_label.append(func)
    opcodes = process_opcode(graphA[func][2])
    vocab.extend(opcodes)
for func in graphB:
    x_label.append(func)
    opcodes = process_opcode(graphB[func][2])
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
        return 500


def compare_jaccard(a, b):
    return jaccard(set(a), set(b))


def compare_minhashA(a, b):
    a_1hot = [1 if x in a else 0 for x in vocab]
    b_1hot = [1 if x in b else 0 for x in vocab]
    a_sig = create_sig(a_1hot)
    b_sig = create_sig(b_1hot)
    return jaccard(set(a_sig), set(b_sig))


def compare(a, b):
    return compare_jaccard(a, b)


# Check nodes we know are similar
a = process_opcode(graphA["0x20004a50"][2])
b = process_opcode(graphB["0x20004aa8"][2])
print("Simple Jaccard", compare_jaccard(a, b))
print("Minhash Score", compare_minhashA(a, b))
print("TLSH score", compare_tlsh(a, b))


scores = []

for funcA in graphA:
    opcodeA = graphA[funcA][2]
    result = []
    for funcB in graphB:
        opcodeB = graphB[funcB][2]
        result.append(compare(opcodeA, opcodeB))
    scores.append(result)


for i in range(len(scores)):
    item = scores[i]
    scores[i] = [min(item), sum(item)/len(item), max(item)]


[scores[x].append(y_label[x]) for x in range(len(scores))]

sorted_scores = sorted(scores, key=lambda x: x[2])
print(sorted_scores[0:60])

sns.lineplot(y_label, [x[2] for x in scores])
plt.show()
