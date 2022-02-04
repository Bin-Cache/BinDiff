import re
import json
import os
from random import shuffle
import numpy as np
import pandas as pd
import copy
import seaborn as sns
import matplotlib.pyplot as plt

from IPython.core.display import display, HTML
display(HTML("<style>div.output_scroll { height: 44em; }</style>"))


def read_graph(graph_fileA = 'ghidra_mods/graphA.json', graph_fileB = 'ghidra_mods/graphB.json'):
    return json.loads(open(graph_fileA, 'r').read()), json.loads(open(graph_fileB, 'r').read())

def jaccard(a, b):
    a = set(a)
    b = set(b)
    if len(a.union(b)) == 0:
       return 0
    else:
        return len(a.intersection(b)) / len(a.union(b))

inst_id = 3
def processOpCodes(graph, proc_format="none"):
    new_graph = copy.deepcopy(graph.copy())
    for func in graph:
        new_graph[func][inst_id] = process_opcode(new_graph[func][inst_id], proc_format)
    return new_graph

class Normalizer(object):
    def __init__(self):
        self.counter = -1

    def __call__(self, match):
        self.counter += 1
        return 'r{0}'.format(self.counter)

# compiler generated differences
similarInstructions = {"adr.w":"adr", "ldr.w":"ldr", "mov.w":"mov", "movw":"mov"}

class Replacer(object): 
    def __call__(self, match):
        if match.group(0) in similarInstructions:
            return similarInstructions[match.group(0)]
        return match.group(0)

# none
# normalize1
# normalize2
# normalize3
# opcodes
# instruction

proc_format = "none"
replacer = Replacer()


def process_opcode(opcode_sequence, proc_format="none"):
    if type(opcode_sequence) == list:
        opcode_sequence = " ".join(opcode_sequence)
    
    opcode_sequence = re.sub('0x[a-fA-F0-9]{8}', ' ', opcode_sequence)
    if proc_format == "none":
        opcode_sequence = re.sub('[\[\]\,\&]', ' ', opcode_sequence)
        opcode_sequence = re.sub('\s+', ' ', opcode_sequence)
        return opcode_sequence.strip().split(' ')
    elif proc_format == "normalize1":
        normalize = Normalizer()
        opcode_sequence = re.sub('[\&]', ' ', opcode_sequence)
        opcode_sequence = re.sub('r(1[0-2]|[0-9])', normalize, opcode_sequence)
        return opcode_sequence
    elif proc_format == "normalize2":
        instructions = ""
        for instruction in opcode_sequence.strip().split('&'):
            normalize = Normalizer()
            instructions += " " +re.sub('r(1[0-2]|[0-9])', normalize, instruction)
        return instructions.strip()
    elif proc_format == "normalize3":
        replace_pattern = re.compile('|'.join(map(re.escape, similarInstructions.keys())))
        return replace_pattern.sub(replacer, opcode_sequence)  
    elif proc_format == "opcodes":
        return [x.split(" ")[0] for x in opcode_sequence.strip().split('&')]
    
    elif proc_format == "instruction":
        return opcode_sequence.strip().split('&')
      

def compare_jaccard(a, b):
    return round(jaccard(set(a), set(b)), 3)


def split_by_2(op_list):
    return [' '.join([op_list[i], op_list[i+1]]) for i in range(len(op_list)) if i != len(op_list)-1]


def compare_2gram_jaccard(a, b):
    a = split_by_2(a)
    b = split_by_2(b)
    return round(jaccard(a, b), 3)


def compare(a, b):
    return compare_2gram_jaccard(a, b)


def getOpCode(aggregation_depth, graph, func):
    opcode = graph[func][inst_id]
    if aggregation_depth > 0:
        for child_func in graph[func][0]:
            opcode += getOpCode(0, graph, child_func)
            if aggregation_depth == 2:
                for child_func2 in graph[child_func][0]:
                    opcode += getOpCode(0, graph, child_func2)

    return opcode

def add_color(val):
    color = 'red' if (val >= 0) and (val < 0.6) else 'green'
    return 'color: %s' % color
                                    
def add_opacity(val):
    opacity = 20 if (val >= 0) and (val < 0.6) else None
    if opacity:
        return 'opacity: %s%%' % opacity
    return None


aggregation_depth = 0
include_peripheral = False
normalize = False

def calc_sim(compareFunc, graphA, graphB):
    scores = []
    for funcA in graphA:
        opcodeA = getOpCode(aggregation_depth, graphA, funcA)
        result = []
        for funcB in graphB:
            opcodeB = getOpCode(aggregation_depth, graphB, funcB)
            result.append(compareFunc(opcodeA, opcodeB))
        scores.append(result)
        
    return scores


def save_panda(df, path):
    html = df.to_html()
    text_file = open(path + "/delta_jaccard.html", "w")
    text_file.write(html)
    text_file.close()




# import ipython_genutils
def draw_results(graphA, graphB, scores, path, threshold):
    x_label = [func for func in graphB]
    y_label = [func for func in graphA]

    labels = []
    for i in range(len(scores)):
        item = scores[i]
        max_value = max(item)
        max_index = item.index(max_value)
        max_label = x_label[max_index]
        labels.append([max_label])
        scores[i] = [min(item), sum(item)/len(item), max_value]
        
    [labels[x].append(y_label[x]) for x in range(len(scores))]
    combined = zip(scores, labels)
    zipped_sorted = sorted(combined, key=lambda x: x[0][2])
    possible_updates = list(filter(lambda s: s[0][2] > threshold and s[0][2] != 1.0, zipped_sorted))
    sorted_scores, sorted_labels = map(list, zip(*zipped_sorted))
    # print(sorted_scores)
    # print(sorted_labels)

    scores_np = np.array(sorted_scores)
    df = pd.DataFrame(scores_np, columns=["min", "avg", "max"], index=[x[1] for x in sorted_labels])
#     ttips_data = [[x[0]] for x in sorted_labels]
#     ttips_data = [[x[0] + "" + " ".join(graphA[x[1]][2])] for x in sorted_labels]

    ttips_data = [[x[0] + " :::---> " + " ".join(graphA[x[1]][inst_id]) + " ====================?  " + x[1] + " :::---> "  + " ".join(graphB[x[0]][inst_id]) + "  : : : : :  differences" + str(set(graphA[x[1]][inst_id]).symmetric_difference(set(graphB[x[0]][inst_id])))] for x in sorted_labels]
    
    ttips = pd.DataFrame(data=ttips_data, columns=df.columns[[2]], index=df.index)
    s2 = df.style.applymap(add_color).set_tooltips(ttips)
    # display(s2)

    save_panda(s2,path)

    # sns.lineplot(y_label, [x[2] for x in scores])
    # plt.show()

    return possible_updates
    
    low_scores = []
    index = 0
    while sorted_scores[index][2] < 1:
        low_scores.append((sorted_labels[index],sorted_scores[index]))
        index = index + 1
    return low_scores



def calculate_jaccard(graph_fileA = 'ghidra_mods/graphA.json', graph_fileB = 'ghidra_mods/graphB.json', path = "jaccard", threshold = 0.9):
    main_graphA, main_graphB = read_graph(graph_fileA, graph_fileB)
    graphA = processOpCodes(main_graphA)
    graphB = processOpCodes(main_graphB)

    proc_format = "opcodes"
    graphA = processOpCodes(main_graphA, proc_format=proc_format)
    graphB = processOpCodes(main_graphB, proc_format=proc_format)
    scores = calc_sim(compare_jaccard, graphA, graphB)
    return draw_results(graphA, graphB, scores, path, threshold)



# proc_format = "instruction"
# graphA = processOpCodes(main_graphA, proc_format=proc_format)
# graphB = processOpCodes(main_graphB, proc_format=proc_format)
# scores = calc_sim(compare_jaccard, graphA, graphB)
# draw_results(scores)



