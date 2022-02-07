import sys
import json
import os
from itertools import groupby
from timeit import repeat
import pydot
import pprint
import numpy as np
from collections import defaultdict
import pandas as pd
from IPython.core.display import display, HTML


sys.path.append('/Users/wamuo/Documents/GitHub/zhang-shasha')
print(sys.path)

from zss import simple_distance, Node

# Compare using json deep equals

# Pairwise deepEquals?
#     Reduce
#     jaccard score as initial value/label
#     Graph Coloring?
#     Color refinement


dir_path = os.path.dirname(os.path.abspath(__file__))
folder = os.path.abspath(os.path.join(dir_path, os.pardir))
print("patsfkfjlsfbufoajfdhkujh",folder)

OPERATIONS = {
    0: 'remove',
    1: 'insert',
    2: 'update',
    3: 'match'
}

A = (
    Node("f")
    .addkid(
        Node("d")
        .addkid(Node("a"))
        .addkid(Node("c")
                .addkid(Node("b")))
    )
    .addkid(Node("e"))
)
B = (
    Node("f")
    .addkid(
        Node("c")
            .addkid(Node("d")
            .addkid(Node("a"))
            .addkid(Node("b")))
                    )
    .addkid(Node("e"))
)


# distance, opts = simple_distance(A, B, return_operations=True)

# nodes = []
# for opt in opts:

#     s = OPERATIONS[opt.type]
#     if "match" == s:
#         continue
    
#     if opt.arg1 is not None:
#         s += f"\t{opt.arg1.label}"
#         nodes.append(opt.arg1)
#     if opt.arg2 is not None:
#         s += f"\t{opt.arg2.label}"
#         # nodes.append(opt.arg2)
#     print(s)
# print(nodes)

# exit()



class CustomNode(object):

    def __init__(self, id, ast):
        self.my_id = id
        self.my_label = getLabel(ast, id)
        self.my_children = list()

    @staticmethod
    def get_children(node):
        return node.my_children

    @staticmethod
    def get_label(node,):
        return node.my_label

    def addkid(self, node, before=False):
        if before:  self.my_children.insert(0, node)
        else:   self.my_children.append(node)
        return self


def get_ast(ast_file):
    return json.loads(
        open(os.path.join(folder, ast_file), 'r').read())


def get_adjacency_list(edges):
    edges = [(x["target"], x["source"]) for x in edges]
    # pprint.pprint("edges")
    # pprint.pprint(edges)
    return {k: [v[1] for v in g] for k, g in groupby(sorted(edges), lambda e: e[0])}


def getNode(ast,node):
    for x in ast['nodes']:
        if x["id"] == node:
            return x


def getNodesByterm(ast, term):
    nodes = []
    for x in ast['nodes']:
        if x["Name"] == term:
            nodes.append(x)
    return nodes



def getLabel(ast, node):
    label = ""
    for x in ast['nodes']:
        if x["id"] == node:
            name = x["Name"]
            # repeat_separator = ' x '
            # if repeat_separator in node:
            #     name = node.split(repeat_separator)[1] + repeat_separator + name
            if 'ram:' in name:
                name = name.split(':')[0]
            if 'const:200' in name:
                name = 'const:200'
            label = name + " type:" + x["VertexType"]
            break

    if not label:
        label = str(node)
    # print("node label", label)
    return label


# graph = pydot.Dot("my_graph", graph_type="graph", bgcolor="white")

def create_tree(ast, adj_list, root_node, root_id):
    for id in adj_list[root_id]:

        # graph.add_edge(pydot.Edge(root_id, id, color="blue", label=getLabel(ast,root_id) +" === "+getLabel(ast,id)))
        current_node = CustomNode(id, ast)
        root_node.addkid(current_node)
        if id in adj_list:
            create_tree(ast, adj_list, current_node, id)
        else:
            pass
    # graph.write_png("outputA.png")
    return root_node


def create_tree_with_orphans(ast, adj_list, orphans):
    root_id = "root"
    adj_list[root_id] = orphans
    root = CustomNode(root_id, ast)
    # print(adj_list[root_id])
    return create_tree(ast, adj_list, root, root_id)


def get_orphans(adj_list):
    orphans = []
    for node in adj_list:
        is_orphan = True
        for child in adj_list:
            if node in adj_list[child]:
                is_orphan = False
                break
        if is_orphan:
            orphans.append(node)
    # print("orphans", orphans)
    return orphans


def has_cycles(node, adj_list, visited, dfs_visited):
    visited[node] = 1
    dfs_visited[node] = 1
    for child_node in adj_list[node]:
        if not visited[child_node] and child_node in adj_list:
            if has_cycles(child_node,adj_list, visited, dfs_visited):
                return True
        elif dfs_visited[child_node]:
            return True
    
    dfs_visited[node] = 0
    return False


def is_cyclic(adj_list):
    visited = defaultdict(int)
    dfs_visited = defaultdict(int)

    for node in adj_list:
        if not visited[node]:
            if has_cycles(node, adj_list, visited, dfs_visited):
                return True
    return False


def delete_cyclic_edge(node, adj_list, new_adj_list, visited, dfs_visited):
    new_adj_list[node] = []
    visited[node] = 1
    dfs_visited[node] = 1
    for child_node in adj_list[node]:
        new_adj_list[node].append(child_node)
        if not visited[child_node] and child_node in adj_list:
            delete_cyclic_edge(child_node,adj_list, new_adj_list, visited, dfs_visited)
        elif dfs_visited[child_node]:
            # print('cycle detected: ', node, " going back to ", child_node, " EVICT EDGE!!")
            new_adj_list[node].remove(child_node)

    dfs_visited[node] = 0
    


def remove_cycles(adj_list):
    visited = defaultdict(int)
    dfs_visited = defaultdict(int)

    new_adj_list = {}

    for node in adj_list:
        if not visited[node]:
            delete_cyclic_edge(node, adj_list, new_adj_list, visited, dfs_visited)
                
    return new_adj_list



def remove_redundant(ast,adj_list):
    # COPY
    copy_nodes = getNodesByterm(ast,"COPY")
    print("Copy Nodes", copy_nodes)
    for copy_node in copy_nodes:
        copy_node_id = copy_node['id']
        for node_child in adj_list[copy_node_id]:
            for node in adj_list:
                if copy_node_id in adj_list[node]:
                    adj_list[node].remove(copy_node_id)
                    adj_list[node].append(node_child)
                    print("remove redundant", node,node_child)
        del adj_list[copy_node_id]



    
def get_rootnode(ast_file):
    ast = get_ast(ast_file)
    adj_list = get_adjacency_list(ast['edges'])
    # remove_redundant(ast,adj_list)
    # exit()
    adj_list = remove_cycles(adj_list)
    orphans = get_orphans(adj_list)
    root_node = create_tree_with_orphans(ast, adj_list, orphans)
    print("Tree size = ", len(ast['nodes']) + 1)

    return root_node



# cycle_list_1 = {'a': ['b'], 'b': ['c'], 'c':['a']}
# cycle_list_2 = {'a': ['b','d'], 'b': ['c'], 'c':['a','d']}

# print(remove_cycles(cycle_list_2))


# TestNode understand structure
# root_nodeC = get_rootnode('func_0x200077E4.json')
# exit()


# Calculate Difference using Tree Edit Distance

########## Two nodes slightly different Start ##########
# root_nodeA = get_rootnode('func2000ba98.json')
# root_nodeB = get_rootnode('func2000b824.json')

# root_nodeA = get_rootnode('func2000ba98_new.json')
# root_nodeB = get_rootnode('func2000b824_new.json')

# root_nodeA = get_rootnode('func_0x2000ba16.json')
# root_nodeB = get_rootnode('func_0x2000b7b8.json')

########## Two nodes slightly different End ##########



########## Two Nodes that should be equal with distance = 0 Start ##########

# root_nodeA = get_rootnode('func200079ba.json')
# root_nodeB = get_rootnode('func20007886.json')

########## Two Nodes that should be equal with distance = 0 End ##########

def save_panda(df, path):
    html = df.to_html()
    text_file = open(path + "_delta_ast.html", "w")
    text_file.write(html)
    text_file.close()


def add_color(text):

    if ("remove" in text):
        color = 'red' 
    if ("update" in text):
        color = 'orange'
    if ("insert" in text):
        color = 'blue'
    return 'color: %s' % color



def compare_ast(func_fileA = 'binary_ast/func_0x2000ba16.json', func_fileB = 'binary_ast/func_0x2000b7b8.json', path = "delta_ast"):
    root_nodeA = get_rootnode(func_fileA)
    root_nodeB = get_rootnode(func_fileB)
    distance, opts = simple_distance(root_nodeA, root_nodeB,CustomNode.get_children, CustomNode.get_label, return_operations=True)
    # distance, opts = simple_distance(root_nodeA, root_nodeB, return_operations=True)

    sout1 = ''
    sout2 = ''
    sout3 = ''
    changes = []
    for opt in opts:
        s = OPERATIONS[opt.type]
        sA = ""
        sB = ""
        sC = ""
        if opt.arg1 is not None:
            s += f"\t id:{opt.arg1.my_id} label:{opt.arg1.my_label}"
            sA += f"{opt.arg1.my_id},"
        if opt.arg2 is not None:
            s += f"\n\t id:{opt.arg2.my_id} label:{opt.arg2.my_label}"
            sB += f"{opt.arg2.my_id},"
        
        if "update" in s: 
            sC += f"{opt.arg1.my_id},{opt.arg2.my_id},"
            sA = ""
            sB = ""

        if "match" not in s: 
            # print(s)
            changes.append(s)
            sout1 += sA
            sout2 += sB
            sout3 += sC
    
    changes_np = np.array(changes)
    df = pd.DataFrame(changes_np, columns=["Change"])
    s2 = df.style.applymap(add_color)
    save_panda(s2,path)


    print("Removes")
    print(sout1)
    print("Inserts")
    print(sout2)
    print("Updates")
    print(sout3)
    print("distance", distance)
    print("opts", len(opts))

compare_ast(func_fileA = 'versions/otaApp-1_4_2_bin/0x200057d0.json', func_fileB = 'versions/otaApp-1_4_4_bin/0x200055d0.json')

