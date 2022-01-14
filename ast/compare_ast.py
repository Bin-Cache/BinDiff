import json
import os
from itertools import groupby
import pydot
import pprint
import numpy as np
from collections import defaultdict

from zss import simple_distance, Node

# Compare using json deep equals

# Pairwise deepEquals?
#     Reduce
#     jaccard score as initial value/label
#     Graph Coloring?
#     Color refinement


folder = os.path.dirname(os.path.abspath(__file__))


def get_ast(ast_file):
    return json.loads(
        open(os.path.join(folder, ast_file), 'r').read())


def get_adjacency_list(edges):
    edges = [(x["target"], x["source"]) for x in edges]
    # pprint.pprint("edges")
    # pprint.pprint(edges)
    return {k: [v[1] for v in g] for k, g in groupby(sorted(edges), lambda e: e[0])}


def getLabel(ast, node):
    label = ""
    for x in ast['nodes']:
        if x["id"] == node:
            name = x["Name"]
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
        current_node = Node(getLabel(ast, id))
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
    root = Node(root_id)
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
    print("orphans", orphans)
    return orphans


def get_rootnode(ast_file):
    ast = get_ast(ast_file)
    adj_list = get_adjacency_list(ast['edges'])
    adj_list = remove_cycles(adj_list)
    orphans = get_orphans(adj_list)
    root_node = create_tree_with_orphans(ast, adj_list, orphans)
    print("Tree size = ", len(ast['nodes']) + 1)
    return root_node



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
            print('cycle detected: ', node, " going back to ", child_node, " EVICT EDGE!!")
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
    


cycle_list_1 = {'a': ['b'], 'b': ['c'], 'c':['a']}
cycle_list_2 = {'a': ['b','d'], 'b': ['c'], 'c':['a','d']}

# print(remove_cycles(cycle_list_2))


# TestNode understand structure
# root_nodeC = get_rootnode('func_0x2000bee8.json')

# Calculate Difference using Tree Edit Distance

# Two nodes slightly different
root_nodeA = get_rootnode('func2000ba98.json')
root_nodeB = get_rootnode('func2000b824.json')



# Two Nodes that should be equal with distance = 0
# root_nodeA = get_rootnode('func200079ba.json')
# root_nodeB = get_rootnode('func20007886.json')

distance, opts = simple_distance(root_nodeA, root_nodeB, return_operations=True)


# Calculate Difference using Deepequals
# ddiff = DeepDiff(astA["node"], astB["node"], ignore_order=True)
# print (ddiff)


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
OPERATIONS = {
    0: 'remove',
    1: 'insert',
    2: 'update',
    3: 'match'
}


for opt in opts:
    s = OPERATIONS[opt.type]
    if opt.arg1 is not None:
        s += f"\t{opt.arg1.label}"
    if opt.arg2 is not None:
        s += f"\t{opt.arg2.label}"
    if "match" not in s: 
        print(s)

print("distance", distance)
print("opts", len(opts))
