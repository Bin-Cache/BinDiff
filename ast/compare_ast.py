from deepdiff import DeepDiff
import json
import os
from itertools import groupby
import pydot
import pprint
import numpy as np

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
    pprint.pprint("edges")
    pprint.pprint(edges)
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
    print("node label", label)
    return label


# graph = pydot.Dot("my_graph", graph_type="graph", bgcolor="white")

def create_tree(ast, adj_list, root_node, root_id, seen=[]):
    for id in adj_list[root_id]:
        # if id in seen:
        #     continue
        # seen.append(id)

        # graph.add_edge(pydot.Edge(root_id, id, color="blue", label=getLabel(ast,root_id) +" === "+getLabel(ast,id)))
        current_node = Node(getLabel(ast, id))
        root_node.addkid(current_node)
        if id in adj_list:
            create_tree(ast, adj_list, current_node, id, seen)
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
    orphans = get_orphans(adj_list)
    root_node = create_tree_with_orphans(ast, adj_list, orphans)
    print("Tree size = ", len(ast['nodes']) + 1)
    return root_node


# TestNode understand structure
# root_nodeC = get_rootnode('func_0x2000bee8.json')

# Calculate Difference using Tree Edit Distance

# Two nodes slightly different
# root_nodeA = get_rootnode('func2000ba98.json')
# root_nodeB = get_rootnode('func2000b824.json')



# Two Nodes that should be equal with distance = 0
root_nodeD = get_rootnode('func200079ba.json')
root_nodeE = get_rootnode('func20007886.json')

distance, opts = simple_distance(root_nodeD, root_nodeE, return_operations=True)


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
    print(s)

print("distance", distance)
