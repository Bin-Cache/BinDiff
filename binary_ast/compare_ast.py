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
from IPython import display
import subprocess


sys.path.append('/Users/wamuo/Documents/GitHub/zhang-shasha')
# print(sys.path)

from zss import simple_distance, Node

# Compare using json deep equals

# Pairwise deepEquals?
#     Reduce
#     jaccard score as initial value/label
#     Graph Coloring?
#     Color refinement


dir_path = os.path.dirname(os.path.abspath(__file__))
folder = os.path.abspath(os.path.join(dir_path, os.pardir))

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

    def __init__(self, id, edge, ast):
        self.my_id = id
        self.edge = edge
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
        current_node = CustomNode(id, (id, root_id), ast)
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
    root = CustomNode(root_id, (root_id, None), ast)
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



    
def get_rootnode(ast):
    adj_list = get_adjacency_list(ast['edges'])
    # remove_redundant(ast,adj_list)
    # exit()
    adj_list = remove_cycles(adj_list)
    orphans = get_orphans(adj_list)
    root_node = create_tree_with_orphans(ast, adj_list, orphans)
    print("Tree size = ", len(ast['nodes']) + 1)
    tree_size = len(ast['nodes'])

    return root_node, tree_size



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

def save_result(result, path):
    with open(path + "result.json", "w") as outfile: 
        json.dump(result, outfile)





def add_color(text):
    color = "black"
    if ("remove" in text):
        color = 'red' 
    if ("update" in text):
        color = 'orange'
    if ("insert" in text):
        color = 'blue'
    return 'color: %s' % color


def get_op_address(edge_string):
    print(edge_string)
    print(edge_string)
    print(edge_string)
    print(edge_string)
    print(edge_string)
    edge_tuple = eval(edge_string)
    node = edge_tuple[0] if "o" in edge_tuple[0] else edge_tuple[1]
    if node == "root":
        return 0
    address = node.split(" o ")[0].split(":")[1]
    return address

def get_instruction_at_op(binary_folder, edge_string):
    instruction = ""
    if "->" in edge_string:
        addresses = []
        for i in edge_string.split("->"):
            addresses.append(get_op_address(i))
        
        if addresses[0] != 0:
            binary_a = binary_folder[0].split("/")[1].replace('_', '.')
            subprocess.call(['./ghidra_mods/instruction.sh', binary_a , addresses[0]])
            with open("temp") as f:
                instruction = f.read().rstrip()

        if addresses[1] != 0:
            binary_b = binary_folder[1].split("/")[1].replace('_', '.')
            subprocess.call(['./ghidra_mods/instruction.sh', binary_b , addresses[1]])
            with open("temp") as f:
                instruction += "->" + f.read().rstrip()

    else:
        binary = binary_folder[0].split("/")[1].replace('_', '.')
        op_addr =  get_op_address(edge_string)
        if op_addr != 0:
            subprocess.call(['./ghidra_mods/instruction.sh', binary , op_addr])
            with open("temp") as f:
                instruction = f.read().rstrip()
    
    print(instruction)
    return instruction


def get_changes(table):
    updates = table[table['Change'].str.contains('update')]

    inserts = table[table['Change'].str.contains(
        'insert')]
    removes = table[table['Change'].str.contains(
        'remove')]

    return updates, inserts, removes



    adj_list = get_adjacency_list(ast['edges'])
    # remove_redundant(ast,adj_list)
    # exit()
    adj_list = remove_cycles(adj_list)
def get_groups(table, func_fileA = 'versions/otaApp-1_4_2_bin/0x2000ba98.json', func_fileB = 'versions/otaApp-1_4_4_bin/0x2000b824.json'):
    adjA = get_adjacency_list(get_ast(func_fileA)['edges'])
    adjA = remove_cycles(adjA)
    adjB = get_adjacency_list(get_ast(func_fileB)['edges'])
    adjB = remove_cycles(adjB)

 
    updates, inserts, removes = get_changes(table)
    change_group = {}

    remove_calls_ids = removes[removes['Change'].str.contains('label:CALL')]['ID'].values.tolist()
    insert_calls_ids = inserts[inserts['Change'].str.contains('label:CALL')]['ID'].values.tolist()
    print("removes",remove_calls_ids)
    insert_ids = inserts['ID'].values.tolist()
    remove_ids = removes['ID'].values.tolist()

    change_group = {}

    get_call_groups(adjA, removes, remove_ids, change_group, remove_calls_ids)
    get_call_groups(adjB, inserts, insert_ids, change_group, insert_calls_ids)


    get_root_groups(adjA, change_group, remove_ids)
    get_root_groups(adjB, change_group, insert_ids)

    return change_group

def get_root_groups(adjB, change_group, ids):
    visited = defaultdict(int)

    for id in ids:
        if not visited[id]:
            tag_root_change(id, adjB, visited, change_group, ids, id)

def get_call_groups(adjA, call_table, changes, change_group, call_ids):
    for call in call_ids:
        tag_call_subtree(call, adjA, change_group, changes, call)
        call_func = call.split(" o ")[0]
        print(call_func)
        call_edges = call_table[(call_table['Change'].str.contains('label:INDIRECT')) &
            (call_table['Change'].str.contains(call_func))]['Edge'].values.tolist()
        for edge in call_edges:
            try:
                edge = eval(edge)
                remove_item_from_list(changes, edge[0])
                change_group[edge[0]] = "Call: " +call
                remove_item_from_list(changes, edge[1])
                change_group[edge[1]] = "Call: " +call
            except ValueError:
                print(edge)
                print(ValueError)

    
def tag_root_change(id, adj, visited, change_group, insert_ids, root_id):
    change_group[id] = "parent: " +root_id
    visited[id] = 1
    
    if id in adj:
        for child in adj[id]:
            if child in insert_ids:
                tag_root_change(child, adj, visited, change_group, insert_ids, root_id)

    
def tag_call_subtree(node, adj, change_group, changes, root):
    change_group[node] = "Call: " +root
    remove_item_from_list(changes, node)
    for id in adj[node]:
        if id in adj:
            tag_call_subtree(id, adj, change_group, changes, root)
        else:
            change_group[id] = "Call: " +root
            remove_item_from_list(changes, id)


def remove_item_from_list(list, item):
    print("removing", item)
    print(list)
    if item in list:
        list.remove(item)

    
    
def compare_ast(bin_folderA, bin_folderB, func_fileA = 'binary_ast/func_0x2000ba16.json', func_fileB = 'binary_ast/func_0x2000b7b8.json', path = "delta_ast"):
    funcA_ast = get_ast(func_fileA)
    funcB_ast = get_ast(func_fileB)

    root_nodeA, tree_size = get_rootnode(funcA_ast)
    if tree_size > 800:
        return
    root_nodeB, tree_size = get_rootnode(funcB_ast)
    if tree_size > 800:
        return
    distance, opts = simple_distance(root_nodeA, root_nodeB,CustomNode.get_children, CustomNode.get_label, return_operations=True)

    removes = []
    inserts = []
    updates = []

    changes = []
    edges = []
    ids = []
    instructions = []
    for opt in opts:
        s = OPERATIONS[opt.type]
        remove_string = ""
        insert_string = ""
        update_item = ()
        edge_string = ""
        id_string = ""
        bin_folder = ""
        
        if opt.arg1 is not None:
            s += f"\t id:{opt.arg1.my_id} label:{opt.arg1.my_label}"
            remove_string += f"{opt.arg1.my_id}"
            edge_string += f"{opt.arg1.edge}"
            id_string += f"{opt.arg1.my_id}"
            bin_folder = (bin_folderA,)

        if opt.arg2 is not None:
            s += f"\n\t id:{opt.arg2.my_id} label:{opt.arg2.my_label}"
            insert_string += f"{opt.arg2.my_id}"
            edge_string += f"{opt.arg2.edge}"
            id_string += f"{opt.arg2.my_id}"
            bin_folder = (bin_folderB,)

        
        if "update" in s: 
            remove_string = ""
            insert_string = ""
            edge_string = ""
            id_string = ""
            bin_folder = (bin_folderA,bin_folderB)
            update_item += (opt.arg1.my_id,opt.arg2.my_id)
            id_string += f"{opt.arg1.my_id}->{opt.arg2.my_id}"
            edge_string += f"{opt.arg1.edge}->{opt.arg2.edge}"

        if "match" not in s: 
            # print(s)
            changes.append(s)
            edges.append(edge_string)
            ids.append(id_string)

            # instructions.append(get_instruction_at_op(bin_folder, edge_string))
            

            if(remove_string):
                removes.append(remove_string)
            if(insert_string):
                inserts.append(insert_string)
            if(update_item):
                updates.append(update_item)
    
  
    # data = {"ID": ids, "Change":changes, "Instruction": instructions, "Edge": edges}
    data = {"ID": ids, "Change":changes, "Edge": edges}

    # changes_np = np.array(changes) #save instruction 
    df = pd.DataFrame(data)
    groups = get_groups(df, func_fileA, func_fileB)
    change_groups = []
    for id in ids:
        if id in groups:
            change_groups.append(groups[id])
        else:
            change_groups.append("None")

    df['Group'] = change_groups
    s2 = df.style.applymap(add_color)

    save_panda(s2,path)
    


    print("Removes")
    print(removes)
    print("Inserts")
    print(inserts) 
    print("Updates")
    print(updates)
    print("distance", distance)
    print("opts", len(opts))

# compare_ast()
# compare_ast('versions/otaApp-1_4_2_bin', 'versions/otaApp-1_4_4_bin',func_fileA = 'versions/otaApp-1_4_2_bin/0x2000ba98.json', func_fileB = 'versions/otaApp-1_4_4_bin/0x2000b824.json')

