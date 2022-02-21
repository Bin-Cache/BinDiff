import dash
import dash_cytoscape as cyto
import dash_html_components as html
import dash_core_components as dcc
from dash.dependencies import Output, Input
import pandas as pd
import plotly.express as px
import math
from dash import Dash, dash_table
from collections import defaultdict
from itertools import groupby


import sys
import json
import os

from torch import classes


external_stylesheets = ['https://codepen.io/chriddyp/pen/bWLwgP.css']

app = dash.Dash(__name__, external_stylesheets=external_stylesheets)

styling = [

    {
        'selector': 'node',
        'style': {
            'label': 'data(label)'
        }
    },

    {
        'selector': '.updates',
        'style': {
            'background-color': 'orange'
        }
    },
    {
        'selector': '.removes',
        'style': {
            'background-color': 'red'
        }
    },
    {
        'selector': '.inserts',
        'style': {
            'background-color': 'blue'
        }
    },

]
      


def update_app(node_edge_listA, node_edge_listB, orphansA, orphansB, df):
    app.layout = html.Div([
        html.Div([
            cyto.Cytoscape(
                id='funcA',
                layout={'name': 'breadthfirst', 'roots': '[id = "root"]'},
                style={'width': '100%', 'height': '800px'},
                stylesheet=styling,
                elements=node_edge_listA
            )
        ], className='six columns'),

        html.Div([
            cyto.Cytoscape(
                id='funcB',
                layout={'name': 'breadthfirst', 'roots': '[id = "root"]'},
                style={'width': '100%', 'height': '800px'},
                stylesheet=styling,
                elements=node_edge_listB
            )
        ], className='six columns'),

        # dash_table.DataTable(df.to_dict('records'), [
        #                      {"name": i, "id": i} for i in df.columns])
        # html.Div([
        #     dcc.Graph(id='my-graph', figure=px.bar(df, x='name', y='slaves_freed'))
        # ], className='five columns'),

    ], className='row')


@app.callback(
    Output('empty-div', 'children'),
    Input('org-chart', 'mouseoverNodeData'),
    Input('org-chart', 'mouseoverEdgeData'),
    Input('org-chart', 'tapEdgeData'),
    Input('org-chart', 'tapNodeData'),
    Input('org-chart', 'selectedNodeData')
)
def update_layout(mouse_on_node, mouse_on_edge, tap_edge, tap_node, snd):
    print("Mouse on Node: {}".format(mouse_on_node))
    print("Mouse on Edge: {}".format(mouse_on_edge))
    print("Tapped Edge: {}".format(tap_edge))
    print("Tapped Node: {}".format(tap_node))
    print("------------------------------------------------------------")
    print("All selected Nodes: {}".format(snd))
    print("------------------------------------------------------------")

    return 'see print statement for nodes and edges selected.'


def get_ast(ast_file):
    return json.loads(
        open(ast_file, 'r').read())


def build_edge_node_list(ast, edge_list, changes):
    node_edge_list = []
    for node in ast["nodes"]:
        node_item = {'data': {
            'id': node["id"], 'label': node["Name"]}, 'classes': get_style_class(node, changes)}
        # print(node_item)
        # exit()
        node_edge_list.append(node_item)
    node_edge_list.append({'data': {'id': "root", 'label': "root"}, 'classes': None})

    for edge in edge_list:
        node_edge_list.append(
            {'data': {'source': edge[0], 'target': edge[1]}})

    return node_edge_list


def get_style_class(node, changes):
    updates, inserts, removes = changes
    if(node["id"] in updates):
        style_class = "updates"
    elif(node["id"] in inserts):
        style_class = "inserts"
    elif(node["id"] in removes):
        style_class = "removes"
    else:
        style_class = None

    return style_class


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

def get_changes(table):
    updates = []
    for id in table[table['Change'].str.contains('update')]['ID'].values.tolist():
        x = id.split("->")
        updates.append(x[0])
        updates.append(x[1])
    inserts = table[table['Change'].str.contains(
        'insert')]['ID'].values.tolist()
    removes = table[table['Change'].str.contains(
        'remove')]['ID'].values.tolist()

    return updates, inserts, removes


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

def get_adjacency_list(edges):
    edges = [(x["target"], x["source"]) for x in edges]
    return {k: [v[1] for v in g] for k, g in groupby(sorted(edges), lambda e: e[0])}


def get_node_edge_list(funcA_ast_file, changes):
    ast = get_ast(funcA_ast_file)

    adj = get_adjacency_list(ast['edges'])
    adj = remove_cycles(adj)
    orphans = get_orphans(adj)
    root_id = "root"
    adj[root_id] = orphans

    edge_list = []
    for a in adj:
        for b in adj[a]:
            edge_list.append((a,b))

    return build_edge_node_list(ast, edge_list, changes), orphans


def draw(funcA_ast_file, funcB_ast_file, result_table):
    tables = pd.read_html(
        'versions/otaApp-1_4_4_bin/0x2000ba98_to_0x2000b824_delta_ast.html')
    changes = get_changes(tables[0])
 
    node_edge_listA, orphansA = get_node_edge_list(funcA_ast_file, changes)
    node_edge_listB, orphansB = get_node_edge_list(funcB_ast_file, changes)


    update_app(node_edge_listA, node_edge_listB, orphansA, orphansB, tables[0])
    app.run_server(debug=False)


draw("versions/otaApp-1_4_2_bin/0x2000ba98.json",
     "versions/otaApp-1_4_4_bin/0x2000b824.json", "")
