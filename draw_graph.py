#!/usr/bin/env python

import pygraphviz

def draw_graph(data, filename):

    Graph = pygraphviz.AGraph(data, directed=True, strict=False)
    Graph.layout()
    Graph.draw(filename)

def create_graph():

    return pygraphviz.AGraph(directed=True, strict=False)
