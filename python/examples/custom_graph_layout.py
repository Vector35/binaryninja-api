#!/usr/bin/env python3
# Copyright (c) 2015-2024 Vector 35 Inc
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to
# deal in the Software without restriction, including without limitation the
# rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
# sell copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
# FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.

import random

from binaryninja import FlowGraph, FlowGraphLayout, FlowGraphNode


class RandomLayout(FlowGraphLayout):
    def layout(self, graph: FlowGraph, nodes: list[FlowGraphNode]):
        min_x = 0
        max_x = 0
        min_y = 0
        max_y = 0

        max_extent = len(nodes) * 50

        # Place nodes
        for node in nodes:
            x = random.randint(0, max_extent)
            y = random.randint(0, max_extent)

            min_x = min(x, min_x)
            max_x = max(x + node.width, max_x)

            min_y = min(y, min_y)
            max_y = max(y + node.height, max_y)

            node.x = x
            node.y = y

        # Place edges
        for node in nodes:
            for edge_num,edge in enumerate(node.outgoing_edges):
                points = [
                    (node.x + node.width/2, node.y + node.height),
                    (edge.target.x + edge.target.width/2, edge.target.y + edge.target.height)
                ]
                node.set_outgoing_edge_points(edge_num, points)

        # Calculate graph size and node visibility
        for node in nodes:
            min_node_x = node.x
            max_node_x = node.x + node.width

            min_node_y = node.y
            max_node_y = node.y + node.height
            for edge in node.outgoing_edges:
                for point in edge.points:
                    px, py = point
                    min_x = min(min_x, px)
                    min_y = min(min_y, py)

                    max_x = max(max_x, px + 1)
                    max_y = max(max_y, py + 1)

                    min_node_x = min(min_node_x, px)
                    max_node_x = max(max_node_x, px+1)

                    min_node_y = min(min_node_y, py)
                    max_node_y = max(max_node_y, py+1)

            node.set_visibility_region(int(min_node_x), int(min_node_y), int(max_node_x - min_node_x), int(max_node_y - min_node_y))

        graph.width = int(max_x - min_x) + graph.horizontal_block_margin*2
        graph.height = int(max_y - min_y) + graph.vertical_block_margin*2

        return True

layout = RandomLayout()
layout.register("Random Layout")
