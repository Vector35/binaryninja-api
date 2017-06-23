# from binaryninja import *
import os
import webbrowser
import time
try:
	from urllib import pathname2url          # Python 2.x
except:
	from urllib.request import pathname2url  # Python 3.x

from binaryninja.interaction import get_save_filename_input, show_message_box
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult, InstructionTextTokenType, BranchType
from binaryninja.plugin import PluginCommand

colors = {'green': [162, 217, 175], 'red': [222, 143, 151], 'blue': [128, 198, 233], 'cyan': [142, 230, 237], 'lightCyan': [176, 221, 228], 'orange': [237, 189, 129], 'yellow': [237, 223, 179], 'magenta': [218, 196, 209], 'none': [74, 74, 74]}

escape_table = {
	"'": "&#39;",
	">": "&#62;",
	"<": "&#60;",
	'"': "&#34;",
	' ': "&#160;"
}


def escape(toescape):
	toescape = toescape.decode('utf-8').encode('ascii', 'xmlcharrefreplace')  # handle extended unicode
	return ''.join(escape_table.get(i, i) for i in toescape)                  # still escape the basics


def save_svg(bv, function):
	address = hex(function.start).replace('L', '')
	path = os.path.dirname(bv.file.filename)
	origname = os.path.basename(bv.file.filename)
	filename = os.path.join(path, 'binaryninja-{filename}-{function}.html'.format(filename=origname, function=address))
	outputfile = get_save_filename_input('File name for export_svg', 'HTML files (*.html)', filename)
	if outputfile is None:
		return
	content = render_svg(function, origname)
	output = open(outputfile, 'w')
	output.write(content)
	output.close()
	result = show_message_box("Open SVG", "Would you like to view the exported SVG?",
							buttons = MessageBoxButtonSet.YesNoButtonSet, icon = MessageBoxIcon.QuestionIcon)
	if result == MessageBoxButtonResult.YesButton:
		url = 'file:{}'.format(pathname2url(outputfile))
		webbrowser.open(url)


def instruction_data_flow(function, address):
	''' TODO:  Extract data flow information '''
	length = function.view.get_instruction_length(address)
	bytes = function.view.read(address, length)
	hex = bytes.encode('hex')
	padded = ' '.join([hex[i:i + 2] for i in range(0, len(hex), 2)])
	return 'Opcode: {bytes}'.format(bytes=padded)


def render_svg(function, origname):
	graph = function.create_graph()
	graph.layout_and_wait()
	heightconst = 15
	ratio = 0.48
	widthconst = heightconst * ratio

	output = '''<html>
	<head>
		<style type="text/css">
			@import url(https://fonts.googleapis.com/css?family=Source+Code+Pro);
			body {
				background-color: rgb(42, 42, 42);
                                color: rgb(220, 220, 220);
                                font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
			}
                        a, a:visited  {
                                color: rgb(200, 200, 200);
                                font-weight: bold;
                        }
			svg {
				background-color: rgb(42, 42, 42);
				display: block;
				margin: 0 auto;
			}
			.basicblock {
				stroke: rgb(224, 224, 224);
			}
			.edge {
				fill: none;
				stroke-width: 1px;
			}
			.back_edge {
				fill: none;
				stroke-width: 2px;
			}
			.UnconditionalBranch, .IndirectBranch {
				stroke: rgb(128, 198, 233);
				color: rgb(128, 198, 233);
			}
			.FalseBranch {
				stroke: rgb(222, 143, 151);
				color: rgb(222, 143, 151);
			}
			.TrueBranch {
				stroke: rgb(162, 217, 175);
				color: rgb(162, 217, 175);
			}
			.arrow {
				stroke-width: 1;
				fill: currentColor;
			}
			text {
                                font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
				font-size: 9pt;
				fill: rgb(224, 224, 224);
			}
			.CodeSymbolToken {
				fill: rgb(128, 198, 223);
			}
			.DataSymbolToken {
				fill: rgb(142, 230, 237);
			}
			.TextToken, .InstructionToken, .BeginMemoryOperandToken, .EndMemoryOperandToken {
				fill: rgb(224, 224, 224);
			}
			.PossibleAddressToken, .IntegerToken {
				fill: rgb(162, 217, 175);
			}
			.RegisterToken {
				fill: rgb(237, 223, 179);
			}
			.AnnotationToken {
				fill: rgb(218, 196, 209);
			}
			.ImportToken {
				fill: rgb(237, 189, 129);
			}
			.StackVariableToken {
				fill: rgb(193, 220, 199);
			}
		</style>
		<script src="https://ajax.googleapis.com/ajax/libs/jquery/1.12.2/jquery.min.js"></script>
	</head>
'''
	output += '''<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{width}" height="{height}">
		<defs>
			<marker id="arrow-TrueBranch" class="arrow TrueBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
			<marker id="arrow-FalseBranch" class="arrow FalseBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
			<marker id="arrow-UnconditionalBranch" class="arrow UnconditionalBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
			<marker id="arrow-IndirectBranch" class="arrow IndirectBranch" viewBox="0 0 10 10" refX="10" refY="5" markerUnits="strokeWidth" markerWidth="8" markerHeight="6" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
		</defs>
	'''.format(width=graph.width * widthconst + 20, height=graph.height * heightconst + 20)
	output += '''	<g id="functiongraph0" class="functiongraph">
			<title>Function Graph 0</title>
	'''
	edges = ''
	for i, block in enumerate(graph.blocks):

		# Calculate basic block location and coordinates
		x = ((block.x) * widthconst)
		y = ((block.y) * heightconst)
		width = ((block.width) * widthconst)
		height = ((block.height) * heightconst)

		# Render block
		output += '		<g id="basicblock{i}">\n'.format(i=i)
		output += '			<title>Basic Block {i}</title>\n'.format(i=i)
		rgb = colors['none']
		try:
			bb = block.basic_block
			color_code = bb.highlight.color
			color_str = bb.highlight._standard_color_to_str(color_code)
			if color_str in colors:
				rgb = colors[color_str]
		except:
			pass
		output += '			<rect class="basicblock" x="{x}" y="{y}" fill-opacity="0.4" height="{height}" width="{width}" fill="rgb({r},{g},{b})"/>\n'.format(x=x, y=y, width=width + 16, height=height + 12, r=rgb[0], g=rgb[1], b=rgb[2])

		# Render instructions, unfortunately tspans don't allow copying/pasting more
		# than one line at a time, need SVG 1.2 textarea tags for that it looks like

		output += '			<text x="{x}" y="{y}">\n'.format(x=x, y=y + (i + 1) * heightconst)
		for i, line in enumerate(block.lines):
			output += '				<tspan id="instr-{address}" x="{x}" y="{y}">'.format(x=x + 6, y=y + 6 + (i + 0.7) * heightconst, address=hex(line.address)[:-1])
			hover = instruction_data_flow(function, line.address)
			output += '<title>{hover}</title>'.format(hover=hover)
			for token in line.tokens:
				# TODO: add hover for hex, function, and reg tokens
				output += '<tspan class="{tokentype}">{text}</tspan>'.format(text=escape(token.text), tokentype=InstructionTextTokenType(token.type).name)
			output += '</tspan>\n'
		output += '			</text>\n'
		output += '		</g>\n'

		# Edges are rendered in a seperate chunk so they have priority over the
		# basic blocks or else they'd render below them

		for edge in block.outgoing_edges:
			points = ""
			x, y = edge.points[0]
			points += str(x * widthconst) + "," + str(y * heightconst + 12) + " "
			for x, y in edge.points[1:-1]:
				points += str(x * widthconst) + "," + str(y * heightconst) + " "
			x, y = edge.points[-1]
			points += str(x * widthconst) + "," + str(y * heightconst + 0) + " "
			if edge.back_edge:
				edges += '		<polyline class="back_edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(type=BranchType(edge.type).name, points=points)
			else:
				edges += '		<polyline class="edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(type=BranchType(edge.type).name, points=points)
	output += ' ' + edges + '\n'
	output += '	</g>\n'
	output += '</svg>'

        output += '<p>This CFG generated by <a href="https://binary.ninja/">Binary Ninja</a> from {filename} on {timestring}.</p>'.format(filename = origname, timestring = time.strftime("%c"))
        output += '</html>'
	return output


PluginCommand.register_for_function("Export to SVG", "Exports an SVG of the current function", save_svg)
