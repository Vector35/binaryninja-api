from binaryninja import *
import os

def save_svg(bv,function):
	filename = bv.file.filename.split(os.sep)[-1]
	outputfile = os.environ['HOME'] + os.sep + 'binaryninja-{filename}-{function}.svg'.format(filename=filename,function=function.symbol.name)
	try:
		output = open(outputfile,'w')
		output.write(render_svg(function))
		output.close()
	except:
	    print "Unexpected error:", sys.exc_info()[0]
    	raise

def render_svg(function):
	graph = function.create_graph()
	graph.layout_and_wait()
	heightconst = 15
	ratio = 0.54
	widthconst = int(heightconst*ratio)

	output = '''<?xml version="1.0" standalone="no"?>
	<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">
	<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1" width="{width}" height="{height}" viewBox="0 0 {width} {height}">
		<defs>
			<style type="text/css"><![CDATA[
				@import url(https://fonts.googleapis.com/css?family=Source+Code+Pro);
				.edge {{
					fill: none;
					stroke-width: 3
				}}
				.UnconditionalBranch {{
					stroke: blue;
					color: blue;
				}}
				.FalseBranch {{
					stroke: red;
					color: red;
				}}
				.TrueBranch {{
					stroke: green;
					color: green;
				}}
				.arrow {{
					stroke-width: 3;
					fill: currentColor;
				}}
				text {{
					font-family: 'Source Code Pro';
					font-size: 9pt;
				}}
			]]></style>
			<marker id="arrow-TrueBranch" class="arrow TrueBranch" viewBox="0 0 10 10" refX="11" refY="5" markerUnits="strokeWidth" markerWidth="4" markerHeight="3" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
			<marker id="arrow-FalseBranch" class="arrow FalseBranch" viewBox="0 0 10 10" refX="11" refY="5" markerUnits="strokeWidth" markerWidth="4" markerHeight="3" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
			<marker id="arrow-UnconditionalBranch" class="arrow UnconditionalBranch" viewBox="0 0 10 10" refX="11" refY="5" markerUnits="strokeWidth" markerWidth="4" markerHeight="3" orient="auto">
				<path d="M 0 0 L 10 5 L 0 10 z" />
			</marker>
		</defs>
	'''.format(width=graph.width*widthconst, height=graph.height*heightconst)
	output += '''	<g id="functiongraph0" class="functiongraph">
			<title>Function Graph 0</title>
	'''
	edges = ''
	for i,block in enumerate(graph.blocks):

		#Calculate basic block location and coordinates
		x = int((block.x) * widthconst)
		y = int((block.y) * heightconst)
		width = int((block.width) * widthconst)
		height = int((block.height) * heightconst)

		#Render block
		output += '		<g id="basicblock{i}" class="basicblock">\n'
		output += '			<title>Basic Block {i}</title>\n'
		output += '			<rect style="fill:grey;stroke:black;" x="{x}" y="{y}" height="{height}" width="{width}"/>\n'.format(i=i,x=x,y=y,width=width,height=height)

		#Render instructions, unfortunately tspans don't allow copying/pasting more
		#than one line at a time, need SVG 1.2 textarea tags for that it looks like

		output += '			<text x="{x}" y="{y}">\n'.format(x=x,y=y + (i + 1) * heightconst)
		for i,line in enumerate(block.lines):
			output += '				<tspan id="{address}" x="{x}" y="{y}">'.format(x=x,y=y + (i + 0.7) * heightconst,address=hex(line.address)[:-1])
			for token in line.tokens:
				output+='<tspan class="{tokentype}">{text}</tspan>'.format(text=token.text,tokentype=token.type)
			output += '				</tspan>\n'
		output += '			</text>\n'
		output += '		</g>\n'

		#Edges are rendered in a seperate chunk so they have priority over the
		#basic blocks or else they'd render below them

		for edge in block.outgoing_edges:
			points = ""
			for x,y in edge.points:
				points += str(x*widthconst)+","+str(y*heightconst) + " "
			edges += '		<polyline class="edge {type}" points="{points}" marker-end="url(#arrow-{type})"/>\n'.format(type=edge.type,points=points)
	output += ' ' + edges + '\n'
	output += '	</g>\n'
	output += '</svg>'
	return output

PluginCommand.register_for_function("Export to SVG", "Exports an SVG to your home folder for the given function", save_svg)
