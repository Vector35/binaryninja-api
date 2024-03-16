# from binaryninja import *
import os
import webbrowser
import time
import sys
from pathlib import Path
from urllib.request import pathname2url

from binaryninja.interaction import get_save_filename_input, show_message_box, TextLineField, ChoiceField, SaveFileNameField, get_form_input
from binaryninja.settings import Settings
from binaryninja.enums import MessageBoxButtonSet, MessageBoxIcon, MessageBoxButtonResult, InstructionTextTokenType, BranchType, DisassemblyOption, FunctionGraphType, ThemeColor
from binaryninja.function import DisassemblySettings
from binaryninja.plugin import PluginCommand
from binaryninjaui import getThemeColor, getTokenColor, UIContext

colors = {
  'green': [162, 217, 175], 'red': [222, 143, 151], 'blue': [128, 198, 233], 'cyan': [142, 230, 237],
  'lightCyan': [176, 221, 228], 'orange': [237, 189, 129], 'yellow': [237, 223, 179], 'magenta': [218, 196, 209],
  'none': [74, 74, 74], 'disabled': [144, 144, 144]
}

escape_table = {"'": "&#39;", ">": "&#62;", "<": "&#60;", '"': "&#34;", ' ': "&#160;"}


def escape(toescape):
	# handle extended unicode
	toescape = toescape.encode('ascii', 'xmlcharrefreplace')
	# still escape the basics
	return ''.join(escape_table.get(chr(i), chr(i)) for i in toescape)


def save_svg(bv, function):
	sym = bv.get_symbol_at(function.start)
	if sym:
		offset = sym.name
	else:
		offset = "%x" % function.start
	path = Path(os.path.dirname(bv.file.filename))
	origname = os.path.basename(bv.file.filename)
	filename = path / f'binaryninja-{origname}-{offset}.html'

	functionChoice = TextLineField("Blank to accept default")
	# TODO: implement linear disassembly settings and output
	modeChoices = ["Graph"]
	modeChoiceField = ChoiceField("Mode", modeChoices)
	if Settings().get_bool('ui.debugMode'):
		formChoices = [
		  "Assembly", "Lifted IL", "LLIL", "LLIL SSA", "Mapped Medium", "Mapped Medium SSA", "MLIL", "MLIL SSA", "HLIL",
		  "HLIL SSA"
		]
		formChoiceField = ChoiceField("Form", formChoices)
	else:
		formChoices = ["Assembly", "LLIL", "MLIL", "HLIL"]
		formChoiceField = ChoiceField("Form", formChoices)

	showOpcodes = ChoiceField("Show Opcodes", ["Yes", "No"])
	showAddresses = ChoiceField("Show Addresses", ["Yes", "No"])

	saveFileChoices = SaveFileNameField("Output file", 'HTML files (*.html)', str(filename))
	if not get_form_input([
	  f'Current Function: {offset}', functionChoice, formChoiceField, modeChoiceField, showOpcodes, showAddresses,
	  saveFileChoices
	], "SVG Export") or saveFileChoices.result is None:
		return
	if saveFileChoices.result == '':
		outputfile = filename
	else:
		outputfile = saveFileChoices.result
	content = render_svg(
	  function, offset, modeChoices[modeChoiceField.result], formChoices[formChoiceField.result], showOpcodes.result == 0,
	  showAddresses.result == 0, origname
	)
	output = open(outputfile, 'w')
	output.write(content)
	output.close()
	result = show_message_box(
	  "Open SVG", "Would you like to view the exported SVG?", buttons=MessageBoxButtonSet.YesNoButtonSet,
	  icon=MessageBoxIcon.QuestionIcon
	)
	if result == MessageBoxButtonResult.YesButton:
		# might need more testing, latest py3 on windows seems.... broken with these APIs relative to other platforms
		if sys.platform == 'win32':
			webbrowser.open(outputfile)
		else:
			webbrowser.open('file://' + str(outputfile))


def instruction_data_flow(function, address):
	# TODO:  Extract data flow information
	length = function.view.get_instruction_length(address)
	func_bytes = function.view.read(address, length)
	hex = func_bytes.hex()
	padded = ' '.join([hex[i:i + 2] for i in range(0, len(hex), 2)])
	return f'Opcode: {padded}'

def rgbStr(tokenType):
	'''Given a token string name, look up the theme color for it and return as rbg(x,y,z) str'''
	try:
		color = eval(f'getThemeColor(ThemeColor.{tokenType})')
	except:
		color = None
	if (not color):
		try:
			ctx = UIContext.activeContext()
			view_frame = ctx.getCurrentViewFrame()
			color = eval(f'getTokenColor(view_frame, InstructionTextTokenType.{tokenType})')
		except:
			return 'rgb(224, 224, 224)'
	r = color.getRgb()[0]
	g = color.getRgb()[1]
	b = color.getRgb()[2]
	return f"rgb({r}, {g}, {b})"

def render_svg(function, offset, mode, form, showOpcodes, showAddresses, origname):
	settings = DisassemblySettings()
	if showOpcodes:
		settings.set_option(DisassemblyOption.ShowOpcode, True)
	if showAddresses:
		settings.set_option(DisassemblyOption.ShowAddress, True)
	if form == "LLIL":
		graph_type = FunctionGraphType.LowLevelILFunctionGraph
	elif form == "LLIL SSA":
		graph_type = FunctionGraphType.LowLevelILSSAFormFunctionGraph
	elif form == "Lifted IL":
		graph_type = FunctionGraphType.LiftedILFunctionGraph
	elif form == "Mapped Medium":
		graph_type = FunctionGraphType.MappedMediumLevelILFunctionGraph
	elif form == "Mapped Medium SSA":
		graph_type = FunctionGraphType.MappedMediumLevelILSSAFormFunctionGraph
	elif form == "MLIL":
		graph_type = FunctionGraphType.MediumLevelILFunctionGraph
	elif form == "MLIL SSA":
		graph_type = FunctionGraphType.MediumLevelILSSAFormFunctionGraph
	elif form == "HLIL":
		graph_type = FunctionGraphType.HighLevelILFunctionGraph
	elif form == "HLIL SSA":
		graph_type = FunctionGraphType.HighLevelILSSAFormFunctionGraph
	else:
		graph_type = FunctionGraphType.NormalFunctionGraph
	graph = function.create_graph(graph_type=graph_type, settings=settings)
	graph.layout_and_wait()
	heightconst = 15
	ratio = 0.48
	widthconst = heightconst * ratio

	output = f'''<html>
	<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="{graph.width * widthconst + 20}" height="{graph.height * heightconst + 20}">
		<style type="text/css">
			@import url(https://fonts.googleapis.com/css?family=Source+Code+Pro);
			body {{
				/* These colors are only for the bottom section, can tweak later */
				background-color: rgb(42, 42, 42);
				color: rgb(220, 220, 220);
				font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
			}}
				a, a:visited  {{
				color: rgb(200, 200, 200);
				font-weight: bold;
			}}
			svg {{
				background-color: {rgbStr('GraphBackgroundDarkColor')};
				display: block;
				margin: 0 auto;
			}}
			.basicblock {{
				stroke: {rgbStr('GraphNodeOutlineColor')};
				fill: {rgbStr('GraphNodeDarkColor')};
			}}
			.edge {{
				fill: none;
				stroke-width: 1px;
			}}
			.back_edge {{
				fill: none;
				stroke-width: 2px;
			}}
			.UnconditionalBranch, .IndirectBranch {{
				stroke: {rgbStr('UnconditionalBranchColor')};
				color: {rgbStr('UnconditionalBranchColor')};
			}}
			.FalseBranch {{
				stroke: {rgbStr('FalseBranchColor')};
				color: {rgbStr('FalseBranchColor')};
			}}
			.TrueBranch {{
				stroke: {rgbStr('TrueBranchColor')};
				color: {rgbStr('TrueBranchColor')};
			}}
			.arrow {{
				stroke-width: 1;
				fill: currentColor;
			}}
			text {{
								font-family: "Source Code Pro", "Lucida Console", "Consolas", monospace;
				font-size: 9pt;
				fill: {rgbStr('TextToken')};
			}}
			.InstructionToken {{
				fill: {rgbStr('InstructionColor')};
			}}
			.RegisterToken {{
				fill: {rgbStr('RegisterColor')};
			}}
			.CodeRelativeAddressToken, .PossibleAddressToken, .IntegerToken, .FloatingPointToken, .ArrayIndexToken {{
				fill: {rgbStr('NumberColor')};
			}}
			.CodeSymbolToken {{
				fill: {rgbStr('CodeSymbolColor')};
			}}
			.DataSymbolToken {{
				fill: {rgbStr('DataSymbolColor')};
			}}
			.LocalVariableToken, .ArgumentNameToken {{
				fill: {rgbStr('LocalVariableColor')};
			}}
			.StackVariableToken {{
				fill: {rgbStr('StackVariableColor')};
			}}
			.IndirectImportToken, .ImportToken, .ExternalSymbolToken {{
				fill: {rgbStr('ImportColor')};
			}}
			.AnnotationToken {{
				fill: {rgbStr('AnnotationColor')};
			}}
			.CommentToken {{
				fill: {rgbStr('CommentColor')};
			}}
			.AddressDisplayToken {{
				fill: {rgbStr('AddressColor')};
			}}
			.UnknownMemoryToken, .OpcodeToken {{
				fill: {rgbStr('OpcodeColor')};
			}}
			.StringToken, .CharacterConstantToken {{
				fill: {rgbStr('StringColor')};
			}}
			.TypeNameToken {{
				fill: {rgbStr('TypeNameColor')};
			}}
			.FieldNameToken, .StructOffsetToken {{
				fill: {rgbStr('FieldNameColor')};
			}}
			.KeywordToken, .EnumerationMemberToken {{
				fill: {rgbStr('KeywordColor')};
			}}
			.NamespaceToken {{
				fill: {rgbStr('NameSpaceColor')};
			}}
			.NamespaceSeparatorToken {{
				fill: {rgbStr('NameSpaceSeparatorColor')};
			}}
			.GotoLabelToken {{
				fill: {rgbStr('GotoLabelColor')};
			}}
			.OperationToken {{
				fill: {rgbStr('OperationColor')};
			}}
			.BaseStructureNameToken, .BaseStructureSeparatorToken {{
				fill: {rgbStr('BaseStructureNameColor')};
			}}
			.TextToken, .BeginMemoryOperandToken, .EndMemoryOperandToken {{
				fill: {rgbStr('TextToken')};
			}}
		</style>
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
		<g id="functiongraph0" class="functiongraph">
			<title>Function Graph 0</title>
	'''
	edges = ''
	for i, block in enumerate(graph):

		# Calculate basic block location and coordinates
		x = ((block.x) * widthconst)
		y = ((block.y) * heightconst)
		width = ((block.width) * widthconst)
		height = ((block.height) * heightconst)

		# Render block
		output += f'		<g id="basicblock{i}">\n'
		output += f'			<title>Basic Block {i}</title>\n'
		rgb = colors['none']
		try:
			bb = block.basic_block
			if hasattr(bb.highlight, 'color'):
				color_code = bb.highlight.color
				color_str = bb.highlight._standard_color_to_str(color_code)
				if color_str in colors:
					rgb = colors[color_str]
			else:
				rgb = [bb.highlight.red, bb.highlight.green, bb.highlight.blue]
		except:
			pass
		output += f'			<rect class="basicblock" x="{x}" y="{y}" height="{height + 12}" width="{width + 16}" fill="rgb({rgb[0]},{rgb[1]},{rgb[2]})"/>\n'

		# Render instructions, unfortunately tspans don't allow copying/pasting more
		# than one line at a time, need SVG 1.2 textarea tags for that it looks like

		output += f'			<text x="{x}" y="{y + (i+1) * heightconst}">\n'
		for i, line in enumerate(block.lines):
			output += f'				<tspan id="instr-{hex(line.address)[:-1]}" x="{x + 6}" y="{y + 6 + (i + 0.7) * heightconst}">'
			hover = instruction_data_flow(function, line.address)
			output += f'<title>{hover}</title>'
			for token in line.tokens:
				# TODO: add hover for hex, function, and reg tokens
				output += f'<tspan class="{InstructionTextTokenType(token.type).name}">{escape(token.text)}</tspan>'
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
			edgeType=BranchType(edge.type).name
			if edge.back_edge:
				edges += f'		<polyline class="back_edge {edgeType}" points="{points}" marker-end="url(#arrow-{edgeType})"/>\n'
			else:
				edges += f'		<polyline class="edge {edgeType}" points="{points}" marker-end="url(#arrow-{edgeType})"/>\n'
	output += ' ' + edges + '\n'
	output += '	</g>\n'
	output += '</svg>\n'

	timestring=time.strftime("%c")
	output += f'<p>This CFG generated by <a href="https://binary.ninja/">Binary Ninja</a> from {origname} on {timestring} showing {offset} as {form}.</p>'
	output += '</html>'
	return output


PluginCommand.register_for_function("Export to SVG", "Exports an SVG of the current function", save_svg)
