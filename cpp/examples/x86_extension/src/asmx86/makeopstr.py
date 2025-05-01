import sys

if len(sys.argv) < 2:
	print "Usage: %s <header-file> [<output-file>]"
	sys.exit(1)

hdr = open(sys.argv[1], "r")

operation = False
operand = False

operation_list = []
operand_list = []

for line in hdr:
	if ("enum InstructionOperation" in line) and ("typedef" not in line):
		operation = True
	elif ("enum OperandType" in line) and ("typedef" not in line):
		operand = True
	elif "}" in line:
		operation = False
		operand = False
	elif (operation or operand) and ("{" not in line):
		parts = line.split("/")[0].split(",")
		for part in parts:
			text = part.split("=")[0].strip().lower()
			if len(text) == 0:
				continue
			if text in ["invalid", "none", "imm", "mem"]:
				text = ""
			if text.startswith("__x86_oper(reg_"):
				text = text[15:].split(")")[0].strip()
			if operation:
				operation_list.append(text)
			if operand:
				operand_list.append(text)

if len(sys.argv) > 2:
	out = open(sys.argv[2], "w")
else:
	out = sys.stdout

out.write("static const char* operationString[] = {\n")
for i in xrange(0, len(operation_list)):
	if i > 0:
		out.write(",\n")
	out.write('\t"%s"' % operation_list[i])
out.write("\n};\n")

out.write("static const char* operandString[] = {\n")
for i in xrange(0, len(operand_list)):
	if i > 0:
		out.write(",\n")
	out.write('\t"%s"' % operand_list[i])
out.write("\n};\n")
