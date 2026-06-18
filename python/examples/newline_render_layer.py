from typing import List

import binaryninja
from binaryninja import RenderLayer, InstructionTextToken, \
    InstructionTextTokenType, DisassemblyTextLine, log_info


"""
Render Layer that splits string literals containing newline characters into multiple lines.

Before:
    char* s = "Hi, guys!\nWe all love Binja!";

After:
    char* s = "Hi, guys!\n"
              "We all love Binja!";
"""


class NewlineSplitRenderLayer(RenderLayer):
    name = "Split Strings at Newlines"

    def split_string_token(self, token: InstructionTextToken) -> List[InstructionTextToken]:
        """
        Split a string token containing \n into multiple tokens.
        Returns a list of tokens representing the split string.
        """
        text = token.text
        log_info(f"[NewlineSplitRenderLayer] Examining token: type={token.type}, text={repr(text)}")

        # Check if this token contains \n (the token text doesn't include quotes)
        if '\\n' not in text:
            return [token]

        log_info(f"[NewlineSplitRenderLayer] Found string with \\n: {repr(text)}")

        # The text is the string content (no quotes in token.text)
        content = text

        # Split by \n but keep the \n with the preceding part
        parts = []
        current_part = ""
        i = 0
        while i < len(content):
            if i < len(content) - 1 and content[i] == '\\' and content[i+1] == 'n':
                current_part += '\\n'
                parts.append(current_part)
                current_part = ""
                i += 2
            else:
                current_part += content[i]
                i += 1

        # Add any remaining content
        if current_part:
            parts.append(current_part)

        # If we only have one part, return the original token
        if len(parts) <= 1:
            return [token]

        log_info(f"[NewlineSplitRenderLayer] Splitting into {len(parts)} parts: {parts}")

        # Create tokens for each part (token.text doesn't include quotes, so don't add them)
        result = []
        for i, part in enumerate(parts):
            result.append(InstructionTextToken(token.type, part, token.value, token.size, token.operand, token.context, token.address, token.confidence))

        return result

    def apply_to_block(
            self,
            block: 'binaryninja.BasicBlock',
            lines: List['binaryninja.DisassemblyTextLine']
    ):
        log_info(f"[NewlineSplitRenderLayer] apply_to_block called with {len(lines)} lines")
        new_lines = []

        for line in lines:
            # Look for string tokens
            has_split = False
            split_info = None

            for i, token in enumerate(line.tokens):
                if token.type == InstructionTextTokenType.StringToken:
                    log_info(f"[NewlineSplitRenderLayer] Found StringToken at index {i}")
                    split_tokens = self.split_string_token(token)
                    if len(split_tokens) > 1:
                        has_split = True
                        split_info = (i, split_tokens)
                        log_info(f"[NewlineSplitRenderLayer] Will split this line into {len(split_tokens)} parts")
                        break

            if not has_split:
                new_lines.append(line)
                continue

            # Create multiple lines for the split string
            token_idx, split_tokens = split_info

            # Find the indentation level by looking at the position of the string token
            indent_count = 0
            for i in range(token_idx):
                if line.tokens[i].type == InstructionTextTokenType.TextToken:
                    indent_count += len(line.tokens[i].text)
                else:
                    indent_count += len(line.tokens[i].text)

            # Create first line with original tokens up to and including first split token
            first_line = DisassemblyTextLine()
            first_line.address = line.address
            first_line.il_instruction = line.il_instruction
            first_line.highlight = line.highlight

            first_line.tokens = line.tokens[:token_idx] + [split_tokens[0]]
            new_lines.append(first_line)

            # Create continuation lines for remaining split tokens
            for j in range(1, len(split_tokens)):
                cont_line = DisassemblyTextLine()
                cont_line.address = line.address
                cont_line.il_instruction = line.il_instruction
                cont_line.highlight = line.highlight

                # Add indentation to align with the start of the string
                indent_token = InstructionTextToken(InstructionTextTokenType.TextToken, ' ' * indent_count)
                cont_line.tokens = [indent_token, split_tokens[j]]

                # If this is the last split token, add the rest of the original tokens
                if j == len(split_tokens) - 1:
                    cont_line.tokens.extend(line.tokens[token_idx + 1:])

                new_lines.append(cont_line)

        return new_lines

    def apply_to_high_level_il_body(
            self,
            function: 'binaryninja.Function',
            lines: List['binaryninja.LinearDisassemblyLine']
    ):
        log_info(f"[NewlineSplitRenderLayer] apply_to_high_level_il_body called with {len(lines)} lines")
        # Similar logic for HLIL linear view
        new_lines = []

        for line in lines:
            # Look for string tokens
            has_split = False
            split_info = None

            for i, token in enumerate(line.contents.tokens):
                if token.type == InstructionTextTokenType.StringToken:
                    split_tokens = self.split_string_token(token)
                    if len(split_tokens) > 1:
                        has_split = True
                        split_info = (i, split_tokens)
                        break

            if not has_split:
                new_lines.append(line)
                continue

            # Create multiple lines for the split string
            token_idx, split_tokens = split_info

            # Find the indentation level
            indent_count = 0
            for i in range(token_idx):
                indent_count += len(line.contents.tokens[i].text)

            # Create first line - we need to create a new DisassemblyTextLine with modified tokens
            first_tokens = line.contents.tokens[:token_idx] + [split_tokens[0]]
            first_contents = DisassemblyTextLine(first_tokens, line.contents.address)
            first_contents.highlight = line.contents.highlight
            first_contents.il_instruction = line.contents.il_instruction

            first_line = binaryninja.LinearDisassemblyLine(
                line.type,
                line.function,
                line.block,
                first_contents,
                line.view
            )
            new_lines.append(first_line)

            # Create continuation lines
            for j in range(1, len(split_tokens)):
                # Add indentation
                indent_token = InstructionTextToken(InstructionTextTokenType.TextToken, ' ' * indent_count)
                cont_tokens = [indent_token, split_tokens[j]]

                # If this is the last split token, add the rest of the original tokens
                if j == len(split_tokens) - 1:
                    cont_tokens.extend(line.contents.tokens[token_idx + 1:])

                cont_contents = DisassemblyTextLine(cont_tokens, line.contents.address)
                cont_contents.highlight = line.contents.highlight
                cont_contents.il_instruction = line.contents.il_instruction

                cont_line = binaryninja.LinearDisassemblyLine(
                    line.type,
                    line.function,
                    line.block,
                    cont_contents,
                    line.view
                )

                new_lines.append(cont_line)

        return new_lines

    def apply_to_flow_graph(self, graph: 'binaryninja.FlowGraph'):
        log_info(f"[NewlineSplitRenderLayer] apply_to_flow_graph called with {len(graph.nodes)} nodes")
        for node in graph.nodes:
            lines = node.lines
            new_lines = []

            for line in lines:
                # Look for string tokens
                has_split = False
                split_info = None

                for i, token in enumerate(line.tokens):
                    if token.type == InstructionTextTokenType.StringToken:
                        log_info(f"[NewlineSplitRenderLayer] Found StringToken in flow graph node")
                        split_tokens = self.split_string_token(token)
                        if len(split_tokens) > 1:
                            has_split = True
                            split_info = (i, split_tokens)
                            log_info(f"[NewlineSplitRenderLayer] Will split this line in flow graph into {len(split_tokens)} parts")
                            break

                if not has_split:
                    new_lines.append(line)
                    continue

                # Create multiple lines for the split string
                token_idx, split_tokens = split_info

                # Find the indentation level by looking at the position of the string token
                indent_count = 0
                for i in range(token_idx):
                    indent_count += len(line.tokens[i].text)

                # Create first line with original tokens up to and including first split token
                first_tokens = line.tokens[:token_idx] + [split_tokens[0]]
                first_line = DisassemblyTextLine(first_tokens, line.address)
                first_line.highlight = line.highlight
                first_line.il_instruction = line.il_instruction
                new_lines.append(first_line)

                # Create continuation lines for remaining split tokens
                for j in range(1, len(split_tokens)):
                    # Add indentation to align with the start of the string
                    indent_token = InstructionTextToken(InstructionTextTokenType.TextToken, ' ' * indent_count)
                    cont_tokens = [indent_token, split_tokens[j]]

                    # If this is the last split token, add the rest of the original tokens
                    if j == len(split_tokens) - 1:
                        cont_tokens.extend(line.tokens[token_idx + 1:])

                    cont_line = DisassemblyTextLine(cont_tokens, line.address)
                    cont_line.highlight = line.highlight
                    cont_line.il_instruction = line.il_instruction
                    new_lines.append(cont_line)

            # Update the node's lines
            node.lines = new_lines


NewlineSplitRenderLayer.register()
