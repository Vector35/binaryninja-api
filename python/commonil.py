# Copyright (c) 2019-2021 Vector 35 Inc
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

from dataclasses import dataclass


# This file contains a list of top level abstract classes for implementing BNIL instructions

@dataclass(frozen=True, repr=False)
class Constant:
	pass


@dataclass(frozen=True, repr=False)
class BinaryOperation:
	pass


@dataclass(frozen=True, repr=False)
class UnaryOperation:
	pass


@dataclass(frozen=True, repr=False)
class Comparison(BinaryOperation):
	pass


@dataclass(frozen=True, repr=False)
class SSA:
	pass


@dataclass(frozen=True, repr=False)
class Phi(SSA):
	pass


@dataclass(frozen=True, repr=False)
class FloatingPoint:
	pass


@dataclass(frozen=True, repr=False)
class ControlFlow:
	pass


@dataclass(frozen=True, repr=False)
class Terminal(ControlFlow):
	pass


@dataclass(frozen=True, repr=False)
class Loop(ControlFlow):
	pass


@dataclass(frozen=True, repr=False)
class Call(ControlFlow):
	pass


@dataclass(frozen=True, repr=False)
class Syscall(Call):
	pass


@dataclass(frozen=True, repr=False)
class Tailcall(Call):
	pass

@dataclass(frozen=True, repr=False)
class Return(Terminal):
	pass


@dataclass(frozen=True, repr=False)
class Signed:
	pass


@dataclass(frozen=True, repr=False)
class Arithmetic:
	pass


@dataclass(frozen=True, repr=False)
class Carry(Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class DoublePrecision(Arithmetic):
	pass


@dataclass(frozen=True, repr=False)
class Memory:
	pass


@dataclass(frozen=True, repr=False)
class Load:
	pass


@dataclass(frozen=True, repr=False)
class Store:
	pass


@dataclass(frozen=True, repr=False)
class RegisterStack:
	pass


@dataclass(frozen=True, repr=False)
class SetVar:
	pass


@dataclass(frozen=True, repr=False)
class StackOperation:
	pass


@dataclass(frozen=True, repr=False)
class SetReg:
	pass
