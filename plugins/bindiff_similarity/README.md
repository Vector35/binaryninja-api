# BinDiff Similarity Provider

This plugin uses Google BinDiff to compare the functions scheduled on connected similarity-session nodes. It exposes
bidirectional function matches, ports the matched function's symbol and type, and renders graph and linear diff views.

Each node is compared with its incoming neighbors, so the session graph controls which binaries are compared.
