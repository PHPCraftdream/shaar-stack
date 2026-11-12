"""Evaluate Cargo target-dependency predicates against a fixed rustc cfg set."""

import json
import re

TOKEN = re.compile(r'\s*(?:(?P<ident>[A-Za-z_][A-Za-z0-9_]*)|(?P<text>"(?:[^"\\]|\\.)*")|(?P<punct>[(),=]))')
MAX_DEPTH = 64


class CfgError(ValueError):
    pass


def tokens(text):
    position, out = 0, []
    while True:
        while position < len(text) and text[position].isspace():
            position += 1
        if position == len(text):
            return out
        match = TOKEN.match(text, position)
        if not match:
            raise CfgError("unexpected character in cfg expression at offset %d" % position)
        kind = match.lastgroup
        value = match.group(kind)
        if kind == "text":
            try:
                value = json.loads(value)
            except ValueError as error:
                raise CfgError("invalid string literal in cfg expression") from error
        out.append((kind, value))
        position = match.end()


def parse(text):
    """Return a tree: ("all"|"any", [..]), ("not", node) or ("is", name, value-or-None)."""
    items = tokens(text)
    node, end = parse_node(items, 0, 0)
    if end != len(items):
        raise CfgError("trailing tokens in cfg expression")
    return node


def expect(items, index, punct):
    if index >= len(items) or items[index] != ("punct", punct):
        raise CfgError("expected %r in cfg expression" % punct)
    return index + 1


def parse_node(items, index, depth):
    if depth > MAX_DEPTH:
        raise CfgError("cfg expression nests too deeply")
    if index >= len(items) or items[index][0] != "ident":
        raise CfgError("expected a cfg predicate")
    name = items[index][1]
    index += 1
    if name in ("all", "any", "not") and index < len(items) and items[index] == ("punct", "("):
        index += 1
        children = []
        while index < len(items) and items[index] != ("punct", ")"):
            child, index = parse_node(items, index, depth + 1)
            children.append(child)
            if index < len(items) and items[index] == ("punct", ","):
                index += 1
            elif index < len(items) and items[index] != ("punct", ")"):
                raise CfgError("expected ',' or ')' in cfg expression")
        index = expect(items, index, ")")
        if name == "not":
            if len(children) != 1:
                raise CfgError("not() takes exactly one predicate")
            return ("not", children[0]), index
        return (name, children), index
    if index < len(items) and items[index] == ("punct", "="):
        if index + 1 >= len(items) or items[index + 1][0] != "text":
            raise CfgError("expected a quoted value after '='")
        return ("is", name, items[index + 1][1]), index + 2
    return ("is", name, None), index


def evaluate(node, cfgs):
    kind = node[0]
    if kind == "all":
        return all(evaluate(child, cfgs) for child in node[1])
    if kind == "any":
        return any(evaluate(child, cfgs) for child in node[1])
    if kind == "not":
        return not evaluate(node[1], cfgs)
    return (node[1], node[2]) in cfgs


def parse_rustc_cfg(lines):
    """Parse `rustc --print cfg` output into a frozenset of (name, value-or-None)."""
    out = set()
    for line in lines:
        line = line.strip()
        if not line:
            continue
        name, separator, value = line.partition("=")
        if separator:
            value = value.strip()
            if len(value) < 2 or value[0] != '"' or value[-1] != '"':
                raise CfgError("malformed rustc cfg line")
            out.add((name.strip(), json.loads(value)))
        else:
            out.add((name, None))
    return frozenset(out)


def matches(platform, triple, cfgs):
    """Whether a Cargo dependency `target` string applies to `triple` with the given cfg set."""
    if platform is None:
        return True
    text = platform.strip()
    if text.startswith("cfg(") and text.endswith(")"):
        return evaluate(parse(text[4:-1]), cfgs)
    return text == triple
