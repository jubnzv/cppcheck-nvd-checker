#!/usr/bin/env python3
import sys
import os
import re
import html
from functools import reduce
from collections import OrderedDict
from dataclasses import dataclass
from typing import List, Dict, Optional


@dataclass
class SourceLineInfo:
    constraints: Dict[int, List[str]]
    exception: Optional[str] = None
    code: str = ""


def read_line_infos(src_path: str, report_path: str) -> Dict[int, SourceLineInfo]:
    if not os.path.exists(src_path):
        print(f'{src_path} is not available')
        return []
    if not os.path.exists(report_path):
        print(f'{report_path} is not available')
        return []

    constraint_re = re.compile(r'^([0-9]+):([0-9]+):(.*)$')
    exception_re = re.compile(r'^ExprEngineException tok.line:([0-9]+).*:(.*)$')
    line_infos: Dict[int, SourceLineInfo] = {}
    with open(report_path, 'r') as report_file:
        lines = report_file.read().split('\n')
        for i in range(0, len(lines)):
            # Searching for expressions
            m = constraint_re.search(lines[i])
            if not m or len(m.groups()) != 3:
                # Searching for ExprEngineException
                me = exception_re.search(lines[i])
                if me and len(me.groups()) == 2:
                    line = int(me.group(1))
                    exc = me.group(2)
                    if line_infos.get(line):
                        line_infos[line].exception = exc
                    else:
                        line_infos[line] = SourceLineInfo(exception=exc, constraints={})
                continue

            # Found expression
            line = int(m.group(1))
            col = int(m.group(2))
            desc = m.group(3)
            if line_infos.get(line):
                if line_infos[line].constraints.get(col):
                    line_infos[line].constraints[col].append(desc)
                else:
                    line_infos[line].constraints[col] = [desc]
            else:
                line_infos[line] = SourceLineInfo(constraints={col: [desc]})
        if not line_infos:
            print(f'{report_path}: no constraints found')
            return []

    with open(src_path, 'r') as src_file:
        lines = src_file.read().split('\n')
        for i in range(0, len(lines)):
            ln = i + 1
            if line_infos.get(ln):
                line_infos[ln].code = lines[i]
            else:
                line_infos[ln] = SourceLineInfo(code=lines[i], constraints=[])

    return line_infos


def print_html(line_infos: Dict[int, SourceLineInfo]):
    print('''<!DOCTYPE html><html>
<head>
</head>
<body>''')
    print('<table><tr><th>Line</th><th>Source</th></tr>')
    for line, info in OrderedDict(sorted(line_infos.items())).items():
        print(f'<tr><td><pre>L{line}</pre></td><td><pre>{html.escape(info.code)}</pre></td></tr>')
        if info.exception:
            print('<tr><td colspan=2 style="color: red;">')
            print(f'Exception: {info.exception}')
            print('</td></tr>')
        if info.constraints:
            print('<tr><td colspan=2><details>')
            print(f'<summary>Information</summary>')
            print('<table>')
            # print('<tr><th>Column</th><th>Expressions</th></tr>')
            for col, exprs in OrderedDict(sorted(info.constraints.items())).items():
                print(f'<tr><td><pre>{col}</pre></td><td><pre>')
                for e in exprs:
                    print(html.escape(e))
                print('<pre></td></tr>')
            print('</table>')
            print('</details></td></tr>')
    print('</table>')
    print('</body></html>')


if __name__ == '__main__':
    if len(sys.argv) != 3:
        print(f'Usage: {sys.argv[0]} <source> <cppcheck report>')
        sys.exit(1)
    line_infos = read_line_infos(sys.argv[1], sys.argv[2])
    print_html(line_infos)
