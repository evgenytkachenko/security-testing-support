"""Negative fixture for the two narrow demo rules, not a security guarantee."""
import ast
import subprocess

def parse_literal(text):
    return ast.literal_eval(text)

def fixed_command():
    return subprocess.run(['printf', 'fixture'], shell=False)
