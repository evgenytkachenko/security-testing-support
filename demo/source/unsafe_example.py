"""Fictional static-analysis fixture. NEVER import or execute this file."""
import subprocess

def unsafe_expression(user_text):
    return eval(user_text)

def unsafe_shell(user_command):
    return subprocess.run(user_command, shell=True)
