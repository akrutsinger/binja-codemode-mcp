"""
Code Mode MCP Server for Binary Ninja

An MCP server that enables LLM-assisted reverse engineering through code execution.
"""

from .plugin import BinjaCodeModeMCP

plugin_instance = BinjaCodeModeMCP()
plugin_instance.register_commands()
