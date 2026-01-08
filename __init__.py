"""
Code Mode MCP Server for Binary Ninja

An MCP server that enables LLM-assisted reverse engineering through code execution.
"""

from .plugin import BinjaCodeModeMCP
from .plugin.widget import init_status_indicator

plugin_instance = BinjaCodeModeMCP()
plugin_instance.register_commands()

# Initialize the status indicator in the Binary Ninja status bar
init_status_indicator(plugin_instance)
