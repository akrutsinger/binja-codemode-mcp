"""
Code Mode MCP Server for Binary Ninja

An MCP server that enables LLM-assisted reverse engineering through code execution.
"""

import binaryninja

# Only load GUI components when running with UI
if binaryninja.core_ui_enabled():
    from .plugin import BinjaCodeModeMCP
    from .plugin.widget import init_status_indicator

    plugin_instance = BinjaCodeModeMCP()
    plugin_instance.register_commands()

    # Initialize the status indicator in the Binary Ninja status bar
    init_status_indicator(plugin_instance)
