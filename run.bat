@echo off
REM ida-headless-mcp server launcher
REM Starts the MCP server in stdio mode for Claude Desktop / Oh My Pi / Cursor

set IDA_HEADLESS_MCP_IDA_DIR=C:\Program Files\IDA Professional 9.0
set IDA_HEADLESS_MCP_CACHE_DIR=%~dp0cache
set IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA=2
set IDA_HEADLESS_MCP_BINBIT_PATH=%~dp0tools\binbit.exe

python -m ida_headless_mcp.server %*
