#!/bin/bash
# ida-headless-mcp server launcher
# Starts the MCP server in stdio mode

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Platform-appropriate default — override via env var
if [[ "$(uname)" == "Darwin" ]]; then
    export IDA_HEADLESS_MCP_IDA_DIR="${IDA_HEADLESS_MCP_IDA_DIR:-/Applications/IDA Professional 9.3.app/Contents/MacOS}"
elif [[ "$(uname)" == "Linux" ]]; then
    export IDA_HEADLESS_MCP_IDA_DIR="${IDA_HEADLESS_MCP_IDA_DIR:-/opt/ida-pro-9.0}"
else
    export IDA_HEADLESS_MCP_IDA_DIR="${IDA_HEADLESS_MCP_IDA_DIR:-/opt/ida-pro-9.0}"
fi
export IDA_HEADLESS_MCP_CACHE_DIR="${IDA_HEADLESS_MCP_CACHE_DIR:-$SCRIPT_DIR/cache}"
export IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA="${IDA_HEADLESS_MCP_MAX_CONCURRENT_IDA:-2}"
export IDA_HEADLESS_MCP_BINBIT_PATH="${IDA_HEADLESS_MCP_BINBIT_PATH:-$SCRIPT_DIR/tools/binbit}"

exec python -m ida_headless_mcp.server "$@"
