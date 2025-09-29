#!/bin/bash

echo "🔐 Please log in to npm first..."
npm login

echo "📦 Publishing Kali MCP Server to npm..."
npm publish --access public

echo "✅ Kali MCP Server published globally!"
echo ""
echo "🌍 Others can now install it with:"
echo "   npm install -g kali-mcp-server"
echo ""
echo "🔧 To use in any MCP configuration:"
echo '   "kali": {'
echo '     "command": "npx",'
echo '     "args": ["-y", "kali-mcp-server"]'
echo '   }'