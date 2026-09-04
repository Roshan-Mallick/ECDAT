#!/bin/sh
# ECDAT: no-op stand-in for the tree-sitter CLI.
# tree-sitter-python's CMakeLists regenerates src/parser.c from grammar.json
# when the build tool is available. ECDAT pins a fixed grammar and ships the
# pre-generated parser.c, so regeneration is never needed; this no-op keeps
# the vendored build from trying to invoke a missing `tree-sitter` binary.
exit 0
