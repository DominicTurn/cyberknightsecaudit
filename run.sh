#!/bin/bash
#
# Project: Cyber Knight Sec - Scout
# Compiles all sources in src/ into bin/ and runs the app.

set -e

SRC_DIR="src"
BUILD_DIR="bin"

mkdir -p "$BUILD_DIR"

echo "Compiling..."
javac -d "$BUILD_DIR" "$SRC_DIR"/*.java

echo "Running Scout..."
java -cp "$BUILD_DIR" App
