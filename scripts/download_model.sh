#!/bin/bash
# Download the TinyLlama model for Telos Cognitive Verifier
# Model: TinyLlama-1.1B-Chat-v1.0 (Q4_K_M quantization, ~600MB)

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
MODEL_DIR="$PROJECT_ROOT/models"
MODEL_FILE="tinyllama-1.1b-chat-v1.0.Q4_K_M.gguf"
MODEL_URL="https://huggingface.co/TheBloke/TinyLlama-1.1B-Chat-v1.0-GGUF/resolve/main/${MODEL_FILE}"

mkdir -p "$MODEL_DIR"

if [ -f "$MODEL_DIR/$MODEL_FILE" ]; then
    echo "✓ Model already exists: $MODEL_DIR/$MODEL_FILE"
    exit 0
fi

echo "Downloading TinyLlama-1.1B (Q4_K_M)..."
echo "URL: $MODEL_URL"
echo "Destination: $MODEL_DIR/$MODEL_FILE"
echo ""

# Use -L to follow redirects (HuggingFace uses 302 redirects)
wget -L -O "$MODEL_DIR/$MODEL_FILE" "$MODEL_URL"

if [ $? -eq 0 ] && [ -s "$MODEL_DIR/$MODEL_FILE" ]; then
    echo ""
    echo "✓ Model downloaded successfully"
    echo "  Size: $(du -h "$MODEL_DIR/$MODEL_FILE" | cut -f1)"
    echo "  Restart Cortex to activate Cognitive Mode."
else
    rm -f "$MODEL_DIR/$MODEL_FILE"  # Clean up partial download
    echo "❌ Download failed. Try with curl instead:"
    echo "  mkdir -p $MODEL_DIR"
    echo "  curl -L -o $MODEL_DIR/$MODEL_FILE $MODEL_URL"
    exit 1
fi
