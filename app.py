import streamlit as st
import hashlib
import datetime
import json

# Title
st.title("🧪 Blockchain Image Authenticator Prototype")
st.write("Upload an image to generate a SHA-256 hash and simulate recording to blockchain.")

# Image upload
uploaded_file = st.file_uploader("Upload your image file", type=["jpg", "jpeg", "png", "tif", "bmp"])

if uploaded_file is not None:
    # Read image bytes
    image_bytes = uploaded_file.read()

    # Show image
    st.image(image_bytes, caption="Uploaded Image", use_column_width=True)

    # Compute SHA-256 hash
    hash_digest = hashlib.sha256(image_bytes).hexdigest()

    # Simulate metadata
    metadata = {
        "filename": uploaded_file.name,
        "hash": hash_digest,
        "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
        "uploader": "Researcher123@UniversityX"
    }

    # Display results
    st.subheader("🔐 Image Hash")
    st.code(hash_digest)

    st.subheader("📄 Metadata Snapshot")
    st.json(metadata)

    # Simulated blockchain record
    st.subheader("⛓️ Blockchain Record (Simulated)")
    blockchain_record = {
        "tx_id": "0x" + hash_digest[:8] + "...",
        "block_number": 12345678,
        "recorded_at": metadata["timestamp"],
        "image_hash": metadata["hash"]
    }
    st.json(blockchain_record)

    st.success("✅ Image hash recorded (simulated). A real app would now push this to Ethereum via a smart contract.")
else:
    st.info("Please upload an image file to begin.")