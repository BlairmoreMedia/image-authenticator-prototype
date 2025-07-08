import streamlit as st
import hashlib
import datetime
import json
from PIL import Image
from PIL.ExifTags import TAGS
import io
import cv2
import tempfile
import os
import numpy as np

# --- Functions ---
def extract_exif_metadata(image_bytes):
    metadata = {}
    try:
        img = Image.open(io.BytesIO(image_bytes))
        exif_data = img._getexif()
        if exif_data is not None:
            for tag_id, value in exif_data.items():
                tag = TAGS.get(tag_id, tag_id)
                metadata[tag] = value
    except Exception as e:
        metadata["error"] = f"Failed to extract EXIF: {str(e)}"
    return metadata

def extract_video_metadata(video_bytes):
    metadata = {}
    try:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".mp4") as tmp:
            tmp.write(video_bytes)
            tmp_path = tmp.name

        cap = cv2.VideoCapture(tmp_path)
        if cap.isOpened():
            frames = cap.get(cv2.CAP_PROP_FRAME_COUNT)
            fps = cap.get(cv2.CAP_PROP_FPS)
            duration = frames / fps if fps else 0
            metadata["frame_count"] = int(frames)
            metadata["fps"] = round(fps, 2)
            metadata["duration_seconds"] = round(duration, 2)
        cap.release()
        os.remove(tmp_path)
    except Exception as e:
        metadata["error"] = f"Failed to extract video metadata: {str(e)}"
    return metadata

def compute_sha256(data):
    return hashlib.sha256(data).hexdigest()

def hash_image_pixels(image_bytes):
    try:
        img = Image.open(io.BytesIO(image_bytes)).convert("RGB")
        pixel_array = np.array(img)
        pixel_bytes = pixel_array.tobytes()
        return hashlib.sha256(pixel_bytes).hexdigest()
    except Exception as e:
        return f"Error: {str(e)}"

# --- Streamlit App ---
st.title("🧪 Blockchain Media Authenticator Prototype")
tabs = st.tabs(["🔐 Authenticate File", "🔍 Verify File"])

# --- Tab 1: Authenticate ---
with tabs[0]:
    st.write("Upload an image or video to generate a SHA-256 hash and simulate recording to blockchain.")

    uploaded_file = st.file_uploader("Upload your file (image or video)", type=["jpg", "jpeg", "png", "tif", "bmp", "mp4", "mov", "avi", "mkv"], key="auth")

    if uploaded_file is not None:
        file_bytes = uploaded_file.read()
        st.subheader("📎 Uploaded Preview")
        if uploaded_file.type.startswith("image"):
            st.image(file_bytes, caption="Uploaded Image", use_container_width=True)
        elif uploaded_file.type.startswith("video"):
            st.video(file_bytes)

        # Hashing Mode
        st.subheader("⚙️ Hashing Mode")
        st.markdown("""
        - **File Hash**: A SHA-256 hash of the full digital file, including metadata. Sensitive to any file-level change.
        - **Pixel Hash**: A hash of only the visual content (pixel data). Ideal when visual integrity matters.
        """)

        hash_mode = st.radio("Choose hashing method:", ["File", "Pixel Only"])

        if hash_mode == "File":
            st.subheader("🔐 File Hash")
            hash_digest = compute_sha256(file_bytes)
            st.code(hash_digest)
        elif hash_mode == "Pixel Only":
            st.subheader("🧬 Pixel Hash (Visual Content Only)")
            pixel_hash = hash_image_pixels(file_bytes)
            st.code(pixel_hash)

        # Standard Metadata
        metadata = {
            "filename": uploaded_file.name,
            "timestamp": datetime.datetime.utcnow().isoformat() + "Z",
            "uploader": "Researcher123@UniversityX"
        }

        st.subheader("📄 Metadata Snapshot")
        st.json(metadata)

        extra_metadata = {}
        if uploaded_file.type.startswith("image"):
            extra_metadata = extract_exif_metadata(file_bytes)
            st.subheader("🧾 EXIF Metadata (from image)")
            st.json(extra_metadata)
        elif uploaded_file.type.startswith("video"):
            extra_metadata = extract_video_metadata(file_bytes)
            st.subheader("🎞️ Video Metadata")
            st.json(extra_metadata)

        blockchain_record = {
            "tx_id": "0x" + compute_sha256(file_bytes)[:8] + "...",
            "block_number": 12345678,
            "recorded_at": metadata["timestamp"]
        }

        st.subheader("⛓️ Blockchain Record (Simulated)")
        st.json(blockchain_record)

        st.success("✅ File hash recorded (simulated). A real app would now push this to Ethereum via a smart contract.")
    else:
        st.info("Please upload a file to begin.")

# --- Tab 2: Verify ---
with tabs[1]:
    st.write("Upload a file and paste a known reference hash to verify authenticity.")

    verify_file = st.file_uploader("Upload file to verify", type=["jpg", "jpeg", "png", "tif", "bmp", "mp4", "mov", "avi", "mkv"], key="verify")
    reference_hash = st.text_input("Enter reference SHA-256 hash")

    st.subheader("⚙️ Verification Mode")
    st.markdown("""
    - **File Hash**: Verifies against a hash of the original file. Detects any change to the file.
    - **Pixel Hash**: Compares visual content only. Useful when file is re-saved but pixels are unchanged.
    """)
    verify_mode = st.radio("Choose verification method:", ["File", "Pixel Only"])

    if verify_file is not None and reference_hash:
        verify_bytes = verify_file.read()

        if verify_mode == "File":
            verify_hash = compute_sha256(verify_bytes)
        elif verify_mode == "Pixel Only":
            verify_hash = hash_image_pixels(verify_bytes)

        st.subheader("🧪 Verification Result")
        if verify_hash == reference_hash.strip():
            st.success("✅ MATCH — File is authentic and unaltered.")
        else:
            st.error("❌ NO MATCH — The file does not match the provided hash.")

        st.subheader("🔎 Calculated Hash")
        st.code(verify_hash)
    elif verify_file or reference_hash:
        st.warning("Please upload a file AND enter a reference hash to verify.")
