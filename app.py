import streamlit as st
import hashlib
from datetime import datetime
import json
from PIL import Image, ExifTags
import numpy as np
import io
import os
import cv2

st.set_page_config(page_title="Digital File Verifier", layout="centered")

st.title("🧪 Digital File Authentication Prototype")
st.markdown("Select a file to authenticate and generate a cryptographic hash.")

tab1, tab2 = st.tabs(["🔐 Authenticate", "🔎 Verify"])

HASH_OPTIONS = {
    "File": "Creates a SHA-256 hash of the entire uploaded file, including any embedded metadata.",
    "Pixel Only": "Creates a SHA-256 hash of only the image's raw pixel data. Ignores file metadata and format."
}

def calculate_file_hash(uploaded_file):
    file_bytes = uploaded_file.read()
    uploaded_file.seek(0)
    return hashlib.sha256(file_bytes).hexdigest()

def calculate_pixel_hash(image):
    if image.mode != "RGB":
        image = image.convert("RGB")
    pixel_array = np.array(image)
    pixel_bytes = pixel_array.tobytes()
    return hashlib.sha256(pixel_bytes).hexdigest()

def get_exif_metadata(image):
    metadata = {}
    try:
        exif_data = image._getexif()
        if exif_data:
            for tag, value in exif_data.items():
                tag_name = ExifTags.TAGS.get(tag, tag)
                if isinstance(value, bytes):
                    metadata[tag_name] = str(value)
                else:
                    metadata[tag_name] = value
    except Exception as e:
        metadata['error'] = str(e)
    return metadata

def get_video_metadata(file_path):
    cap = cv2.VideoCapture(file_path)
    duration = cap.get(cv2.CAP_PROP_FRAME_COUNT) / cap.get(cv2.CAP_PROP_FPS)
    cap.release()
    return {"duration_seconds": round(duration, 2)}

def create_certificate(data_dict):
    def clean(val):
        if isinstance(val, bytes):
            return str(val)
        elif isinstance(val, (int, float, str)):
            return val
        elif isinstance(val, dict):
            return {k: clean(v) for k, v in val.items()}
        elif isinstance(val, (list, tuple)):
            return [clean(v) for v in val]
        else:
            return str(val)
    cleaned = {k: clean(v) for k, v in data_dict.items()}
    json_bytes = json.dumps(cleaned, indent=2).encode('utf-8')
    return json_bytes

with tab1:
    uploaded_file = st.file_uploader("Upload an image or video file", type=["jpg", "jpeg", "png", "mp4", "mov"])
    hash_type = st.radio("Select hash method", list(HASH_OPTIONS.keys()))
    st.caption(HASH_OPTIONS[hash_type])

    if uploaded_file:
        file_name = uploaded_file.name
        file_type = uploaded_file.type

        metadata = {}
        if file_type.startswith("image"):
            image = Image.open(uploaded_file)
            uploaded_file.seek(0)
            st.image(uploaded_file, caption="Uploaded file preview", use_container_width=True)
            metadata = get_exif_metadata(image)
        else:
            st.video(uploaded_file)
            temp_file_path = os.path.join(".", "temp_video")
            with open(temp_file_path, "wb") as f:
                f.write(uploaded_file.read())
            uploaded_file.seek(0)
            metadata = get_video_metadata(temp_file_path)
            os.remove(temp_file_path)

        st.subheader("📄 Full Metadata Snapshot")
        st.json(metadata)

        if st.button("Generate Hash"):
            if file_type.startswith("image"):
                if hash_type == "Pixel Only":
                    hash_value = calculate_pixel_hash(image)
                else:
                    hash_value = calculate_file_hash(uploaded_file)
            else:
                hash_value = calculate_file_hash(uploaded_file)

            timestamp = datetime.utcnow().isoformat()
            st.success("Hash generated successfully.")
            st.code(hash_value, language="text")

            cert_data = {
                "file_name": file_name,
                "hash_type": hash_type,
                "hash": hash_value,
                "timestamp": timestamp,
                "metadata": metadata
            }

            json_bytes = create_certificate(cert_data)

            st.download_button(
                label="📄 Download Certificate (JSON)",
                data=json_bytes,
                file_name=f"certificate_{file_name}_{timestamp[:10].replace('-', '')}.json",
                mime="application/json"
            )

with tab2:
    st.write("To verify a file, upload it and compare its hash to the original.")
    uploaded_verification_file = st.file_uploader("Upload file to verify", key="verify")
    verify_hash_type = st.radio("Hash method used during original authentication", list(HASH_OPTIONS.keys()), key="verify_type")
    st.caption(HASH_OPTIONS[verify_hash_type])
    expected_hash = st.text_input("Enter original hash value")

    if uploaded_verification_file and expected_hash:
        if st.button("Verify File"):
            if uploaded_verification_file.type.startswith("image"):
                image = Image.open(uploaded_verification_file)
                result_hash = (
                    calculate_pixel_hash(image)
                    if verify_hash_type == "Pixel Only"
                    else calculate_file_hash(uploaded_verification_file)
                )
            else:
                result_hash = calculate_file_hash(uploaded_verification_file)

            if result_hash == expected_hash.strip():
                st.success("✅ Match! The file is authentic.")
            else:
                st.error("❌ No match. This file does not match the original hash.")
