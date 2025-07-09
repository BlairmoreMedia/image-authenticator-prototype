import streamlit as st
import hashlib
from datetime import datetime
import json
from PIL import Image, ExifTags
import numpy as np
import io
import os
import cv2
import re

st.set_page_config(page_title="Digital File Verifier", layout="centered")

st.title("Digital Media Authentication Protocol")
st.markdown("Secure your digital media files from reproduction, manipulation and guarantee your ownership with safe and secure authentication and verification. Select a file to authenticate and generate a cryptographic hash.")

tab1, tab2 = st.tabs(["🔐 Authenticate", "🔎 Verify"])

HASH_OPTIONS = {
    "File": "Creates a SHA-256 hash of the entire uploaded file, including any embedded metadata.",
    "Pixel Only": "Creates a SHA-256 hash of only the image's raw pixel data. Ignores file metadata and format."
}

GPS_TAGS = {
    0: "GPS Version ID",
    1: "GPS Latitude Ref",
    2: "GPS Latitude",
    3: "GPS Longitude Ref",
    4: "GPS Longitude",
    5: "GPS Altitude Ref",
    6: "GPS Altitude",
    16: "GPS Image Direction"
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
                metadata[tag_name] = value
    except Exception as e:
        metadata['error'] = str(e)
    return metadata

def get_video_metadata(file_path):
    cap = cv2.VideoCapture(file_path)
    duration = cap.get(cv2.CAP_PROP_FRAME_COUNT) / cap.get(cv2.CAP_PROP_FPS)
    cap.release()
    return {"Duration Seconds": round(duration, 2)}

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
        image = None

        if file_type.startswith("image"):
            image = Image.open(uploaded_file)
            uploaded_file.seek(0)
            st.image(uploaded_file, caption="Uploaded file preview", use_container_width=True)
            metadata = get_exif_metadata(image)
        elif file_type.startswith("video"):
            st.video(uploaded_file)
            temp_file_path = os.path.join(".", "temp_video")
            with open(temp_file_path, "wb") as f:
                f.write(uploaded_file.read())
            uploaded_file.seek(0)
            metadata = get_video_metadata(temp_file_path)
            os.remove(temp_file_path)

        if "cert_data" not in st.session_state:
            st.session_state.cert_data = None

        if st.button("Generate Hash"):
            if file_type.startswith("image") and hash_type == "Pixel Only" and image:
                hash_value = calculate_pixel_hash(image)
            else:
                hash_value = calculate_file_hash(uploaded_file)

            timestamp = datetime.utcnow().isoformat()

            st.session_state.cert_data = {
                "file_name": file_name,
                "hash_type": hash_type,
                "hash": hash_value,
                "timestamp": timestamp,
                "metadata": metadata
            }

        if st.session_state.cert_data:
            st.success("Hash generated successfully.")
            st.code(st.session_state.cert_data["hash"], language="text")
            json_bytes = create_certificate(st.session_state.cert_data)
            st.download_button(
                label="Download Authentication Certificate",
                data=json_bytes,
                file_name=f"certificate_{st.session_state.cert_data['file_name']}_{st.session_state.cert_data['timestamp'][:10].replace('-', '')}.json",
                mime="application/json"
            )

            if st.button("View Metadata"):
                st.subheader("Full Metadata Snapshot")
                for key, value in st.session_state.cert_data["metadata"].items():
                    display_key = re.sub(r'(?<!^)(?=[A-Z])', ' ', key).title()
                    if key == "GPSInfo" and isinstance(value, dict):
                        st.markdown(f"- **GPS Info:**")
                        for gps_tag_id, gps_value in value.items():
                            gps_key_name = GPS_TAGS.get(gps_tag_id, f"Unknown Tag {gps_tag_id}")
                            st.markdown(f"  - **{gps_key_name}**: {gps_value}")
                    else:
                        st.markdown(f"- **{display_key}**: {value}")

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
