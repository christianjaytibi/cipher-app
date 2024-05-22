import streamlit as st
import os
import time
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding


st.set_page_config(
    page_title="Fernet",
    page_icon="💫",
)

if 'aes_btn_disabled' not in st.session_state:
    st.session_state.aes_btn_disabled = True

if 'aes_btn_tooltip' not in st.session_state:
    st.session_state.aes_btn_tooltip = ":red[Please fill in all required fields.]"


def main() -> None:
    st.markdown("### <span style=\"color:#00FFA3;\"> AES Block Cipher </span>",
                unsafe_allow_html=True)

    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander(
        "🪄 **Output**", expanded=True)

    with key_container:
        key_size = select_key_size()
        aes_key = generate_AES_key(key_size)

        gen_key_btn = st.button(":green[**Generate a new key**]", use_container_width=True,
                                help="This generates a new public and private key.")
        placeholder = st.empty()

        if gen_key_btn:
            with st.spinner("Wait for it..."):
                msg = st.toast("Cooking fresh AES key...", icon="🔥")
                time.sleep(1)
                generate_AES_key.clear()
                msg.toast("AES key served.", icon="🍜")
                placeholder.empty()

            with placeholder.container():
                key_download_btn(aes_key)

    with try_container:
        mode = select_mode()
        user_key = st.file_uploader(
            "📤 Upload key :red[*]", type=(".key"), help="Upload your key with file extension `\".key\"` here.")

        input_text = st.text_area(
            "Insert text below :red[*]", height=150, key="input_text", placeholder="Type some magic words.")

        input_fields = (user_key, input_text)
        if all(input_fields) and not st.session_state["input_text"] == "":
            st.session_state.aes_btn_disabled = False
            st.session_state.aes_btn_tooltip = None
        else:
            st.session_state.aes_btn_disabled = True
            st.session_state.aes_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button(
                f"✨ **GO!**",
                use_container_width=True,
                disabled=st.session_state.aes_btn_disabled,
                help=st.session_state.aes_btn_tooltip):
            try:
                user_key = user_key.getvalue()
                if mode == "Encrypt":
                    output = aes_encrypt_text(input_text, user_key)
                    output = output.hex()

                elif mode == "Decrypt":
                    output = aes_decrypt_text(input_text, user_key)
                    output = output.decode()

                output_container.markdown(
                    f"<span style=\"color:#00FFA3\"> {output} </span>", unsafe_allow_html=True)

            except Exception as e:
                st.error(
                    f'An error occured. {"Encryption" if mode == "Encrypt" else "Decryption"} failed.', icon="🚨")


@st.experimental_fragment
def key_download_btn(file_bytes: bytes) -> None:
    st.download_button(
        label="🔑 :orange[Download AES key]",
        data=file_bytes.hex(),
        file_name="aes.key",
        help="Download `aes.key`. Keep this some place safe!",
        use_container_width=True
    )


@st.experimental_fragment
def select_key_size() -> int:
    return st.selectbox(
        "Choose a key size", (128, 192, 256), index=0)


@st.cache_data
def generate_AES_key(key_size) -> bytes:
    return os.urandom(key_size // 8)


def select_mode() -> str:
    mode = st.selectbox(
        "MODE",
        ("Encrypt", "Decrypt"),
    )
    return mode


def aes_encrypt_text(text: str, key: bytes) -> bytes:
    # Generate a random 16-byte IV
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    encryptor = cipher.encryptor()

    # Pad the plain text
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(text.encode()) + padder.finalize()

    # Encrypt the padded data
    cipher_text = encryptor.update(padded_data) + encryptor.finalize()
    return iv + cipher_text


def aes_decrypt_text(ciphertext: str, key: bytes) -> bytes:
    ciphertext = bytes.fromhex(ciphertext)
    iv = ciphertext[:16]
    encrypted_data = ciphertext[16:]
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv),
                    backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypting the data
    padded_data = decryptor.update(encrypted_data) + decryptor.finalize()

    # Unpadding the data
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext


if __name__ == "__main__":
    main()
