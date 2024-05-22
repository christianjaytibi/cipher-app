import rsa.pkcs1
import streamlit as st
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
import time
import zipfile
from io import BytesIO
from typing_extensions import Literal


st.set_page_config(
    page_title="RSA",
    page_icon="💫",
)

if 'rsa_btn_disabled' not in st.session_state:
    st.session_state.rsa_btn_disabled = True

if 'rsa_btn_tooltip' not in st.session_state:
    st.session_state.rsa_btn_tooltip = ":red[Please fill in all required fields.]"


def main() -> None:
    st.markdown("### <span style=\"color:#00FFA3;\"> RSA </span>",
                unsafe_allow_html=True)

    key_container = st.expander("Key pair generation", expanded=True)
    try_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander(
        "🪄 **Output**", expanded=True)

    with key_container:
        key_size = select_key_size()
        pubkey, privkey = generate_key_pair(key_size)

        gen_key_btn = st.button(":green[**Generate a new key pair**]", use_container_width=True,
                                help="This generates a new public and private key.")
        placeholder = st.empty()

        if gen_key_btn:
            with st.spinner("Wait for it..."):
                msg = st.toast("Cooking fresh key pair...", icon="🔥")
                time.sleep(1)
                generate_key_pair.clear()
                msg.toast("Key pair served.", icon="🍜")
                placeholder.empty()

                with placeholder.container():
                    key_pair_download_btn(pubkey, privkey)

    with try_container:
        mode = select_mode()
        key = upload_key(mode=mode)

        input_text = st.text_area(
            "Insert text below :red[*]", height=150, key="input_text", placeholder="Type some magic words.")

        input_fields = (key, input_text)
        if all(input_fields) and not st.session_state["input_text"] == "":
            st.session_state.rsa_btn_disabled = False
            st.session_state.rsa_btn_tooltip = None
        else:
            st.session_state.rsa_btn_disabled = True
            st.session_state.rsa_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button(
                f"✨ **GO!**",
                use_container_width=True,
                disabled=st.session_state.rsa_btn_disabled,
                help=st.session_state.rsa_btn_tooltip):
            try:
                key = key.getvalue()
                if mode == "Encrypt":
                    key = load_key(key, "public")
                    output = rsa_encrypt_text(input_text, key)
                    output = output.hex()

                elif mode == "Decrypt":
                    key = load_key(key, "private")
                    output = rsa_decrypt_text(input_text, key)
                    output = output.decode()

                output_container.markdown(
                    f"<span style=\"color:#00FFA3\"> {output} </span>", unsafe_allow_html=True)

            except Exception:
                st.error(
                    f'An error occured. {"Encryption" if mode == "Encrypt" else "Decryption"} failed.', icon="🚨")


@st.experimental_fragment
def key_pair_download_btn(pubkey_bytes: bytes, privkey_bytes: bytes) -> None:
    pubkey_buffer = BytesIO(pubkey_bytes)
    privkey_buffer = BytesIO(privkey_bytes)

    zip_buffer = BytesIO()
    with zipfile.ZipFile(zip_buffer, 'a', zipfile.ZIP_DEFLATED, False) as zip_file:
        zip_file.writestr('rsa_public_key.pem', pubkey_buffer.getvalue())
        zip_file.writestr('rsa_private_key.pem', privkey_buffer.getvalue())

    st.divider()
    st.download_button(
        label="📁 :orange[Download key pair]",
        data=zip_buffer.getvalue(),
        file_name="rsa_key_pair.zip",
        mime="application/zip",
        use_container_width=True,
        help="Download a zip file of the public and private key in PEM format."
    )


def select_mode() -> str:
    mode = st.selectbox(
        "MODE",
        ("Encrypt", "Decrypt"),
    )
    return mode


def upload_key(mode: Literal['Encrypt', 'Decrypt']) -> BytesIO | None:
    key = st.file_uploader(
        "📤 Upload public key :red[*]" if mode == "Encrypt" else "📤 Upload private key :red[*]", type=(".pem"))
    return key


@st.experimental_fragment
def select_key_size() -> None:
    key_size = st.selectbox(
        "Choose a key size", (2048, 4096), index=0)
    return key_size


@st.cache_data
def generate_key_pair(size: int) -> tuple[bytes, bytes]:
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    public_key = private_key.public_key()

    pem_private_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    pem_public_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return pem_public_key, pem_private_key


def load_key(keyfile: bytes, type: Literal['public', 'private']) -> tuple:
    if type == 'public':
        public_key = serialization.load_pem_public_key(
            keyfile,
            backend=default_backend()
        )
        return public_key
    elif type == 'private':
        private_key = serialization.load_pem_private_key(
            keyfile,
            password=None,
        )
        return private_key


def rsa_encrypt_text(text: str, public_key: rsa.RSAPublicKey) -> bytes:
    message = text.encode()
    ciphertext = public_key.encrypt(
        message,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return ciphertext


def rsa_decrypt_text(ciphertext: str, private_key: rsa.RSAPrivateKey) -> bytes:
    plaintext = private_key.decrypt(
        bytes.fromhex(ciphertext),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext


if __name__ == "__main__":
    main()
