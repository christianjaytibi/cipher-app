import streamlit as st
from cryptography.fernet import Fernet, InvalidToken
import io


st.set_page_config(
    page_title="Fernet",
    page_icon="💫",
    layout="centered"
)


if 'fernet_btn_disabled' not in st.session_state:
    st.session_state.fernet_btn_disabled = True

if 'fernet_btn_tooltip' not in st.session_state:
    st.session_state.fernet_btn_tooltip = ":red[Please fill in all required fields.]"


def main() -> None:
    st.markdown("### <span style=\"color:#00FFA3\"> Fernet </span>",
                unsafe_allow_html=True)

    if st.toggle("Show overview",):

        st.success("""
            _\"Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.
            Fernet is an implementation of symmetric (also known as “secret key”) authenticated cryptography.\"_

            **READ:** [Fernet (symmetric encryption) — Cryptography 43.0.0.dev1 documentation ](https://cryptography.io/en/latest/fernet/)

            """)

        st.image(
            "https://miro.medium.com/v2/resize:fit:1400/1*1bO8UAo3WOhCu9QrnpjA0g.png", caption="Fernet symmetric encryption architecture")

        with st.expander("Guide", expanded=True):
            st.info("""
                    1. Generate a key. This is needed for encryption and decryption.
                    2. Download the generated key.
                    3. Upload the key.
                    4. Choose whether to encrypt or decrypt.
                    5. Select the type of desired input. It could be a text or a file.
                    6. Insert the text or upload the file.
                    7. Click "✨GO!".
            """)

    input_container = st.expander("Try it yourself!", expanded=True)
    output_container = st.expander(
        "🪄 **Output**", expanded=True)

    with input_container:

        key_gen_col = st.columns(2)

        with key_gen_col[0]:
            if st.button("🍭 :rainbow[**Generate a new key**]", use_container_width=True, help="If you don\'t have a key, generate it first."):
                key = Fernet.generate_key()

                key_gen_col[1].download_button(
                    label="🔑 :orange[Download key]",
                    data=key,
                    file_name="fernet.key",
                    help="Download `fernet.key`. Keep this some place safe!",
                    use_container_width=True
                )

        user_key = st.file_uploader(
            "📤 Upload key :red[*]", type=(".key"), help="Upload your key with file extension `\".key\"` here.")

        mode = st.selectbox(
            "MODE :red[*]",
            ("Encrypt", "Decrypt"),
        )

        input_type = st.selectbox(
            "INPUT TYPE :red[*]",
            ("Text", "File"),
        )

        if input_type == 'Text':
            token = st.text_area(
                "⚡ Insert text below :red[*]", key="token", placeholder="Type some magic words.")
        elif input_type == 'File':
            token = st.file_uploader(
                "📤 Choose a file to upload :red[*]", type=(".enc") if mode == "Decrypt" else None, key="token")

        input_fields = (user_key, input_type, mode, token)

        if all(input_fields) and not st.session_state["token"] == "":
            st.session_state.fernet_btn_disabled = False
            st.session_state.fernet_btn_tooltip = None
        else:
            st.session_state.fernet_btn_disabled = True
            st.session_state.fernet_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button(
                f"✨ **GO!**",
                use_container_width=True,
                disabled=st.session_state.fernet_btn_disabled,
                help=st.session_state.fernet_btn_tooltip):

            user_key = user_key.getvalue()
            try:
                if input_type == "Text":
                    if mode == "Encrypt":
                        result = encrypt_text(token, user_key)
                    if mode == "Decrypt":
                        result = decrypt_text(token, user_key)

                    with output_container:
                        st.markdown(
                            f"<span style=\"color:#00FFA3\"> {result.decode()} </span>", unsafe_allow_html=True)

                elif input_type == "File":
                    if mode == "Encrypt":
                        file = encrypt_file(token, user_key)
                        with output_container:
                            st.download_button(
                                label="🔐 :orange[Download encrypted file]",
                                data=file,
                                file_name=f"{token.name}.enc",
                                use_container_width=True,
                                help=f"Download `{token.name}.enc`"
                            )

                    else:
                        file = decrypt_file(token, user_key)
                        with output_container:
                            st.download_button(
                                label="🔓 :orange[Download decrypted file]",
                                data=file,
                                file_name=f"{token.name[:-4]}",
                                use_container_width=True,
                                help=f"Download `{token.name[:-4]}`"
                            )

            except InvalidToken:
                output_container.error(
                    "The token is invalid.",  icon="🚨")


@st.cache_data
def encrypt_text(text: str, key: bytes):
    f = Fernet(key)
    token = f.encrypt(text.encode())
    return token


@st.cache_data
def decrypt_text(token: bytes, key: bytes):
    f = Fernet(key)
    return f.decrypt(token)


@st.cache_data
def encrypt_file(file_object, key: bytes):
    f = Fernet(key)

    file_data = file_object.read()
    encrypted_file = f.encrypt(file_data)
    return encrypted_file


@st.cache_data
def decrypt_file(file_object, key: bytes):
    f = Fernet(key)

    file_data = file_object.read()
    decrypted_file = f.decrypt(file_data)
    return decrypted_file


if __name__ == "__main__":
    main()
