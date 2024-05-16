import streamlit as st
import hashlib

st.set_page_config(
    page_title="Hash Functions",
    page_icon="💫",
)

if 'hash_btn_disabled' not in st.session_state:
    st.session_state.hash_btn_disabled = True

if 'hash_btn_tooltip' not in st.session_state:
    st.session_state.hash_btn_tooltip = ":red[Please fill in all required fields.]"


def main() -> None:

    st.markdown("### <span style=\"color:#00FFA3;\"> Hash Functions </span>",
                unsafe_allow_html=True)

    input_container = st.container(border=True)
    output_container = st.expander(
        "🪄 **Runic Characters (output)**", expanded=True)

    with input_container:
        hash_option = st.selectbox(
            "HASHING ALGORITHM",
            ("SHA-256", "SHA3-512", "MD5", "BLAKE2b"),
        )

        input_type = st.selectbox(
            "INPUT TYPE",
            ("Text", "File"),
        )

        if input_type == 'Text':
            user_input = st.text_area(
                "Insert text below :red[*]", height=200, key="user_input", placeholder="Type some magic words.")
        elif input_type == 'File':
            user_input = st.file_uploader(
                "📤 Choose a file to upload :red[*]", key="user_input")

        input_fields = (hash_option, input_type, user_input)

        if all(input_fields) and not st.session_state["user_input"] == "":
            st.session_state.hash_btn_disabled = False
            st.session_state.hash_btn_tooltip = None
            with st.expander("🌀 Spell", expanded=True):
                st.info(
                    f"Create _\`message digest\`_ of a {input_type.lower()} using {hash_option}.")
        else:
            st.session_state.hash_btn_disabled = True
            st.session_state.hash_btn_tooltip = ":red[Please fill in all required fields.]"

        if st.button(
                f"✨ **Cast Spell**", use_container_width=True, disabled=st.session_state.hash_btn_disabled, help=st.session_state.hash_btn_tooltip):
            if input_type == "Text":
                result = hash_text(user_input, hash_option)
            if input_type == "File":
                result = hash_file(user_input, hash_option)

            with output_container:
                st.markdown(
                    f"<span style=\"color:#00FFA3\"> {result} </span>", unsafe_allow_html=True)


def hash_text(text: str, hash_algo: str) -> str:
    match hash_algo:
        case "SHA-256":
            hash = hashlib.sha256(text.encode())
        case "SHA3-512":
            hash = hashlib.sha3_512(text.encode())
        case "MD5":
            hash = hashlib.md5(text.encode())
        case "BLAKE2b":
            hash = hashlib.blake2b(text.encode())
    return hash.hexdigest()


def hash_file(file, hash_algo: str) -> str:
    match hash_algo:
        case "SHA-256":
            content = hashlib.file_digest(file, hashlib.sha256)
        case "SHA3-512":
            content = hashlib.file_digest(file, hashlib.sha3_512)
        case "MD5":
            content = hashlib.file_digest(file, hashlib.md5)
        case "BLAKE2b":
            content = hashlib.file_digest(file, hashlib.blake2b)

    return content.hexdigest()


if __name__ == "__main__":
    main()
