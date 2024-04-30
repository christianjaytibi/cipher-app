import streamlit as st


st.set_page_config(
    page_title="Applied Cryptography",
    page_icon="💫",
    layout="centered"
)


def main() -> None:

    st.write("# Hello, World! 🔮",)
    # st.write("[![Static Badge](https://img.shields.io/badge/Visit_Github_repository-black?style=for-the-badge&logo=github&color=%23333)](https://github.com/christianjaytibi/applied-cryptography-app)")

    st.markdown(
        "![](https://img.shields.io/badge/Applied_Cryptography-CSAC_329-gr?style=for-the-badge)")
    # st.markdown(
    #     """
    #         ![Python](https://img.shields.io/badge/Python-3.11.5-FFD43B?style=for-the-badge&logo=python&logoColor=white)
    #         ![Streamlit](https://img.shields.io/badge/streamlit-v1.33.0-FF4B4B?style=for-the-badge&logo=streamlit&logoColor=white)
    #         ![cryptography](https://img.shields.io/badge/pyca%2Fcryptography-v42.0.5-gr?style=for-the-badge)
    #     """)

    # st.markdown(
    #     """
    #         ![rsa](https://img.shields.io/badge/rsa-4.9-gr?style=for-the-badge)
    #     """)

    st.markdown("#### <span style=\"color:#00FFA3;\"> Project Objectives </span>",
                unsafe_allow_html=True)

    st.write(
        """
            1. Implement various cryptographic techniques to secure communication, data, and information exchange.
            2. Design a simple and user-friendly application where users can create message digests, perform encryption and decryption of both text and file inputs.
            3. Understand cryptographic algorithms in terms of their implementation, architecture, strengths, and limitations.
        """)


if __name__ == "__main__":
    main()
