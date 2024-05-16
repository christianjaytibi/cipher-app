import streamlit as st


st.set_page_config(
    page_title="Applied Cryptography",
    page_icon="💫",
    layout="wide"
)


def main() -> None:
    col1, col2, col3 = st.columns(3)

    col1.title("🍀Encryptify")

    col1.markdown(
        "![](https://img.shields.io/badge/Applied_Cryptography-CSAC_329-gr?style=for-the-badge)")

    col1.markdown("#### <span style=\"color:#00FFA3;\"> Introduction </span>",
                  unsafe_allow_html=True)

    col1.write(
        """
            Cryptography is significant in securing communication channels. 
            It involves techniques for encrypting information to make it unreadable to anyone except those authorized to access it. 
            By employing mathematical algorithms and keys, cryptography ensures data confidentiality, integrity, and authenticity in digital communication.
        """
    )

    col1.divider()

    col1.markdown("#### <span style=\"color:#00FFA3;\"> Project Objectives </span>",
                  unsafe_allow_html=True)

    col1.write(
        """
            1. Implement various cryptographic techniques to secure communication, data, and information exchange.
            2. Design a simple and user-friendly application where users can create message digests, perform encryption and decryption of both text and file inputs.
            3. Understand cryptographic algorithms in terms of their implementation, architecture, strengths, and limitations.
        """)

    col1.divider()

    col2.page_link(page="pages/0_Fernet.py",
                   label=":green[Fernet]",)

    col2.markdown(
        """
            ```
            $ pip install cryptography
            ```
        """
    )

    col2.markdown(
        """
            ```python
            from cryptography.fernet import Fernet


            key = Fernet.generate_key()
            f = Fernet(key)
            token = f.encrypt(b"my deep dark secret")
            f.decrypt(token)
            ```
        """
    )

    col2.divider()
    col2.page_link(page="pages/2_Hash_Functions.py",
                   label=":green[Hash Functions]")

    col2.markdown(
        """
            ```python
            import hashlib


            m = hashlib.sha256()
            m.update(b"Rimuru Tempest")
            print(m.hexdigest())      
            ```
        """
    )
    col2.divider()

    col3.page_link(page="pages/1_RSA.py",
                   label=":green[RSA]")

    col3.markdown(
        """
        ```
            $ pip install rsa
        ```
        """
    )

    col3.markdown(
        """
            ```python
            import rsa

            # Generate a key pair
            bob_pub, bob_priv = rsa.newkeys(512)
            # Create a message
            message = 'hello Bob!'.encode('utf8')
            # Encrypt the message 
            encrypted_msg = rsa.encrypt(message, bob_pub)
            # Decrypt the message 
            message = rsa.decrypt(encrypted_msg, bob_priv)
            print(message.decode('utf8'))
            ```
        """
    )


if __name__ == "__main__":
    main()
