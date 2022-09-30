# CA Wizard

CA Wizard lets you create and manage your own certificate authority.

It can generate:

- Root certificates
- Intermediate certificates
- Web server TLS certificates
- Client authentication (mTLS) certificates
- Code signing certificates

It is a convenient shortcut to using the long OpenSSL commands.

CA Wizard was created for homelabs and personal environments. TLS client authentication is a powerful and secure way of authenticating to self hosted web services.

```console
$ python3 ca_wizard.py
What would you like to do?
1) Create a website certificate
2) Create a client certificate
3) Create a code signing certificate
4) Install root certificate (Windows ONLY)
5) Regenerate intermediate CA
6) Exit
```

## Getting Started

Install the requirements (`pip3 install -r requirements.txt`) and run the tool (`python3 ca_wizard.py`).

A full guide is available here: [https://blog.ajsmith.us/posts/Creating-your-own-Certificate-Authority-and-Using-TLS-Client-Certificates-mTLS/](https://blog.ajsmith.us/posts/Creating-your-own-Certificate-Authority-and-Using-TLS-Client-Certificates-mTLS/)
