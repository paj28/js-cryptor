# JS Cryptor

This Burp extension helps you test web applications that use JavaScript encryption. Encryption used this way provides no real security, however it prevents testing tools like Burp operating correctly.

 * [Video demo](https://youtu.be/SzA7Lg_ZEkA)

To use the extension you need to analyze the application's JavaScript and locate the encryption and decryption functionality. In the *JS Cryptor* tab, you can define an encryption and decryption function. The functions must be named `encrypt` and `decrypt`, take a single string argument, and return a string. You can then *Save* these functions into your project file.

Once you have defined the functions, a *JS Cryptor* tab will appear in every message editor within Burp. The editor will be editable, in applicable contexts, and the message re-encrypted after it is edited.

You can also send the request in decrypted format to automated Burp tools (i.e. Intruder and Scanner) In this case, the tools  the decrypted request, so features like insertion point detection operate normally. A special header added is the request, *X-JSCryptor: decrypted* When the request is sent, an *IHttpListener* detects this header and applies the encryption, so the target application receives the request in the encrypted format it is expecting. The *IHttpListener* also decrypts the response so the Burp tool can process it normally.