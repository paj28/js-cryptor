# JS Cryptor

This Burp extension helps you test web applications that use JavaScript encryption. Encryption used this way provides no real security, however it prevents testing tools like Burp operating correctly.

To use the extension you need to analyze the application's JavaScript and locate the encryption and decryption login. In the *JS Cryptor* tab, you can define an encryption and decryption function. The functions must be named `encrypt` and `decrypt`, take a single string argument, and return a string. You can then *Save* these functions into your project file.

Once you have defined a decryption function, a *JS Cryptor* tab will appear in every message editor within Burp. If you have also defined an encryption function then the editor will be editable, in applicable contexts, and you can send the decrypted request to Burp tools including Scanner and Intruder.

Burp tools see the decrypted request, so features like insertion point detection operate normally. The request has a special header added, *X-JSCryptor: decrypted* When the request is sent, an *IHttpListener* detects this header and applies the encryption, so the target application receives the request in the encrypted format it is expecting. The *IHttpListener* also decrypts the response so the Burp tool can process it normally.

The extension does not implement the *IProxyListener* interface so it's not possible to edit responses intercepted by the Proxy, although this feature could be added if required. It also assumes that encryption and decryption do not change the message length; this could also be added if required.