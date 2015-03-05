
   class RsaAesCrypto
    {
        static StreamWriter sw = new StreamWriter(@"D:\crypto.txt");

        static void Main(string[] args)
        {
            sw.WriteLine("\n-----RSA-----\n");
            RSACryptoServiceProvider rsaKeyObj = CreateRsaKeyPair("xml");
            string publicKeyXml = rsaKeyObj.ToXmlString(false);
            string privateKeyXml = rsaKeyObj.ToXmlString(true);
            byte[] cipherRsa = RsaEncryption("xml", "Hello Rsa", publicKeyXml);
            sw.WriteLine("Cipher Rsa: {0}", Convert.ToBase64String(cipherRsa));            
            string plainTextRsa = RsaDecryption("xml", cipherRsa, privateKeyXml);
            sw.WriteLine("PlainText Rsa: {0}", plainTextRsa);
            

            sw.WriteLine("\n\n-----AES-----\n");
            RijndaelManaged aesKeyObj = CreateAesKey();
            byte[] keyAes = aesKeyObj.Key;
            byte[] IV = aesKeyObj.IV;
            byte[] cipherAes = AesEncryption("Hello Aes", keyAes, IV);
            sw.WriteLine("Cipher Aes: {0}", Convert.ToBase64String(cipherAes));
            string plainTextAes = AesDecryption(cipherAes, keyAes, IV);
            sw.WriteLine("PlainText Aes: {0}\n", plainTextAes);


            sw.WriteLine("\n\n-----RSA with AES-----\n");
            byte[] cipherData = AesEncryption("Hello Rsa with Aes", keyAes, IV);
            sw.WriteLine("Cipher Data : {0}", Convert.ToBase64String(cipherData));
            byte[] cipherAesKey = RsaEncryption("xml", Convert.ToBase64String(keyAes), publicKeyXml);
            sw.WriteLine("Cipher AesKey : {0}", Convert.ToBase64String(cipherAesKey));
            string plainTextAesKey = RsaDecryption("xml", cipherAesKey, privateKeyXml);
            sw.WriteLine("PlainText AesKey : {0}\n", plainTextAesKey);
            string plainTextData = AesDecryption(cipherData, Convert.FromBase64String(plainTextAesKey), IV);
            sw.WriteLine("PlainText Data : {0}\n", plainTextData);

            sw.Close();
        }

        static public RSACryptoServiceProvider CreateRsaKeyPair(string keyType)
        {
            var csp = new RSACryptoServiceProvider(2048);
            keyType = keyType.ToUpper();
            if (keyType == "XML")
            {
                sw.WriteLine("Public Key: {0}\n", csp.ToXmlString(false).ToString());
                sw.WriteLine("Private Key: {0}", csp.ToXmlString(true).ToString());                
            }
            else if (keyType == "BLOB")
            {
                sw.WriteLine("Public Key: {0}\n", Convert.ToBase64String(csp.ExportCspBlob(false)));
                sw.WriteLine("Private Key: {0}", Convert.ToBase64String(csp.ExportCspBlob(true)));                
            }
            return csp;
        }

        static byte[] RsaEncryption(string keyType, string plainText, string publicKey)
        {
            var cspEncryption = new RSACryptoServiceProvider();
            keyType = keyType.ToUpper();
            if (keyType == "XML")
            {
                cspEncryption.FromXmlString(publicKey);
            }
            else if (keyType == "BLOB")
            {
                cspEncryption.ImportCspBlob(Convert.FromBase64String(publicKey));
            }
            var bytesPlainTextData = Encoding.UTF8.GetBytes(plainText);
            var bytesCypherText = cspEncryption.Encrypt(bytesPlainTextData, false);

            return bytesCypherText;
        }

        static string RsaDecryption(string keyType, byte[] cipherText, string privateKey)
        {
            var cspDecryption = new RSACryptoServiceProvider();
            keyType = keyType.ToUpper();
            if (keyType == "XML")
            {
                cspDecryption.FromXmlString(privateKey);
            }
            else if (keyType == "BLOB")
            {
                cspDecryption.ImportCspBlob(Convert.FromBase64String(privateKey));
            }
            var bytesPlainTextData = cspDecryption.Decrypt(cipherText, false);

            return Encoding.UTF8.GetString(bytesPlainTextData);
        }

        static public RijndaelManaged CreateAesKey()
        {
            RijndaelManaged Crypto = new RijndaelManaged();
            //Crypto.IV = new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
            Crypto.KeySize = 128;

            sw.WriteLine("BlockSize: {0}", Crypto.BlockSize);
            sw.WriteLine("FeedbackSize: {0}", Crypto.FeedbackSize);
            sw.WriteLine("IV: {0}", Convert.ToBase64String(Crypto.IV));
            sw.WriteLine("Key: {0}", Convert.ToBase64String(Crypto.Key));
            sw.WriteLine("Key Size: {0}", Crypto.KeySize);
            sw.WriteLine("LegalBlockSizes: {0}", Crypto.LegalBlockSizes);
            sw.WriteLine("LegalKeySizes: {0}", Crypto.LegalKeySizes);
            sw.WriteLine("Mode: {0}", Crypto.Mode);
            sw.WriteLine("Padding: {0}\n", Crypto.Padding);
            return Crypto;
        }

        static byte[] AesEncryption(string plainText, byte[] Key, byte[] IV)
        {
            byte[] encrypted;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                ICryptoTransform encryptor = rijAlg.CreateEncryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msEncrypt = new MemoryStream())
                {
                    using (CryptoStream csEncrypt = new CryptoStream(msEncrypt, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter swEncrypt = new StreamWriter(csEncrypt))
                        {

                            swEncrypt.Write(plainText);
                        }
                        encrypted = msEncrypt.ToArray();
                    }
                }
            }

            return encrypted;
        }

        static string AesDecryption(byte[] cipherText, byte[] Key, byte[] IV)
        {
            string plaintext = null;
            using (RijndaelManaged rijAlg = new RijndaelManaged())
            {
                rijAlg.Key = Key;
                rijAlg.IV = IV;

                ICryptoTransform decryptor = rijAlg.CreateDecryptor(rijAlg.Key, rijAlg.IV);

                using (MemoryStream msDecrypt = new MemoryStream(cipherText))
                {
                    using (CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader srDecrypt = new StreamReader(csDecrypt))
                        {
                            plaintext = srDecrypt.ReadToEnd();
                        }
                    }
                }
            }

            return plaintext;
        }       
    }
