package com.theicenet.cryptography.service.asymmetric.rsa;

import com.theicenet.cryptography.provider.CryptographyProviderUtil;
import com.theicenet.cryptography.service.asymmetric.rsa.exception.RSACryptographyServiceException;
import org.apache.commons.lang.Validate;

import javax.crypto.Cipher;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;

public class JCARSACryptographyService implements RSACryptographyService {

    public JCARSACryptographyService() {
        // For RSA/NONE/OAEP* it's required Bouncy Castle
        CryptographyProviderUtil.addBouncyCastleCryptographyProvider();
    }

    @Override
    public byte[] encrypt(Padding padding, PublicKey publicKey, byte[] clearContent) {
        return process(Cipher.ENCRYPT_MODE, padding, publicKey, clearContent);
    }

    @Override
    public byte[] decrypt(Padding padding, PrivateKey privateKey, byte[] encryptedContent) {
        return process(Cipher.DECRYPT_MODE, padding, privateKey, encryptedContent);
    }

    private byte[] process(int operationMode, Padding padding, Key key, byte[] content) {
        Validate.notNull(padding);
        Validate.notNull(key);
        Validate.notNull(content);

        Cipher cipher;
        try {
            cipher = Cipher.getInstance(String.format("RSA/NONE/%s", padding.toString()));
            cipher.init(operationMode, key);

            return cipher.doFinal(content);
        } catch (Exception e) {
            throw new RSACryptographyServiceException("Exception processing content", e);
        }
    }
}
