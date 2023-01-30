package org.unb;

import org.unb.aes.AES;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

public class HybridEncryption {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        /*User alice = new User();
        User bob = new User();

        alice.initRSAKeyGen();
        alice.publishPublicKeyTo(bob);

        bob.initAESSecret();
        bob.shareSecretKeyWith(alice);*/
        SecretKey secretKey = AES.generateKey(128);
        System.out.println("BEFORE =>" + Arrays.toString(secretKey.getEncoded()));
        BigInteger bigInteger = new BigInteger(secretKey.getEncoded());
        System.out.println(bigInteger);
        SecretKey secretKeyDecrypted = new SecretKeySpec(bigInteger.toByteArray(), "AES");
        System.out.println("AFTER => " + Arrays.toString(secretKeyDecrypted.getEncoded())
        );
    }
}