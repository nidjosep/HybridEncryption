package org.unb;

import org.unb.models.User;
import org.unb.rsa.models.PublicKey;

import java.math.BigInteger;

public class Connection {

    public static void publishPublicKey(int hashCode, PublicKey publicKey, User bob) {
        bob.getPublicKeyMap().put(hashCode, publicKey);
    }

    public static void sendEncryptedSecretKey(BigInteger c, User user) {
    }
}
