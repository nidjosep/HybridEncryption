package org.unb.rsa;

import org.unb.rsa.models.PublicKey;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;

public class Encrypt {
    public static BigInteger encryptMessage(BigInteger m, PublicKey publicKey) {
        Instant start = Instant.now();
        BigInteger c = m.modPow(publicKey.getE(), publicKey.getN());
        Instant end = Instant.now();
        System.out.printf("Encryption done in %s ms\n", Duration.between(start, end).toMillis());
        return c;
    }
}
