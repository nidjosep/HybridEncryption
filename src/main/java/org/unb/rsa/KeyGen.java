package org.unb.rsa;

import org.unb.rsa.models.KeyPair;
import org.unb.rsa.models.PrivateKey;
import org.unb.rsa.models.PublicKey;

import java.math.BigInteger;
import java.util.Random;

public class KeyGen {
    private BigInteger p;
    private BigInteger q;
    private BigInteger phiOfn;

    public KeyGen(BigInteger p, BigInteger q) {
        this.p = p;
        this.q = q;
    }

    public KeyPair init() {
        this.phiOfn = p.subtract(BigInteger.ONE).multiply((q.subtract(BigInteger.ONE)));
        BigInteger e = generateRandomE(this.phiOfn);
        return new KeyPair(new PublicKey(e, this.p.multiply(this.q)),
                new PrivateKey(e.modInverse(this.phiOfn), p, q));
    }

    private static BigInteger generateRandomE(BigInteger phiOfn) {
        BigInteger e = new BigInteger(phiOfn.bitLength(), new Random());
        while (!phiOfn.gcd(e).equals(BigInteger.ONE)) {
            e = new BigInteger(phiOfn.bitLength(), new Random());
        }
        return e;
    }

    public BigInteger getPhiOfn() {
        return phiOfn;
    }
}
