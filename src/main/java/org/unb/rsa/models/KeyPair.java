package org.unb.rsa.models;

public class KeyPair {
    private PrivateKey privateKey;
    private PublicKey publicKey;

    public KeyPair(PublicKey publicKey, PrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public PrivateKey getRsaPrivateKey() {
        return privateKey;
    }

    public PublicKey getRsaPublicKey() {
        return publicKey;
    }
}
