package org.unb.models;

import org.unb.Connection;
import org.unb.aes.AES;
import org.unb.rsa.Encrypt;
import org.unb.rsa.KeyGen;
import org.unb.rsa.models.KeyPair;
import org.unb.rsa.models.PrivateKey;
import org.unb.rsa.models.PublicKey;

import javax.crypto.SecretKey;
import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class User {

    private PrivateKey privateKey;
    private PublicKey publicKey;
    private SecretKey secretKey;

    private final Map<Integer, PublicKey> publicKeyMap = new HashMap<>();

    public User() {
    }

    public User initRSAKeyGen() {
        BigInteger p = new BigInteger("19211916981990472618936322908621863986876987146317321175477459636156953561475008733870517275438245830106443145241548501528064000686696553079813968930084003413592173929258239545538559059522893001415540383237712787805857248668921475503029012210091798624401493551321836739170290569343885146402734119714622761918874473987849224658821203492683692059569546468953937059529709368583742816455260753650612502430591087268113652659115398868234585603351162620007030560547611");
        BigInteger q = new BigInteger("49400957163547757452528775346560420645353827504469813702447095057241998403355821905395551250978714023163401985077729384422721713135644084394023796644398582673187943364713315617271802772949577464712104737208148338528834981720321532125957782517699692081175107563795482281654333294693930543491780359799856300841301804870312412567636723373557700882499622073341225199446003974972311496703259471182056856143760293363135470539860065760306974196552067736902898897585691");

        //key generation
        KeyGen keyGen = new KeyGen(p, q);
        KeyPair keyPair = keyGen.init();
        this.privateKey = keyPair.getRsaPrivateKey();
        this.publicKey = keyPair.getRsaPublicKey();
        return this;
    }

    public Map<Integer, PublicKey> getPublicKeyMap() {
        return publicKeyMap;
    }

    public void initAESSecret() throws NoSuchAlgorithmException {
        this.secretKey = AES.generateKey(128);
    }

    public void publishPublicKeyTo(User bob) {
        Connection.publishPublicKey(this.hashCode(), this.publicKey, bob);
    }

    public void shareSecretKeyWith(User user) {
        BigInteger c = Encrypt.encryptMessage(new BigInteger(secretKey.toString().getBytes()), getPublicKeyMap().get(user.hashCode()));
        Connection.sendEncryptedSecretKey(c, user);
    }
}
