package cz.edris.crypto.paillier;

import java.math.BigInteger;

public final class CipherString implements Decryptable<String> {
    private final BigInteger cipher;

    public CipherString(BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public String decrypt(PrivateKey privateKey) {
        return new String(privateKey.decrypt(cipher).toByteArray());
    }
}
