package cz.edris.crypto.paillier;

import java.math.BigInteger;

public final class CipherString implements Decryptable<String> {
    private final BigInteger cipher;

    public CipherString(BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public String decrypt(PrivateKey privateKey) {
        BigInteger plainText = privateKey.decrypt(cipher);
        return new String(plainText.toByteArray());
    }

    @Override
    public BigInteger get() {
        return cipher;
    }
}
