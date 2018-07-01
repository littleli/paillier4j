package cz.edris.crypto.paillier;

import java.math.BigInteger;

public final class CipherBytes implements Decryptable<byte[]> {
    private final BigInteger cipher;

    public CipherBytes(BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public byte[] decrypt(PrivateKey privateKey) {
        return privateKey.decrypt(cipher).toByteArray();
    }

    @Override
    public BigInteger get() {
        return cipher;
    }
}
