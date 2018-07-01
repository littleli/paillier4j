package cz.edris.crypto.paillier;

import java.math.BigInteger;

public final class CipherNumber implements Decryptable<BigInteger> {
    private final BigInteger cipher;

    public CipherNumber(BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public BigInteger decrypt(PrivateKey privateKey) {
        return privateKey.decrypt(cipher);
    }

    @Override
    public BigInteger get() {
        return cipher;
    }
}
