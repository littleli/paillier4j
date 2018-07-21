package cz.edris.crypto.paillier;

import java.math.BigInteger;

import org.jetbrains.annotations.NotNull;

public final class CipherBytes implements Decryptable<byte[]> {
    private final BigInteger cipher;

    public CipherBytes(@NotNull BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public byte[] decrypt(@NotNull PrivateKey privateKey) {
        return privateKey.decrypt(cipher).toByteArray();
    }
}
