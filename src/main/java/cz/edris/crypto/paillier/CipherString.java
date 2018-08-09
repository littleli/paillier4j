package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;

public final class CipherString implements Decryptable<String> {
    private final BigInteger cipher;

    public CipherString(@NotNull BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public String decrypt(@NotNull PrivateKey privateKey) {
        return new String(privateKey.decrypt(cipher).toByteArray(), StandardCharsets.UTF_8);
    }

    @Override
    public String toString() {
        return cipher.toString();
    }

    public String toString(int radix) {
        return cipher.toString(radix);
    }
}
