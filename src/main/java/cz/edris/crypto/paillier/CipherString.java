package cz.edris.crypto.paillier;

import java.io.UnsupportedEncodingException;
import java.math.BigInteger;

import org.jetbrains.annotations.NotNull;

public final class CipherString implements Decryptable<String> {
    private final BigInteger cipher;

    public CipherString(@NotNull BigInteger cipher) {
        this.cipher = cipher;
    }

    @Override
    public String decrypt(@NotNull PrivateKey privateKey) {
        try {
			return new String(privateKey.decrypt(cipher).toByteArray(), "UTF-8");
		} catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
		}
    }
}
