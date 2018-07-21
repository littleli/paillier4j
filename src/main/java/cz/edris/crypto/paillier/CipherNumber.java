package cz.edris.crypto.paillier;

import org.jetbrains.annotations.NotNull;

import java.math.BigInteger;

public final class CipherNumber implements Decryptable<BigInteger> {
    private final PublicKey publicKey;
    private final BigInteger cipher;

    public CipherNumber(@NotNull PublicKey publicKey, @NotNull BigInteger cipher) {
        this.publicKey = publicKey;
        this.cipher = cipher;
    }

    @Override
    public BigInteger decrypt(@NotNull PrivateKey privateKey) {
        return privateKey.decrypt(cipher);
    }

    public CipherNumber add(@NotNull CipherNumber otherCipher) {
        return new CipherNumber(publicKey, publicKey.add(this.cipher, otherCipher.cipher));
    }

    public CipherNumber add(@NotNull BigInteger plain) {
        if (plain.compareTo(BigInteger.ZERO) < 0) {
            throw new ArithmeticException("Only zero or positive number is allowed");
        }
        return add(publicKey.encryptNumber(plain));
    }

    public CipherNumber add(long plain) {
        return add(BigInteger.valueOf(plain));
    }

    public CipherNumber multiply(@NotNull BigInteger plain) {
        if (plain.compareTo(BigInteger.ZERO) <= 0) {
            throw new ArithmeticException("Only positive number is allowed");
        }
        return new CipherNumber(publicKey, publicKey.multiply(cipher, plain));
    }

    public CipherNumber multiply(long plain) {
        return multiply(BigInteger.valueOf(plain));
    }
}
