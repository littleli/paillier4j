package cz.edris.crypto.paillier;

import java.math.BigInteger;

interface Decryptable<T> {
    T decrypt(PrivateKey privateKey);
    BigInteger get();
}
