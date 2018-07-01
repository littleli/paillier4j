package cz.edris.crypto.paillier;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.stream.Stream;

public final class Paillier implements Encryptor {
    private final PublicKey publicKey;

    public Paillier(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public CipherNumber encrypt(BigInteger n) {
        return new CipherNumber(publicKey.encrypt(n));
    }

    @Override
    public CipherNumber encrypt(long n) {
        return new CipherNumber(publicKey.encrypt(BigInteger.valueOf(n)));
    }

    @Override
    public CipherString encrypt(String text) {
        return new CipherString(publicKey.encrypt(new BigInteger(text.getBytes())));
    }

    @Override
    public CipherBytes encrypt(byte[] bytes) {
        BigInteger bytesNumber = new BigInteger(bytes);
        BigInteger cipherText = publicKey.encrypt(bytesNumber);
        return new CipherBytes(cipherText);
    }

    @Override
    public CipherNumber sum(BigInteger n, BigInteger m) {
        return new CipherNumber(publicKey.add(n, m));
    }

    @Override
    public CipherNumber sum(BigInteger... n) {
        BigInteger cipherNumber = Stream.of(n)
                .reduce(BigInteger.ONE, (acc, next) -> acc.multiply(publicKey.encrypt(next)).mod(publicKey.nsquare));
        return new CipherNumber(cipherNumber);
    }

    @Override
    public CipherNumber sum(long n, long m) {
        return sum(BigInteger.valueOf(n), BigInteger.valueOf(m));
    }

    @Override
    public CipherNumber sum(long... numbers) {
        BigInteger cipherNumber = Arrays.stream(numbers)
                .mapToObj(BigInteger::valueOf)
                .reduce(BigInteger.ONE, (acc, next) -> acc.multiply(publicKey.encrypt(next)).mod(publicKey.nsquare));
        return new CipherNumber(cipherNumber);
    }

    @Override
    public CipherNumber sum(CipherNumber c, BigInteger p) {
        return sum(c, new CipherNumber(publicKey.encrypt(p)));
    }

    @Override
    public CipherNumber sum(CipherNumber c1, CipherNumber c2) {
        BigInteger sum = publicKey.add(c1.get(), c2.get());
        return new CipherNumber(sum);
    }

    @Override
    public CipherNumber product(BigInteger n, BigInteger m) {
        return new CipherNumber(publicKey.multiply(publicKey.encrypt(n), m));
    }

    @Override
    public CipherNumber product(BigInteger... numbers) {
        BigInteger product = Stream.of(numbers)
                .reduce(publicKey.encrypt(BigInteger.ONE), publicKey::multiply);
        return new CipherNumber(product);
    }

    @Override
    public CipherNumber product(long n, long m) {
        return product(BigInteger.valueOf(n), BigInteger.valueOf(m));
    }

    @Override
    public CipherNumber product(long... numbers) {
        BigInteger product = Arrays.stream(numbers)
                .mapToObj(BigInteger::valueOf)
                .reduce(publicKey.encrypt(BigInteger.ONE), publicKey::multiply);
        return new CipherNumber(product);
    }

    @Override
    public CipherNumber product(CipherNumber c, BigInteger p) {
        return product(c.get(), p);
    }

    @Override
    public CipherNumber product(CipherNumber c, long n) {
        return product(c, BigInteger.valueOf(n));
    }
}
