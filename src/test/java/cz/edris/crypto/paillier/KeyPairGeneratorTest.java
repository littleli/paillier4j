package cz.edris.crypto.paillier;

import org.junit.Test;

import java.math.BigInteger;

import org.junit.Assert;

public class KeyPairGeneratorTest {

    @Test
    public void initialTest() {
        KeyPair keyPair = KeyPairGenerator.generate(512, 64, false);
        PublicKey pubkey = keyPair.getPublicKey();
        PrivateKey seckey = keyPair.getPrivateKey();

        BigInteger encryptedNumber = pubkey.encrypt(BigInteger.valueOf(1000));
        System.out.println(encryptedNumber);

        BigInteger e2 = pubkey.encrypt(BigInteger.valueOf(100));
        System.out.println(e2);

        BigInteger e3 = pubkey.add(encryptedNumber, e2);
        System.out.println(e3);

        BigInteger decryptedNumber = seckey.decrypt(encryptedNumber);
        System.out.println(decryptedNumber);
        System.out.println(seckey.decrypt(e2));
        System.out.println(seckey.decrypt(e3));

        BigInteger e4 = pubkey.encrypt(BigInteger.valueOf(10));
        BigInteger e5 = pubkey.encrypt(BigInteger.valueOf(400));
        BigInteger e6 = pubkey.add(e4, e5);
        BigInteger e7 = seckey.decrypt(e6);
        System.out.println(e7);

        BigInteger e10 = seckey.decrypt(pubkey.multiply(pubkey.encrypt(BigInteger.valueOf(10)), BigInteger.valueOf(10000)));
        System.out.println(e10);

        BigInteger greetingSecret = pubkey.encrypt(new BigInteger("Hello world".getBytes()));
        BigInteger greetingDecrypted = seckey.decrypt(greetingSecret);
        System.out.println(new String(greetingDecrypted.toByteArray()));
    }

    @Test
    public void abstractionTest() {
        KeyPair keyPair = KeyPairGenerator.generate(256, 64, false);

        Encryptor encryptor = new Paillier(keyPair.getPublicKey());

        CipherNumber encryptedSum = encryptor.sum(10, 100, 1000, 10000);
        System.out.println(encryptedSum.get());
        Assert.assertEquals(BigInteger.valueOf(11110), encryptedSum.decrypt(keyPair.getPrivateKey()));

        CipherNumber encryptedProduct = encryptor.product(100, 100, 100);
        System.out.println(encryptedProduct.get());
        Assert.assertEquals(BigInteger.valueOf(1000000), encryptedProduct.decrypt(keyPair.getPrivateKey()));
    }
}
