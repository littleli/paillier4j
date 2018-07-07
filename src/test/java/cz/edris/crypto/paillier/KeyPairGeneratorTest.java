package cz.edris.crypto.paillier;

import org.junit.Ignore;
import org.junit.Test;

import java.math.BigInteger;

import org.junit.Assert;

public class KeyPairGeneratorTest {

    @Test @Ignore
    public void initialTest() {
        KeyPair keyPair = KeyPair.generate(512, 64, false);
        PublicKey pubkey = keyPair.getPublicKey();
        PrivateKey seckey = keyPair.getPrivateKey();

        BigInteger encryptedNumber = pubkey.encrypt(BigInteger.valueOf(1_000));
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

        BigInteger e10 = seckey.decrypt(pubkey.multiply(pubkey.encrypt(BigInteger.valueOf(10)), BigInteger.valueOf(10_000)));
        System.out.println(e10);

        BigInteger greetingSecret = pubkey.encrypt(new BigInteger("Hello world".getBytes()));
        BigInteger greetingDecrypted = seckey.decrypt(greetingSecret);
        System.out.println(new String(greetingDecrypted.toByteArray()));
    }

    @Test
    public void abstractionTest() {
        KeyPair keyPair = KeyPair.generate(2_048, 64, false);

        PublicKey publicKey = keyPair.getPublicKey();

        CipherNumber encryptedSum = publicKey.encryptNumber(1_000).add(10_000);

        System.out.println(encryptedSum.get());
        System.out.println(encryptedSum.decrypt(keyPair.getPrivateKey()));

        Assert.assertEquals(BigInteger.valueOf(11_000), encryptedSum.decrypt(keyPair.getPrivateKey()));

        CipherNumber encryptedProduct = publicKey.encryptNumber(1_000).multiply(1_000);

        System.out.println(encryptedProduct.get());
        System.out.println(encryptedProduct.decrypt(keyPair.getPrivateKey()));

        Assert.assertEquals(BigInteger.valueOf(1_000_000), encryptedProduct.decrypt(keyPair.getPrivateKey()));
    }
}
