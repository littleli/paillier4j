package cz.edris.crypto.paillier;

import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class PaillierKeysGenerator extends Generator<KeyPair> {

    public PaillierKeysGenerator() {
        super(KeyPair.class);
    }

    @Override
    public KeyPair generate(SourceOfRandomness sourceOfRandomness, GenerationStatus generationStatus) {
        int bits = sourceOfRandomness.nextInt(256, 2048);
        int certainty = sourceOfRandomness.nextInt(16, 64);
        boolean exerciseSimpleVariant = sourceOfRandomness.nextBoolean();
        System.out.println("bits: " + bits + ", certainty: " + certainty + ", simple: " + exerciseSimpleVariant);
        return KeyPair.generate(bits & (bits ^ 1), certainty, exerciseSimpleVariant);
    }
}
