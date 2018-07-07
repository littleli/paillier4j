package cz.edris.crypto.paillier;

import com.github.nhalase.lorem.LoremIpsum;
import com.pholser.junit.quickcheck.generator.GenerationStatus;
import com.pholser.junit.quickcheck.generator.Generator;
import com.pholser.junit.quickcheck.random.SourceOfRandomness;

public class LoremIpsumGenerator extends Generator<String> {
    LoremIpsum loremIpsum;

    public LoremIpsumGenerator() {
        super(String.class);
    }

    @Override
    public String generate(SourceOfRandomness sourceOfRandomness, GenerationStatus generationStatus) {
        if (loremIpsum == null) {
            loremIpsum = new LoremIpsum(sourceOfRandomness.nextLong());
        }
        switch (sourceOfRandomness.nextInt(0, 4)) {
            case 0:
                return loremIpsum.getNameFemale();
            case 1:
                return loremIpsum.getDepartmentName();
            case 2:
                return loremIpsum.getCity();
            case 3:
                return loremIpsum.getPhone();
            case 4:
                return loremIpsum.getEmail();
            default:
                return loremIpsum.getName();
        }
    }
}
