package org.omadac.vote.belenios.cli;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.TrusteePublicKey;

import picocli.CommandLine.Command;

@Command(name = "mktrustees", mixinStandardHelpOptions = true, description = "Reads public_keys.jsons and threshold.json (if any) " 
    + "and generates a trustees.json file.\n\n")
public class Mktrustees implements Callable<Integer> {

    private List<Object> toSingleTrustee(TrusteePublicKey publicKey) {
        return List.of("Single", publicKey);
    }

    private TrusteePublicKey deserialize(String json) {
        try {
            return JsonMapper.INSTANCE.readValue(json, TrusteePublicKey.class);
        } catch (IOException exc) {
            throw new IllegalArgumentException(exc);
        }
    }

    @Override
    public Integer call() throws Exception {
        var publicKeysFile = new File("public_keys.jsons");
        if (!publicKeysFile.exists()) {
            System.err.println("public_keys.jsons does not exist");
            return 1;
        }
        var publicKeys = Files.readAllLines(publicKeysFile.toPath(), UTF_8);
        var singleTrustees = publicKeys.stream().map(this::deserialize)
            .map(this::toSingleTrustee).collect(toList());
        JsonMapper.INSTANCE.writeValue(new File("trustees.json"), singleTrustees);

        return 0;
    }
}