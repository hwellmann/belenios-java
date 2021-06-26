package org.omadac.vote.belenios.cli;

import static java.util.stream.Collectors.toList;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.IntStream;

import org.omadac.vote.belenios.algo.GenCredentials;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Credentials;
import org.omadac.vote.belenios.model.Group;

import picocli.CommandLine.ArgGroup;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "credgen", mixinStandardHelpOptions = true, description = "This command is run by a credential authority to generate credentials\n"
    + "for a specific election. The generated private credentials are stored\n"
    + "in T.privcreds, where T is a timestamp. T.privcreds contains one\n"
    + "credential per line. Each voter must be sent a credential, and\n"
    + "T.privcreds must be destroyed after dispatching is done. The\n"
    + "associated public keys are stored in T.pubcreds and must be sent to\n"
    + "the election administrator.\n\n")
public class Credgen implements Callable<Integer> {

    @Option(names = {"--group"}, description = "Take group parameters from file GROUP", required = true)
    private File group;

    @Option(names = {"--uuid"}, description = "UUID of the election", required = true)
    private String uuid;

    @ArgGroup(exclusive = true, multiplicity = "1")
    private Exclusive exclusive;

    static class Exclusive {

        @Option(names = {"--count"}, description = "Generate N credentials")
        private Integer count;

        @Option(names = {"--derive"}, description = "Derive the public key associated to a specific PRIVATE_CRED")
        private String privCred;

        @Option(names = {
            "--file"}, description = "Read identities from FILE. One credential will be generated for each line of FILE")
        private File file;

    }

    @Override
    public Integer call() throws Exception {
        Group g = JsonMapper.INSTANCE.readValue(group, Group.class);

        if (exclusive.privCred != null) {
            BigInteger publicKey = GenCredentials.derive(exclusive.privCred, uuid, g);
            System.out.println(publicKey);
            return 0;
        }
        List<String> ids = null;
        if (exclusive.count != null) {
            if (exclusive.count <= 0) {
                System.err.println("--count must be positive");
                return 1;
            }
            ids = IntStream.rangeClosed(1, exclusive.count).mapToObj(Integer::toString).collect(toList());

        } else if (exclusive.file != null) {
            ids = Files.readAllLines(exclusive.file.toPath());
        }
        List<Credentials> credentials = ids.stream()
            .filter(id -> !id.isBlank())
            .map(id -> GenCredentials.generate(uuid, g)).collect(toList());
        long epochSecond = Instant.now().getEpochSecond();

        var privCreds = new StringBuilder();
        var pubCreds = new StringBuilder();
        for (int i = 0; i < ids.size(); i++) {
            String id = ids.get(i);
            Credentials creds = credentials.get(i);
            privCreds.append(id);
            privCreds.append(" ");
            privCreds.append(creds.privateCred());
            privCreds.append("\n");

            pubCreds.append(creds.publicCred());
            pubCreds.append("\n");
        }
        Files.writeString(Paths.get(epochSecond + ".privcreds"), privCreds);
        Files.writeString(Paths.get(epochSecond + ".pubcreds"), pubCreds);
        return 0;
    }
}