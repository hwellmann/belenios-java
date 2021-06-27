package org.omadac.vote.belenios.cli;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.GenTrusteeKey;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Group;
import org.omadac.vote.belenios.model.TrusteeKeyPair;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "trustee-keygen", mixinStandardHelpOptions = true, description = "This command is run by a trustee to generate a share of an election "
    + "key. Such a share consists of a private key and a public key with a "
    + "certificate. Generated files are stored in the current directory with "
    + "a name that starts with ID, where ID is a short fingerprint of the "
    + "public key. The private key is stored in ID.privkey and must be "
    + "secured by the trustee. The public key is stored in ID.pubkey and must "
    + "be sent to the election administrator.  ")
public class TrusteeKeygen implements Callable<Integer> {

    @Option(names = {"--group"}, description = "Take group parameters from file GROUP", required = true)
    private File group;

    @Override
    public Integer call() throws Exception {
        Group g = JsonMapper.INSTANCE.readValue(group, Group.class);
        TrusteeKeyPair keyPair = GenTrusteeKey.genKeyPair(g);
        String privKey = String.format("\"%s\"\n", keyPair.privateKey());
        Files.writeString(Paths.get(keyPair.id() + ".privkey"), privKey);
        String json = JsonMapper.INSTANCE.writeValueAsString(keyPair.trusteePublicKey());
        Files.writeString(Paths.get(keyPair.id() + ".pubkey"), json + "\n");

        return 0;
    }
}