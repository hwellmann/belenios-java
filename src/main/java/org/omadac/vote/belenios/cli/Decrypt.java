package org.omadac.vote.belenios.cli;

import static java.nio.charset.StandardCharsets.UTF_8;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;
import java.util.stream.Stream;

import org.omadac.vote.belenios.algo.CreateEncryptedTally;
import org.omadac.vote.belenios.algo.CreatePartialDecryption;
import org.omadac.vote.belenios.algo.GenTrusteeKey;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "decrypt", mixinStandardHelpOptions = true, description = "Run by each trustee to perform a partial decryption.\n")
public class Decrypt implements Callable<Integer> {

    @Option(names = {"--privkey"}, description = "Read private key from file PRIV_KEY", required = true)
    private File privkey;

    @Override
    public Integer call() throws Exception {
        if (!privkey.exists()) {
            System.err.println("Private key file " + privkey + " does not exist");
            return 1;
        }
        var electionFile = new File("election.json");
        if (!electionFile.exists()) {
            System.err.println("Election file " + electionFile + " does not exist");
            return 1;
        }
        var ballotsFile = new File("ballots.jsons");
        if (!ballotsFile.exists()) {
            System.err.println("Ballots file " + ballotsFile + " does not exist");
            return 1;
        }

        var privKeyString = JsonMapper.INSTANCE.readValue(privkey, String.class);
        var election = JsonMapper.INSTANCE.readValue(electionFile, Election.class);
        var keyPair = GenTrusteeKey.deriveKeyPair(new BigInteger(privKeyString), election.publicKey().group());
        Stream<Ballot> ballots = Files.lines(ballotsFile.toPath(), UTF_8)
            .map(t -> JsonMapper.fromJson(t, Ballot.class));
        List<List<Ciphertext>> encryptedTally = CreateEncryptedTally.tally(election, ballots);
        var decryption = CreatePartialDecryption.decrypt(election, keyPair, encryptedTally);
        var json = JsonMapper.INSTANCE.writeValueAsString(decryption);
        System.out.println(json);
        return 0;
    }
}