package org.omadac.vote.belenios.cli;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;
import static java.util.stream.Collectors.toMap;

import java.io.File;
import java.math.BigInteger;
import java.nio.file.Files;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Callable;

import org.graalvm.collections.Pair;
import org.omadac.vote.belenios.algo.CreateEncryptedTally;
import org.omadac.vote.belenios.algo.CreatePartialDecryption;
import org.omadac.vote.belenios.algo.GenTrusteeKey;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.WeightedBallot;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "decrypt", mixinStandardHelpOptions = true, description = "Run by each trustee to perform a partial decryption.\n")
public class Decrypt implements Callable<Integer> {

    @Option(names = {"--privkey"}, description = "Read private key from file PRIV_KEY", required = true)
    private File privkey;

    private Pair<BigInteger, Integer> pubKeyWithWeight(String line) {
        String[] parts = line.split(",");
        if (parts.length == 2) {
            return Pair.create(new BigInteger(parts[0]), Integer.parseInt(parts[1]));
        } else {
            return Pair.create(new BigInteger(parts[0]), 1);
        }
    }
    
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

        var publicCredsFile = new File("public_creds.txt");
        if (!publicCredsFile.exists()) {
            System.err.println("File " + publicCredsFile + " does not exist");
            return 1;
        }

        var privKeyString = JsonMapper.INSTANCE.readValue(privkey, String.class);
        var election = JsonMapper.INSTANCE.readValue(electionFile, Election.class);
        var keyPair = GenTrusteeKey.deriveKeyPair(new BigInteger(privKeyString), election.publicKey().group());

        List<Ballot> ballots = Files.lines(ballotsFile.toPath(), UTF_8)
            .map(t -> JsonMapper.fromJson(t, Ballot.class))
            .collect(toList());
            
        Map<BigInteger, Integer> pubKeysWithWeights = Files.lines(publicCredsFile.toPath())
            .map(line -> pubKeyWithWeight(line))
            .collect(toMap(Pair::getLeft, Pair::getRight));

        var weightedBallots = ballots.stream()
            .map(b -> WeightedBallot.builder()
                .ballot(b)
                .weight(pubKeysWithWeights.get(b.signature().publicKey()))
                .build());

        List<List<Ciphertext>> encryptedTally = CreateEncryptedTally.tallyWeighted(election, weightedBallots);
        var decryption = CreatePartialDecryption.decrypt(election, keyPair, encryptedTally);
        var json = JsonMapper.INSTANCE.writeValueAsString(decryption);
        System.out.println(json);
        return 0;
    }
}