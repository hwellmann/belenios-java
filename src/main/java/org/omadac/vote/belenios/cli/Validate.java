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
import org.omadac.vote.belenios.algo.CreateElectionResult;
import org.omadac.vote.belenios.algo.CreateEncryptedTally;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.PartialDecryption;
import org.omadac.vote.belenios.model.WeightedBallot;

import picocli.CommandLine.Command;

@Command(name = "validate", mixinStandardHelpOptions = true, description = "Reads partial decryptions done by trustees from file "
    + "partial_decryptions.jsons, checks them, combines them into the final "
    + "tally and prints the result to standard output.\n"
    + "The result structure contains partial decryptions itself, so "
    + "partial_decryptions.jsons can be discarded afterwards.\n")
public class Validate implements Callable<Integer> {

    public static boolean checkFiles(File... files) {
        for (File file: files) {
            if (!file.exists()) {
                System.err.println("File " + file + " does not exist");
                return false;
            }
        }
        return true;
    }

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
        var electionFile = new File("election.json");
        var ballotsFile = new File("ballots.jsons");
        var partialDecryptionsFile = new File("partial_decryptions.jsons");
        var publicCredsFile = new File("public_creds.txt");

        if (!checkFiles(electionFile, ballotsFile, partialDecryptionsFile, publicCredsFile)) {
            return 1;
        }

        var election = JsonMapper.fromJson(electionFile, Election.class);
        List<PartialDecryption> partialDecryptions = Files.lines(partialDecryptionsFile.toPath())
            .map(pd -> JsonMapper.fromJson(pd, PartialDecryption.class))
            .collect(toList());

        List<Ballot> ballots = Files.lines(ballotsFile.toPath(), UTF_8)
            .map(b -> JsonMapper.fromJson(b, Ballot.class))
            .collect(toList());

        Map<BigInteger, Integer> pubKeysWithWeights = Files.lines(publicCredsFile.toPath()).map(line -> pubKeyWithWeight(line))
            .collect(toMap(Pair::getLeft, Pair::getRight));

        var weightedBallots = ballots.stream()
            .map(b -> WeightedBallot.builder().ballot(b).weight(pubKeysWithWeights.get(b.signature().publicKey())).build()).collect(toList());

        List<List<Ciphertext>> encryptedTally = CreateEncryptedTally.tallyWeighted(election, weightedBallots.stream());

        int numTallied = weightedBallots.stream().map(wb -> wb.weight()).reduce(0, Integer::sum);

        var result = CreateElectionResult.createResult(election, numTallied, encryptedTally, partialDecryptions);
        JsonMapper.INSTANCE.writeValue(new File("result.json"), result);
        return 0;
    }
}
