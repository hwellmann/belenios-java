package org.omadac.vote.belenios.cli;

import static java.nio.charset.StandardCharsets.UTF_8;
import static java.util.stream.Collectors.toList;

import java.io.File;
import java.nio.file.Files;
import java.util.List;
import java.util.concurrent.Callable;

import org.omadac.vote.belenios.algo.CreateElectionResult;
import org.omadac.vote.belenios.algo.CreateEncryptedTally;
import org.omadac.vote.belenios.algo.JsonMapper;
import org.omadac.vote.belenios.model.Ballot;
import org.omadac.vote.belenios.model.Ciphertext;
import org.omadac.vote.belenios.model.Election;
import org.omadac.vote.belenios.model.PartialDecryption;

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

    @Override
    public Integer call() throws Exception {
        var electionFile = new File("election.json");
        var ballotsFile = new File("ballots.jsons");
        var partialDecryptionsFile = new File("partial_decryptions.jsons");

        if (!checkFiles(electionFile, ballotsFile, partialDecryptionsFile)) {
            return 1;
        }

        var election = JsonMapper.fromJson(electionFile, Election.class);
        List<PartialDecryption> partialDecryptions = Files.lines(partialDecryptionsFile.toPath())
            .map(pd -> JsonMapper.fromJson(pd, PartialDecryption.class))
            .collect(toList());

        List<Ballot> ballots = Files.lines(ballotsFile.toPath(), UTF_8)
            .map(b -> JsonMapper.fromJson(b, Ballot.class))
            .collect(toList());
        List<List<Ciphertext>> encryptedTally = CreateEncryptedTally.tally(election, ballots.stream());

        var result = CreateElectionResult.createResult(election, ballots.size(), encryptedTally, partialDecryptions);
        JsonMapper.INSTANCE.writeValue(new File("result.json"), result);
        return 0;
    }
}
