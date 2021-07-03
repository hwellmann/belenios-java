package org.omadac.vote.belenios.cli;

import java.io.File;
import java.util.concurrent.Callable;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

@Command(name = "verify-diff", mixinStandardHelpOptions = true, description = "noop\n")
public class VerifyDiff implements Callable<Integer> {

    @Option(names = {"--dir1"})
    private File dir1;

    @Option(names = {"--dir2"})
    private File dir2;

    @Override
    public Integer call() throws Exception {
        return 0;
    }
}