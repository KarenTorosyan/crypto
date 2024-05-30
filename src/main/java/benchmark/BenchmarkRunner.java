package benchmark;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.openjdk.jmh.runner.NoBenchmarksException;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.ChainedOptionsBuilder;
import org.openjdk.jmh.runner.options.CommandLineOptionException;
import org.openjdk.jmh.runner.options.CommandLineOptions;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.io.IOException;

public class BenchmarkRunner {

    private static final Logger log = LogManager.getLogger(BenchmarkRunner.class);

    public void run(String[] args) {

        CommandLineOptions commandLineOptions;
        try {
            commandLineOptions = new CommandLineOptions(args);
        } catch (CommandLineOptionException e) {
            throw new RuntimeException(e);
        }
        ChainedOptionsBuilder optionsBuilder = new OptionsBuilder()
                .include("!")
                .parent(commandLineOptions);
        Runner runner = new Runner(optionsBuilder.build());

        try {
            if (commandLineOptions.shouldHelp()) {
                commandLineOptions.showHelp();
            } else if (commandLineOptions.shouldList()) {
                runner.list();
            } else if (commandLineOptions.shouldListWithParams()) {
                runner.listWithParams(commandLineOptions);
            } else if (commandLineOptions.shouldListProfilers()) {
                commandLineOptions.listProfilers();
            } else if (commandLineOptions.shouldListResultFormats()) {
                commandLineOptions.listResultFormats();
            }
        } catch (IOException e) {
            log.error(e.getMessage());
        }

        try {
            runner.run();
        } catch (NoBenchmarksException e) {
            log.info("No active benchmarks");
        } catch (RunnerException e) {
            log.error(e);
        }
    }
}
